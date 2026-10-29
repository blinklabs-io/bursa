// Copyright 2026 Blink Labs Software
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package confidentialspace

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"strings"

	"cloud.google.com/go/storage"
	"github.com/blinklabs-io/bursa/internal/signer/backend"
	"google.golang.org/api/googleapi"
	"google.golang.org/api/option"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	counterStateVersionV1 = "bursa-confidential-space-counter/1"
	counterStateVersion   = "bursa-confidential-space-counter/2"
	maxCounterStateSize   = 4096
	maxCounterCASRetries  = 8
)

// ErrCounterRegression indicates that an issue counter is not the next value
// in the sequence.
var ErrCounterRegression = errors.New(
	"operational-certificate issue counter is out of sequence",
)

type counterState struct {
	Version         string `json:"version"`
	KeyHash         string `json:"key_hash"`
	NextIssueNumber uint64 `json:"next_issue_number"`
}

type counterStateWire struct {
	Version         string  `json:"version"`
	KeyHash         string  `json:"key_hash"`
	IssueNumber     *uint64 `json:"issue_number,omitempty"`
	NextIssueNumber *uint64 `json:"next_issue_number,omitempty"`
}

type counterObject interface {
	Load(context.Context) ([]byte, int64, bool, error)
	Store(context.Context, []byte, int64, bool) error
}

type cloudCounterObject struct {
	object *storage.ObjectHandle
}

// CloudCounterStore reserves issue counters in one Cloud Storage object. The
// object generation precondition provides a compare-and-swap across workload
// replicas.
type CloudCounterStore struct {
	object counterObject
	client *storage.Client
}

// Prepare binds the counter object to key. A missing object is created only
// while the wrapped key identity is being created.
func (s *CloudCounterStore) Prepare(
	ctx context.Context,
	key backend.KeyHash,
	allowCreate bool,
) error {
	keyHash := key.String()
	for range maxCounterCASRetries {
		_, _, exists, err := s.loadCurrent(ctx, keyHash)
		if err != nil {
			return err
		}
		if exists {
			return nil
		}
		if !allowCreate {
			return errors.New("counter state is missing for the pool cold key")
		}
		initial := counterState{
			Version: counterStateVersion,
			KeyHash: keyHash,
		}
		if err := s.store(ctx, initial, 0, false); err == nil {
			return nil
		} else if !isPreconditionFailure(err) {
			return err
		}
	}
	return errors.New("counter state changed too often")
}

// NewCloudCounterStore creates a counter store using the measured workload's
// external-account credentials.
func NewCloudCounterStore(
	ctx context.Context,
	bucket, object, credentialFile string,
) (*CloudCounterStore, error) {
	if strings.TrimSpace(bucket) == "" || strings.TrimSpace(object) == "" {
		return nil, errors.New("counter bucket and object are required")
	}
	if err := validateWIFCredentials(credentialFile); err != nil {
		return nil, err
	}
	client, err := storage.NewClient(
		ctx,
		option.WithAuthCredentialsFile(option.ExternalAccount, credentialFile),
		storage.WithJSONReads(),
	)
	if err != nil {
		return nil, fmt.Errorf("create Cloud Storage client: %w", err)
	}
	return &CloudCounterStore{
		object: &cloudCounterObject{
			object: client.Bucket(bucket).Object(object),
		},
		client: client,
	}, nil
}

// CheckAndAdvance commits issueNumber only when it is the next sequential
// value for key.
func (s *CloudCounterStore) CheckAndAdvance(
	ctx context.Context,
	key backend.KeyHash,
	issueNumber uint64,
) error {
	keyHash := key.String()
	for range maxCounterCASRetries {
		current, generation, exists, err := s.loadCurrent(ctx, keyHash)
		if err != nil {
			return err
		}
		if !exists {
			return errors.New("counter state is missing for the pool cold key")
		}
		if err := checkCounterSequence(
			current.NextIssueNumber,
			issueNumber,
		); err != nil {
			return err
		}
		next := counterState{
			Version:         counterStateVersion,
			KeyHash:         keyHash,
			NextIssueNumber: issueNumber + 1,
		}
		if err := s.store(ctx, next, generation, exists); err == nil {
			return nil
		} else if !isPreconditionFailure(err) {
			return err
		}
	}
	return errors.New("counter state changed too often")
}

func checkCounterSequence(expected, next uint64) error {
	if next == math.MaxUint64 || next != expected {
		return ErrCounterRegression
	}
	return nil
}

func (s *CloudCounterStore) loadCurrent(
	ctx context.Context,
	keyHash string,
) (counterState, int64, bool, error) {
	for range maxCounterCASRetries {
		wire, generation, exists, err := s.load(ctx)
		if err != nil || !exists {
			return counterState{}, generation, exists, err
		}
		state, migrate, err := normalizeCounterState(wire, keyHash)
		if err != nil {
			return counterState{}, 0, false, err
		}
		if !migrate {
			return state, generation, true, nil
		}
		if err := s.store(ctx, state, generation, true); err == nil {
			continue
		} else if !isPreconditionFailure(err) {
			return counterState{}, 0, false, err
		}
	}
	return counterState{}, 0, false, errors.New(
		"counter state changed too often",
	)
}

func (s *CloudCounterStore) load(
	ctx context.Context,
) (counterStateWire, int64, bool, error) {
	data, generation, exists, err := s.object.Load(ctx)
	if err != nil || !exists {
		return counterStateWire{}, generation, exists, err
	}
	var state counterStateWire
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&state); err != nil {
		return counterStateWire{}, 0, false, fmt.Errorf(
			"decode counter state: %w",
			err,
		)
	}
	if err := requireJSONEOF(dec); err != nil {
		return counterStateWire{}, 0, false, fmt.Errorf(
			"decode counter state: %w",
			err,
		)
	}
	return state, generation, true, nil
}

func normalizeCounterState(
	wire counterStateWire,
	keyHash string,
) (counterState, bool, error) {
	if wire.KeyHash != keyHash {
		return counterState{}, false, errors.New(
			"counter state does not match the pool cold key",
		)
	}
	switch wire.Version {
	case counterStateVersion:
		if wire.NextIssueNumber == nil || wire.IssueNumber != nil {
			return counterState{}, false, errors.New(
				"counter state is incomplete",
			)
		}
		return counterState{
			Version:         counterStateVersion,
			KeyHash:         keyHash,
			NextIssueNumber: *wire.NextIssueNumber,
		}, false, nil
	case counterStateVersionV1:
		if wire.IssueNumber == nil || wire.NextIssueNumber != nil ||
			*wire.IssueNumber == math.MaxUint64 {
			return counterState{}, false, errors.New(
				"legacy counter state cannot be migrated",
			)
		}
		return counterState{
			Version:         counterStateVersion,
			KeyHash:         keyHash,
			NextIssueNumber: *wire.IssueNumber + 1,
		}, true, nil
	default:
		return counterState{}, false, errors.New(
			"counter state has an unsupported version",
		)
	}
}

func (s *CloudCounterStore) store(
	ctx context.Context,
	state counterState,
	generation int64,
	exists bool,
) error {
	data, err := json.Marshal(state)
	if err != nil {
		return fmt.Errorf("encode counter state: %w", err)
	}
	return s.object.Store(ctx, data, generation, exists)
}

func (s *cloudCounterObject) Load(
	ctx context.Context,
) ([]byte, int64, bool, error) {
	r, err := s.object.NewReader(ctx)
	if errors.Is(err, storage.ErrObjectNotExist) {
		return nil, 0, false, nil
	}
	if err != nil {
		return nil, 0, false, fmt.Errorf("read counter state: %w", err)
	}
	defer r.Close()
	data, err := io.ReadAll(io.LimitReader(r, maxCounterStateSize+1))
	if err != nil {
		return nil, 0, false, fmt.Errorf("read counter state: %w", err)
	}
	if len(data) > maxCounterStateSize {
		return nil, 0, false, errors.New("counter state exceeds size limit")
	}
	return data, r.Attrs.Generation, true, nil
}

func (s *cloudCounterObject) Store(
	ctx context.Context,
	data []byte,
	generation int64,
	exists bool,
) error {
	conditions := storage.Conditions{DoesNotExist: true}
	if exists {
		conditions = storage.Conditions{GenerationMatch: generation}
	}
	writeCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	w := s.object.If(conditions).NewWriter(writeCtx)
	w.ContentType = "application/json"
	if _, err := w.Write(data); err != nil {
		cancel()
		return fmt.Errorf("write counter state: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("commit counter state: %w", err)
	}
	return nil
}

func isPreconditionFailure(err error) bool {
	var apiErr *googleapi.Error
	return (errors.As(err, &apiErr) && apiErr.Code == http.StatusPreconditionFailed) ||
		status.Code(err) == codes.FailedPrecondition
}

// Close releases the Cloud Storage client.
func (s *CloudCounterStore) Close() error { return s.client.Close() }
