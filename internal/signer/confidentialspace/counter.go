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
	counterStateVersion  = "bursa-confidential-space-counter/1"
	maxCounterStateSize  = 4096
	maxCounterCASRetries = 8
)

// ErrCounterRegression indicates that an issue counter was already reserved.
var ErrCounterRegression = errors.New(
	"operational-certificate issue counter did not advance",
)

type counterState struct {
	Version     string `json:"version"`
	KeyHash     string `json:"key_hash"`
	IssueNumber uint64 `json:"issue_number"`
}

// CloudCounterStore reserves issue counters in one Cloud Storage object. The
// object generation precondition provides a compare-and-swap across workload
// replicas.
type CloudCounterStore struct {
	object *storage.ObjectHandle
	client *storage.Client
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
		object: client.Bucket(bucket).Object(object),
		client: client,
	}, nil
}

// CheckAndAdvance commits issueNumber only when it is greater than the last
// committed value for key.
func (s *CloudCounterStore) CheckAndAdvance(
	ctx context.Context,
	key backend.KeyHash,
	issueNumber uint64,
) error {
	keyHash := key.String()
	for range maxCounterCASRetries {
		current, generation, exists, err := s.load(ctx)
		if err != nil {
			return err
		}
		if exists {
			if current.Version != counterStateVersion ||
				current.KeyHash != keyHash {
				return errors.New(
					"counter state does not match the pool cold key",
				)
			}
			if issueNumber <= current.IssueNumber {
				return ErrCounterRegression
			}
		}
		next := counterState{
			Version:     counterStateVersion,
			KeyHash:     keyHash,
			IssueNumber: issueNumber,
		}
		if err := s.store(ctx, next, generation, exists); err == nil {
			return nil
		} else if !isPreconditionFailure(err) {
			return err
		}
	}
	return errors.New("counter state changed too often")
}

func (s *CloudCounterStore) load(
	ctx context.Context,
) (counterState, int64, bool, error) {
	r, err := s.object.NewReader(ctx)
	if errors.Is(err, storage.ErrObjectNotExist) {
		return counterState{}, 0, false, nil
	}
	if err != nil {
		return counterState{}, 0, false, fmt.Errorf(
			"read counter state: %w",
			err,
		)
	}
	defer r.Close()
	data, err := io.ReadAll(io.LimitReader(r, maxCounterStateSize+1))
	if err != nil {
		return counterState{}, 0, false, fmt.Errorf(
			"read counter state: %w",
			err,
		)
	}
	if len(data) > maxCounterStateSize {
		return counterState{}, 0, false, errors.New(
			"counter state exceeds size limit",
		)
	}
	var state counterState
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&state); err != nil {
		return counterState{}, 0, false, fmt.Errorf(
			"decode counter state: %w",
			err,
		)
	}
	if err := requireJSONEOF(dec); err != nil {
		return counterState{}, 0, false, fmt.Errorf(
			"decode counter state: %w",
			err,
		)
	}
	return state, r.Attrs.Generation, true, nil
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
	conditions := storage.Conditions{DoesNotExist: true}
	if exists {
		conditions = storage.Conditions{GenerationMatch: generation}
	}
	w := s.object.If(conditions).NewWriter(ctx)
	w.ContentType = "application/json"
	if _, err := w.Write(data); err != nil {
		_ = w.CloseWithError(err)
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
