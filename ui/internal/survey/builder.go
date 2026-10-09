// Copyright 2026 Blink Labs Software
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package survey

import (
	"context"
	"time"

	"github.com/blinklabs-io/bursa/ui/internal/spend"
	"golang.org/x/crypto/blake2b"
)

// MetadataBuilder is the wallet's transaction builder. *spend.Service satisfies
// it; the built transaction is confirmed through the spend flow.
type MetadataBuilder interface {
	WalletCredential(kind spend.SignerKind) ([28]byte, error)
	BuildMetadata(ctx context.Context, req spend.MetadataRequest) (spend.Preview, error)
}

// SetBuilder enables the respond, create and cancel operations. Call it before
// the service is used.
func (s *Service) SetBuilder(b MetadataBuilder) { s.builder = b }

// RespondRequest answers a survey. Omitting a question's answer abstains.
type RespondRequest struct {
	Survey  string   `json:"survey"`
	Role    Role     `json:"role"`
	Answers []Answer `json:"answers"`
}

// CreateRequest publishes a new survey owned by the wallet's payment key.
type CreateRequest struct {
	Title       string     `json:"title"`
	Description string     `json:"description"`
	Roles       []Role     `json:"roles"`
	EndEpoch    uint64     `json:"end_epoch"`
	Questions   []Question `json:"questions"`
	// AnchorURI is where the author will publish AnchorDocument, a longer
	// presentation of the survey. Its blake2b-256 hash goes on chain so readers
	// can tell the published document is the one referenced.
	AnchorURI      string       `json:"anchor_uri,omitempty"`
	AnchorDocument string       `json:"anchor_document,omitempty"`
	Seal           *SealOptions `json:"seal,omitempty"`
}

// SealOptions makes a new survey sealed: responses are timelock-encrypted to
// the Drand quicknet round and padded to PaddingSize bytes before encryption.
type SealOptions struct {
	Round       uint64 `json:"round"`
	PaddingSize uint64 `json:"padding_size"`
}

// CancelRequest cancels a survey the wallet's payment key owns.
type CancelRequest struct {
	Survey string `json:"survey"`
}

// signerFor maps a role to the wallet key that proves its credential. SPO and
// CC credentials are not wallet keys.
func signerFor(role Role) (spend.SignerKind, bool) {
	kind, ok := walletSigners[role]
	return kind, ok
}

var walletSigners = map[Role]spend.SignerKind{
	RoleDRep:        spend.SignerDRep,
	RoleStakeholder: spend.SignerStake,
	RoleKeyholder:   spend.SignerPayment,
}

func (s *Service) build(
	ctx context.Context,
	p Payload,
	signer spend.SignerKind,
	expectedCredential [28]byte,
) (spend.Preview, error) {
	md, err := Encode(p)
	if err != nil {
		return spend.Preview{}, err
	}
	return s.builder.BuildMetadata(ctx, spend.MetadataRequest{
		Label:                    Label,
		Value:                    md,
		Signer:                   signer,
		ExpectedSignerCredential: expectedCredential,
	})
}

// openSurvey finds a survey and requires that it still accepts activity.
func (s *Service) openSurvey(ctx context.Context, id string) (*known, error) {
	sn, err := s.snapshot(ctx)
	if err != nil {
		return nil, err
	}
	k, ok := sn.find(id)
	if !ok {
		return nil, ErrNotFound
	}
	switch {
	case k.cancelled:
		return nil, invalidf("survey is cancelled")
	case sn.cl.epoch > k.def.EndEpoch:
		return nil, invalidf("survey ended in epoch %d", k.def.EndEpoch)
	}
	return k, nil
}

// Respond builds a public response to an open survey, signed with the wallet
// key matching the claimed role, and returns it as a pending transaction.
func (s *Service) Respond(ctx context.Context, req RespondRequest) (spend.Preview, error) {
	if s.builder == nil {
		return spend.Preview{}, spend.ErrNoWallet
	}
	k, err := s.openSurvey(ctx, req.Survey)
	if err != nil {
		return spend.Preview{}, err
	}
	signer, ok := signerFor(req.Role)
	if !ok {
		return spend.Preview{}, invalidf("role %d cannot be signed with a wallet key", req.Role)
	}
	hash, err := s.builder.WalletCredential(signer)
	if err != nil {
		return spend.Preview{}, err
	}
	resp := Response{Survey: k.ref, Role: req.Role, Credential: Credential{Hash: hash}, Answers: req.Answers}
	if k.def.Mode.Sealed {
		if resp, err = sealResponse(k.def, resp); err != nil {
			return spend.Preview{}, err
		}
	}
	if err := k.def.CheckResponse(resp); err != nil {
		return spend.Preview{}, err
	}
	return s.build(
		ctx,
		Payload{Kind: KindResponses, Responses: []Response{resp}},
		signer,
		hash,
	)
}

// sealResponse validates the answers and replaces them with their timelock
// ciphertext. Once the reveal round has published, anyone can open a sealed
// response, so a late one is refused rather than published as if secret.
func sealResponse(d Definition, r Response) (Response, error) {
	if err := d.CheckAnswers(r.Answers); err != nil {
		return Response{}, err
	}
	if current := CurrentRound(time.Now()); current >= d.Mode.Round {
		return Response{}, invalidf("reveal round %d has already published (current round %d)", d.Mode.Round, current)
	}
	sealed, err := SealAnswers(r.Answers, d.Mode)
	if err != nil {
		return Response{}, err
	}
	r.Answers, r.Sealed = nil, sealed
	return r, nil
}

// Create builds a survey definition owned by the wallet's payment key. Text may
// be empty only when an external content anchor supplies it.
func (s *Service) Create(ctx context.Context, req CreateRequest) (spend.Preview, error) {
	if s.builder == nil {
		return spend.Preview{}, spend.ErrNoWallet
	}
	if (req.AnchorURI == "") != (req.AnchorDocument == "") {
		return spend.Preview{}, invalidf("an anchor needs both its URI and its document")
	}
	if req.AnchorURI == "" && req.Title == "" {
		return spend.Preview{}, invalidf("title required")
	}
	cl, err := s.clock(ctx)
	if err != nil {
		return spend.Preview{}, err
	}
	if req.EndEpoch <= cl.epoch {
		return spend.Preview{}, invalidf("end epoch %d must be after the current epoch %d", req.EndEpoch, cl.epoch)
	}
	owner, err := s.builder.WalletCredential(spend.SignerPayment)
	if err != nil {
		return spend.Preview{}, err
	}
	def := Definition{
		Owner: Credential{Hash: owner}, Title: req.Title, Description: req.Description,
		Roles: req.Roles, EndEpoch: req.EndEpoch, Questions: req.Questions,
	}
	if req.AnchorURI != "" {
		def.Anchor = &Anchor{URI: req.AnchorURI, Hash: blake2b.Sum256([]byte(req.AnchorDocument))}
	}
	if req.Seal != nil {
		def.Mode = SubmissionMode{Sealed: true, ChainHash: quicknetHash(), Round: req.Seal.Round, PaddingSize: req.Seal.PaddingSize}
		if current := CurrentRound(time.Now()); req.Seal.Round <= current {
			return spend.Preview{}, invalidf("reveal round %d is not in the future (current round %d)", req.Seal.Round, current)
		}
		// A round that publishes while the survey is open would let anyone read
		// the answers given so far before the rest are in, and this wallet stops
		// sealing responses once the round is out.
		if closes := CurrentRound(cl.endOf(req.EndEpoch)); req.Seal.Round <= closes {
			return spend.Preview{}, invalidf("reveal round %d publishes before epoch %d ends (round %d)", req.Seal.Round, req.EndEpoch, closes)
		}
		if req.Seal.PaddingSize > maxPadding {
			return spend.Preview{}, invalidf("padding size %d exceeds %d bytes", req.Seal.PaddingSize, maxPadding)
		}
	}
	return s.build(
		ctx,
		Payload{Kind: KindDefinitions, Definitions: []Definition{def}},
		spend.SignerPayment,
		owner,
	)
}

// Cancel builds a cancellation of a survey the wallet's payment key owns.
func (s *Service) Cancel(ctx context.Context, req CancelRequest) (spend.Preview, error) {
	if s.builder == nil {
		return spend.Preview{}, spend.ErrNoWallet
	}
	k, err := s.openSurvey(ctx, req.Survey)
	if err != nil {
		return spend.Preview{}, err
	}
	owner, err := s.builder.WalletCredential(spend.SignerPayment)
	if err != nil {
		return spend.Preview{}, err
	}
	if k.def.Owner.Script || k.def.Owner.Hash != owner {
		return spend.Preview{}, invalidf("survey is not owned by this wallet's payment key")
	}
	return s.build(
		ctx,
		Payload{Kind: KindCancellations, Cancellations: []Ref{k.ref}},
		spend.SignerPayment,
		owner,
	)
}
