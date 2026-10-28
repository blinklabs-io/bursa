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

package cli

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/blinklabs-io/bursa"
	"github.com/blinklabs-io/bursa/internal/txbuilder"
)

// submitChain records submitted transactions and fails with err when set.
type submitChain struct {
	txbuilder.Chain
	err       error
	submitted [][]byte
}

func (c *submitChain) SubmitTx(_ context.Context, tx []byte) error {
	if c.err != nil {
		return c.err
	}
	c.submitted = append(c.submitted, tx)
	return nil
}

const submitFixture = "../../testdata/conway-unsigned.tx"

func TestSubmitTxPrintsID(t *testing.T) {
	raw, err := bursa.ReadCborInputFile(submitFixture)
	if err != nil {
		t.Fatal(err)
	}
	want, err := bursa.TransactionID(raw)
	if err != nil {
		t.Fatal(err)
	}
	chain := &submitChain{}
	var out bytes.Buffer
	if err := submitTx(context.Background(), chain, submitFixture, &out); err != nil {
		t.Fatal(err)
	}
	if len(chain.submitted) != 1 || !bytes.Equal(chain.submitted[0], raw) {
		t.Fatal("transaction bytes were not passed to the node unchanged")
	}
	if strings.TrimSpace(out.String()) != want {
		t.Fatalf("printed %q, want tx id %s", out.String(), want)
	}
}

func TestSubmitTxReportsRejection(t *testing.T) {
	reason := errors.New("ValueNotConservedUTxO")
	chain := &submitChain{err: reason}
	var out bytes.Buffer
	err := submitTx(context.Background(), chain, submitFixture, &out)
	if !errors.Is(err, reason) {
		t.Fatalf("error %v does not carry the node's reason", err)
	}
	if !strings.Contains(err.Error(), "rejected") {
		t.Fatalf("error %q does not say the node rejected it", err)
	}
	if out.Len() != 0 {
		t.Fatalf("printed %q on rejection", out.String())
	}
}
