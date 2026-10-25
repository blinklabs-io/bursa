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

package api

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/blinklabs-io/bursa"
	"github.com/blinklabs-io/gouroboros/cbor"
	"github.com/stretchr/testify/require"
)

// babbageTxHex is the reference GenTx_Babbage payload. It decodes as Alonzo,
// Babbage and Conway, so its era cannot be inferred from the CBOR.
const babbageTxHex = "84a3008001800200a0f5f6"

const babbageTxEnvelope = `{"type":"Tx BabbageEra","description":"","cborHex":"` +
	babbageTxHex + `"}`

func postTx(t *testing.T, handler http.HandlerFunc, path string, body any) (int, []byte) {
	t.Helper()
	reqBody, err := json.Marshal(body)
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handler(w, req)
	resp := w.Result()
	defer resp.Body.Close()
	out, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return resp.StatusCode, out
}

// vkeyWitnessesTagged reports whether the vkey witness field of a signed
// transaction is wrapped in CBOR tag 258, which only Conway and later accept.
func vkeyWitnessesTagged(t *testing.T, txHex string) bool {
	t.Helper()
	raw, err := hex.DecodeString(txHex)
	require.NoError(t, err)
	var arr []cbor.RawMessage
	_, err = cbor.Decode(raw, &arr)
	require.NoError(t, err)
	if len(arr) < 2 {
		t.Fatalf("transaction has %d elements, want at least 2", len(arr))
	}
	ws := map[uint64]cbor.RawMessage{}
	_, err = cbor.Decode(arr[1], &ws)
	require.NoError(t, err)
	field, ok := ws[0]
	require.True(t, ok && len(field) > 0, "no vkey witness field")
	return field[0] == 0xd9
}

func testSigningKeyJSON(t *testing.T) string {
	t.Helper()
	mnemonic, err := bursa.GenerateMnemonic()
	require.NoError(t, err)
	wallet, err := bursa.NewWallet(mnemonic, bursa.WithNetwork("mainnet"))
	require.NoError(t, err)
	skeyJSON, err := json.Marshal(wallet.PaymentExtendedSKey)
	require.NoError(t, err)
	return string(skeyJSON)
}

func TestHandleTxBabbageEnvelopeKeepsEra(t *testing.T) {
	skey := testSigningKeyJSON(t)

	status, body := postTx(t, handleTxSign, "/api/tx/sign", TxSignRequest{
		TxCbor:      babbageTxEnvelope,
		SigningKeys: []string{skey},
	})
	require.Equal(t, http.StatusOK, status, "body: %s", body)
	var signed TxCborResponse
	require.NoError(t, json.Unmarshal(body, &signed))
	require.False(t, vkeyWitnessesTagged(t, signed.TxCbor),
		"sign wrapped Babbage vkey witnesses in tag 258")

	status, body = postTx(t, handleTxWitness, "/api/tx/witness", TxWitnessRequest{
		TxCbor:     babbageTxEnvelope,
		SigningKey: skey,
	})
	require.Equal(t, http.StatusOK, status, "body: %s", body)
	var wit TxWitnessResponse
	require.NoError(t, json.Unmarshal(body, &wit))

	status, body = postTx(t, handleTxAssemble, "/api/tx/assemble", TxAssembleRequest{
		TxCbor:    babbageTxEnvelope,
		Witnesses: []string{wit.Witness},
	})
	require.Equal(t, http.StatusOK, status, "body: %s", body)
	var assembled TxCborResponse
	require.NoError(t, json.Unmarshal(body, &assembled))
	require.False(t, vkeyWitnessesTagged(t, assembled.TxCbor),
		"assemble wrapped Babbage vkey witnesses in tag 258")
}

func TestHandleTxAmbiguousEraRejected(t *testing.T) {
	skey := testSigningKeyJSON(t)
	zeroWitness := "825820" + strings.Repeat("00", 32) + "5840" + strings.Repeat("00", 64)

	status, body := postTx(t, handleTxSign, "/api/tx/sign", TxSignRequest{
		TxCbor:      babbageTxHex,
		SigningKeys: []string{skey},
	})
	require.Equal(t, http.StatusBadRequest, status, "body: %s", body)
	require.Contains(t, string(body), "Tx ConwayEra", "error must name an era-typed envelope")

	status, body = postTx(t, handleTxAssemble, "/api/tx/assemble", TxAssembleRequest{
		TxCbor:    babbageTxHex,
		Witnesses: []string{zeroWitness},
	})
	require.Equal(t, http.StatusBadRequest, status, "body: %s", body)
	require.Contains(t, string(body), "Tx ConwayEra", "error must name an era-typed envelope")
}
