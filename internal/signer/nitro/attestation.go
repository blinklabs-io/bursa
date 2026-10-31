// Copyright 2026 Blink Labs Software
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0

package nitro

import (
	"bytes"
	"fmt"

	"github.com/fxamacker/cbor/v2"
)

const (
	nitroPCRSize = 48
	coseSign1Tag = 18
)

type sign1Document struct {
	_           struct{} `cbor:",toarray"`
	Protected   []byte
	Unprotected cbor.RawMessage
	Payload     []byte
	Signature   []byte
}

type attestationPayload struct {
	PCRs map[uint][]byte `cbor:"pcrs"`
}

// requireProductionEvidence catches the platform's documented debug-mode
// representation before a KMS request. AWS KMS independently verifies the
// signed document and applies the configured PCR conditions.
func requireProductionEvidence(evidence []byte) error {
	var tagged cbor.Tag
	if err := cbor.Unmarshal(evidence, &tagged); err == nil && tagged.Number == coseSign1Tag {
		raw, err := cbor.Marshal(tagged.Content)
		if err != nil {
			return fmt.Errorf("%w: malformed COSE document", ErrMeasurement)
		}
		evidence = raw
	}
	var msg sign1Document
	if err := cbor.Unmarshal(evidence, &msg); err != nil {
		return fmt.Errorf("%w: malformed COSE document", ErrMeasurement)
	}
	var payload attestationPayload
	if err := cbor.Unmarshal(msg.Payload, &payload); err != nil {
		return fmt.Errorf("%w: malformed payload", ErrMeasurement)
	}
	pcr0 := payload.PCRs[0]
	if len(pcr0) != nitroPCRSize || bytes.Equal(pcr0, make([]byte, nitroPCRSize)) {
		return fmt.Errorf("%w: PCR0 is absent or debug", ErrMeasurement)
	}
	return nil
}
