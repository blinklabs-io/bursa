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

package kesagent

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"net"
)

// localClient names a caller with no network peer: a direct call on the agent.
var localClient = []any{"remote", "local"}

// clientAttrs returns the log attributes naming the peer on conn: its remote
// address ("local" for a unix socket) and, on a TLS connection with a client
// certificate, the certificate subject and the SHA-256 of its public key info.
// Never key material: the SPKI hash identifies the certificate only.
func clientAttrs(conn net.Conn) []any {
	remote := "local"
	if addr := conn.RemoteAddr(); addr != nil {
		switch addr.Network() {
		case "unix", "unixpacket":
		default:
			remote = addr.String()
		}
	}
	attrs := make([]any, 0, 6)
	attrs = append(attrs, "remote", remote)
	cs, ok := conn.(interface{ ConnectionState() tls.ConnectionState })
	if !ok {
		return attrs
	}
	certs := cs.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return attrs
	}
	sum := sha256.Sum256(certs[0].RawSubjectPublicKeyInfo)
	return append(attrs,
		"client_cert_subject", certs[0].Subject.String(),
		"client_cert_spki_sha256", hex.EncodeToString(sum[:]),
	)
}
