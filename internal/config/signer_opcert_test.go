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

package config

import (
	"reflect"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestSignerCallerOpCertKESAgentsYAML(t *testing.T) {
	t.Parallel()
	const doc = `
subject: ops
keys: ["aa"]
opcerts:
  - key: "aa"
    kes_vkeys: ["bb"]
    kes_agents:
      - spki_sha256: "cc"
        profile: "pool-a"
      - spki_sha256: "dd"
`
	var got SignerCallerConfig
	if err := yaml.Unmarshal([]byte(doc), &got); err != nil {
		t.Fatal(err)
	}
	want := []SignerCallerOpCertConfig{{
		Key:      "aa",
		KESVKeys: []string{"bb"},
		KESAgents: []SignerKESAgentConfig{
			{SPKISHA256: "cc", Profile: "pool-a"},
			{SPKISHA256: "dd"},
		},
	}}
	if !reflect.DeepEqual(got.OpCerts, want) {
		t.Fatalf("opcerts = %#v, want %#v", got.OpCerts, want)
	}
}
