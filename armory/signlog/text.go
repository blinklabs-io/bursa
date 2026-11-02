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

package signlog

import "fmt"

// FormatEntry renders e as one line for an operator: sequence number,
// purpose, profile and role, the purpose's fields, and the summary, marked
// when it was cut.
func FormatEntry(e Entry) string {
	summary := e.Summary
	if e.SummaryTruncated {
		summary += " [summary truncated]"
	}

	if e.Purpose == PurposeOpCertNext {
		return fmt.Sprintf("%d %s %s %s issue=%d kes-period=%d kes-vkey-hash=%x %s",
			e.Seq, e.Purpose, e.Profile, e.Role, e.IssueCounter, e.KESPeriod, e.KESKeyHash, summary)
	}

	return fmt.Sprintf("%d %s %s %s body=%x %s", e.Seq, e.Purpose, e.Profile, e.Role, e.BodyHash, summary)
}
