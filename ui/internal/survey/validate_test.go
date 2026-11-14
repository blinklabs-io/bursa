package survey

import (
	"fmt"
	"math"
	"testing"
)

// Tallies and the detail response hold one entry per option per question, so
// a definition is bounded as a whole, not only per question: thousands of
// compact external-content questions would otherwise expand into millions of
// tally entries.
func TestDefinitionBoundsItsTotalTallySize(t *testing.T) {
	def := func(questions int) Definition {
		d := Definition{Owner: cred(false, 1), Title: "t", Roles: []Role{RoleDRep}, EndEpoch: 5}
		for i := range questions {
			d.Questions = append(d.Questions, Question{
				Kind: KindSingleChoice, Prompt: fmt.Sprint(i), OptionCount: MaxOptions,
			})
		}
		return d
	}
	noErr(t, def(MaxTallyEntries/MaxOptions).Validate())
	isErr(t, def(MaxTallyEntries/MaxOptions+1).Validate())

	// A custom question allocates no options, so its option count must not
	// enter the sum, where a huge value would wrap it back under the bound.
	custom := def(MaxTallyEntries / MaxOptions)
	custom.Questions = append(custom.Questions, Question{
		Kind: KindCustom, Prompt: "c", Anchor: &Anchor{URI: "https://x"}, OptionCount: math.MaxUint64,
	})
	isErr(t, custom.Validate())
}
