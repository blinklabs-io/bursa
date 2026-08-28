package docs

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSwaggerDefinitionsAreCurrentAndCorrectlyNamed(t *testing.T) {
	raw, err := os.ReadFile("swagger.json")
	require.NoError(t, err)

	var spec struct {
		Definitions map[string]json.RawMessage `json:"definitions"`
	}
	require.NoError(t, json.Unmarshal(raw, &spec))
	full := string(raw)

	apiTypes := []string{
		"AddressBuildRequest", "AddressBuildResponse", "AddressEnumerateRequest",
		"AddressParseRequest", "AddressParseResponse", "ErrorResponse",
		"ScriptAddressRequest", "ScriptAddressResponse", "ScriptCreateRequest",
		"ScriptResponse", "ScriptValidateRequest", "ScriptValidateResponse",
	}
	for _, name := range apiTypes {
		_, ok := spec.Definitions["api."+name]
		assert.True(t, ok, "definitions missing api.%s", name)
		_, wrongPrefix := spec.Definitions["_."+name]
		assert.False(t, wrongPrefix, "definitions contains _.%s", name)
	}

	for name := range spec.Definitions {
		assert.Contains(t, full, `"#/definitions/`+name+`"`,
			"definitions.%s is never referenced by $ref", name)
	}
}
