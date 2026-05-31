package output

import (
	"encoding/json"
	"io"

	"github.com/exalm-ai/exalm/pkg/plugin"
)

// JSON writes the report as indented JSON.
func JSON(w io.Writer, r plugin.Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}
