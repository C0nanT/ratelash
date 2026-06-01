package attacks

import (
	"context"
	"flag"
	"net/http"
	"time"

	"github.com/conantorreswf/limithit/internal/metrics"
)

// Report is the printable result of an attack run.
// Both *metrics.Report and *metrics.ConnReport satisfy this interface.
type Report interface {
	String() string
}

// CommonOpts carries the flags registered for every attack by runAttack.
type CommonOpts struct {
	Total       int
	Concurrency int
	Timeout     time.Duration
	Headers     http.Header
	Pacer       metrics.Pacer // nil → noop (max rate)
}

// Base carries shared, pre-built dependencies injected into Attack.Run.
type Base struct {
	URL        string
	Client     *http.Client // nil for raw-socket attacks (e.g. slowloris)
	Common     CommonOpts
	ProgressCh chan<- metrics.Progress // nil = disabled; caller closes after Run returns
}

// FieldKind classifies how an attack flag is rendered in the interactive TUI.
type FieldKind int

const (
	FieldString FieldKind = iota // plain text input, no built-in validation
	FieldURL                     // text input validated as http/https URL
	FieldInt                     // numeric text input; set Validate for constraints
	FieldFloat                   // numeric text input; set Validate for constraints
	FieldBool                    // yes/no select stored as "true"/"false"
	FieldSelect                  // option dropdown; Choices must be non-empty
	FieldWarn                    // full-page safety gate: note + acknowledge select
	FieldFile                    // file path input with browser file picker in web UI
)

// FormField describes one interactive TUI form field for an attack.
//
// Value must survive the return of FormFields(); local variables work because
// Go's escape analysis heap-allocates them when their address is captured in
// the returned slice.
type FormField struct {
	Flag     string // flag name used to build CLI args (--<Flag> <Value>); "" = omit
	Label    string // human-readable title shown in the form
	Help     string // sub-label description
	Default  string // pre-fills the form field
	Kind     FieldKind
	Choices  []string           // "Label=value" or bare "value"; required for FieldSelect
	Value    *string            // filled by the generic form builder after the form runs
	Validate func(string) error // overrides the kind's default validation when non-nil
}

// Attack is the pluggable interface each attack package must implement.
type Attack interface {
	Name() string
	Synopsis() string
	Flags(fs *flag.FlagSet) // register attack-specific flags only
	Validate() error        // called after flag.Parse; check attack-specific constraints
	Run(ctx context.Context, base Base) (Report, error)
	FormFields() []FormField // metadata for TUI form generation
}

// HTTPMethodChoices returns the standard HTTP method list for FieldSelect fields.
func HTTPMethodChoices() []string {
	return []string{"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}
}
