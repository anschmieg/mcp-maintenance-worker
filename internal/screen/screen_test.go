package screen

import (
	"slices"
	"testing"
)

func TestInspectPolicyCategories(t *testing.T) {
	for _, test := range []struct {
		command string
		want    []string
		absent  []string
	}{
		{"cat < input", []string{"file-input"}, []string{"write"}},
		{"echo ok >> output", []string{"write", "output-append"}, []string{"output-overwrite"}},
		{"echo ok > output", []string{"write", "output-overwrite"}, []string{"output-append"}},
		{"cat <<< data >&2", []string{"inline-input", "descriptor-redirect"}, []string{"write"}},
		{"flag=1; if true; then echo \"$(cat < input)\" | cat; fi", []string{"assignment", "branch", "command-substitution", "file-input", "pipeline"}, nil},
		{"printf '%s' 'x >> y | $(z)'", []string{"execution", "unclear"}, []string{"pipeline", "write", "command-substitution"}},
		{"f() { for x in a b; do echo \"$x\"; done; }; (f && true) &", []string{"function-definition", "command-group", "loop", "parameter-expansion", "subshell", "conditional-chain", "background-job"}, nil},
		{"uptime", []string{"execution", "read-only"}, []string{"unclear"}},
	} {
		t.Run(test.command, func(t *testing.T) {
			decision, _, _, categories := Inspect(test.command)
			if decision == "invalid" {
				t.Fatal("expected valid Bash")
			}
			for _, category := range test.want {
				if !slices.Contains(categories, category) {
					t.Errorf("missing %q in %v", category, categories)
				}
			}
			for _, category := range test.absent {
				if slices.Contains(categories, category) {
					t.Errorf("unexpected %q in %v", category, categories)
				}
			}
		})
	}
}
