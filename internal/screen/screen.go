package screen

import (
	"mvdan.cc/sh/v3/syntax"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"
)

const MaxCommand = 4096

func Command(command string) (string, string) {
	decision, reason, _ := Analyze(command)
	return decision, reason
}

func Analyze(command string) (decision, reason string, facts []string) {
	if len(command) > MaxCommand || strings.TrimSpace(command) == "" {
		return "invalid", "command must contain text and be at most 4096 bytes", nil
	}
	if !utf8.ValidString(command) || strings.ContainsFunc(command, func(r rune) bool {
		return r != '\t' && r != '\n' && (unicode.IsControl(r) || unicode.Is(unicode.Cf, r))
	}) {
		return "invalid", "command contains invalid UTF-8 or hidden control characters", nil
	}
	file, err := syntax.NewParser(syntax.Variant(syntax.LangBash)).Parse(strings.NewReader(command), "proposal")
	if err != nil {
		return "invalid", "invalid Bash syntax", nil
	}
	decision, reason = classify(command, file)
	if decision == "review" {
		facts = syntaxFacts(file)
	}
	return decision, reason, facts
}

func classify(command string, file *syntax.File) (string, string) {
	if len(file.Stmts) != 1 {
		return "review", "expected one simple command"
	}
	stmt := file.Stmts[0]
	call, ok := stmt.Cmd.(*syntax.CallExpr)
	if !ok || len(stmt.Redirs) != 0 || stmt.Negated || stmt.Background || stmt.Coprocess || len(call.Assigns) != 0 {
		return "review", "shell structure, assignment, or redirection requires review"
	}
	args := make([]string, 0, len(call.Args))
	for _, word := range call.Args {
		if len(word.Parts) != 1 {
			return "review", "nonliteral argument requires review"
		}
		lit, ok := word.Parts[0].(*syntax.Lit)
		if !ok || strings.ContainsAny(lit.Value, "\\*?[]{}~") {
			return "review", "nonliteral or expandable argument requires review"
		}
		args = append(args, lit.Value)
	}
	if slices.Equal(args, []string{"df", "-h", "/srv/techleaddocker"}) || slices.Equal(args, []string{"uptime"}) {
		// Require the original text to contain only these arguments and horizontal
		// ASCII whitespace. The parser can discard comments and terminators.
		fields := strings.FieldsFunc(command, func(r rune) bool { return r == ' ' || r == '\t' })
		if !slices.Equal(fields, args) {
			return "review", "expected only diagnostic arguments and horizontal whitespace"
		}
		return "auto_candidate", "matched an exact diagnostic rule; simulation only"
	}
	return "review", "no exact diagnostic rule matched"
}

func syntaxFacts(file *syntax.File) []string {
	facts := []string{}
	syntax.Walk(file, func(node syntax.Node) bool {
		var fact string
		switch n := node.(type) {
		case *syntax.BinaryCmd:
			switch n.Op {
			case syntax.Pipe, syntax.PipeAll:
				fact = "pipeline"
			case syntax.AndStmt, syntax.OrStmt:
				fact = "conditional_chain"
			}
		case *syntax.Redirect:
			fact = "redirection"
		case *syntax.CmdSubst:
			fact = "command_substitution"
		case *syntax.ProcSubst:
			fact = "process_substitution"
		case *syntax.ParamExp:
			fact = "parameter_expansion"
		}
		if fact != "" && !slices.Contains(facts, fact) {
			facts = append(facts, fact)
		}
		return true
	})
	return facts
}
