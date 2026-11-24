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
	decision, reason, facts, _ = Inspect(command)
	return
}

// Inspect parses once for screening, assessment, and policy evaluation.
func Inspect(command string) (decision, reason string, facts, categories []string) {
	if len(command) > MaxCommand || strings.TrimSpace(command) == "" {
		return "invalid", "command must contain text and be at most 4096 bytes", nil, nil
	}
	if !utf8.ValidString(command) || strings.ContainsFunc(command, func(r rune) bool {
		return r != '\t' && r != '\n' && (unicode.IsControl(r) || unicode.Is(unicode.Cf, r))
	}) {
		return "invalid", "command contains invalid UTF-8 or hidden control characters", nil, nil
	}
	file, err := syntax.NewParser(syntax.Variant(syntax.LangBash)).Parse(strings.NewReader(command), "proposal")
	if err != nil {
		return "invalid", "invalid Bash syntax", nil, nil
	}
	decision, reason = classify(command, file)
	if decision == "review" {
		facts = syntaxFacts(file)
	}
	return decision, reason, facts, categoriesFor(file, decision)
}

// categoriesFor describes observable shell behavior. Unknown programs remain unclear.
func categoriesFor(file *syntax.File, decision string) []string {
	if decision == "auto_candidate" {
		return []string{"read-only", "execution"}
	}
	categories := []string{"unclear"}
	add := func(category string) {
		if !slices.Contains(categories, category) {
			categories = append(categories, category)
		}
	}
	syntax.Walk(file, func(node syntax.Node) bool {
		switch n := node.(type) {
		case *syntax.Stmt:
			if n.Background {
				add("background-job")
			}
			if n.Coprocess {
				add("coprocess")
			}
			if n.Negated {
				add("negation")
			}
		case *syntax.CallExpr:
			if len(n.Args) > 0 {
				add("execution")
			}
		case *syntax.Assign:
			add("assignment")
		case *syntax.Redirect:
			switch n.Op {
			case syntax.RdrOut, syntax.ClbOut, syntax.RdrAll:
				add("write")
				add("output-overwrite")
			case syntax.AppOut, syntax.AppAll:
				add("write")
				add("output-append")
			case syntax.RdrInOut:
				add("write")
				add("read-write-redirect")
			case syntax.RdrIn:
				add("file-input")
			case syntax.Hdoc, syntax.DashHdoc, syntax.WordHdoc:
				add("inline-input")
			case syntax.DplIn, syntax.DplOut:
				add("descriptor-redirect")
			}
		case *syntax.BinaryCmd:
			switch n.Op {
			case syntax.Pipe, syntax.PipeAll:
				add("pipeline")
			case syntax.AndStmt, syntax.OrStmt:
				add("conditional-chain")
			}
		case *syntax.CmdSubst:
			add("command-substitution")
		case *syntax.ProcSubst:
			add("process-substitution")
		case *syntax.ParamExp:
			add("parameter-expansion")
		case *syntax.ArithmExp, *syntax.ArithmCmd:
			add("arithmetic")
		case *syntax.Subshell:
			add("subshell")
		case *syntax.Block:
			add("command-group")
		case *syntax.IfClause, *syntax.CaseClause:
			add("branch")
		case *syntax.ForClause, *syntax.WhileClause:
			add("loop")
		case *syntax.FuncDecl:
			add("function-definition")
		}
		return true
	})
	return categories
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
