//go:build js && wasm

package main

import (
	"maintenance-poc/internal/screen"
	"syscall/js"
)

func main() {
	js.Global().Set("maintenanceScreen", js.FuncOf(func(_ js.Value, args []js.Value) any {
		command := args[0].String()
		decision, reason, facts := screen.Analyze(command)
		values := make([]any, len(facts))
		for i, fact := range facts {
			values[i] = fact
		}
		categories := screen.Categories(command, decision)
		semantic := make([]any, len(categories))
		for i, category := range categories {
			semantic[i] = category
		}
		return map[string]any{"decision": decision, "reason": reason, "syntax_facts": values, "categories": semantic}
	}))
	select {}
}
