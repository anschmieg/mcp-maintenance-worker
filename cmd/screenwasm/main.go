//go:build js && wasm

package main

import (
	"maintenance-poc/internal/screen"
	"syscall/js"
)

func main() {
	js.Global().Set("maintenanceScreen", js.FuncOf(func(_ js.Value, args []js.Value) any {
		decision, reason, facts := screen.Analyze(args[0].String())
		values := make([]any, len(facts))
		for i, fact := range facts {
			values[i] = fact
		}
		return map[string]any{"decision": decision, "reason": reason, "syntax_facts": values}
	}))
	select {}
}
