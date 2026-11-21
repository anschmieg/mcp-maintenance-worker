package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	screening "maintenance-poc/internal/screen"
)

const maxCommand = screening.MaxCommand

type proposal struct {
	Command string `json:"command" jsonschema:"Bash text to screen; never executed"`
}
type outcome struct {
	ID             string `json:"request_id"`
	Decision       string `json:"decision"`
	Reason         string `json:"reason"`
	ClientResponse string `json:"client_response"`
	Executed       bool   `json:"executed"`
}

func screen(command string) (string, string) { return screening.Command(command) }

func newServer() *mcp.Server {
	s := mcp.NewServer(&mcp.Implementation{Name: "maintenance-screening-poc", Version: "0.1.0"}, nil)
	mcp.AddTool(s, &mcp.Tool{Name: "screen_maintenance_command", Description: "Dry run only. Screen Bash and optionally show a no-op review form. Never executes commands or grants permission."}, handle)
	return s
}

func handle(ctx context.Context, req *mcp.CallToolRequest, input proposal) (*mcp.CallToolResult, outcome, error) {
	decision, reason := screen(input.Command)
	o := outcome{ID: rand.Text(), Decision: decision, Reason: reason, ClientResponse: "not_requested"}
	if decision != "review" {
		return nil, o, nil
	}
	ctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	const schema = `{"type":"object","properties":{"confirm_dry_run":{"type":"boolean","title":"Confirm this test review (no command will run)"}},"required":["confirm_dry_run"]}`
	// Format as escaped plain text: command input can contain controls, newlines or deceptive Unicode.
	message := fmt.Sprintf("DRY RUN — no host, shell, or Docker action will occur.\nRequest: %s\nReason: %s\nSubmitted command (escaped): %+q", o.ID, o.Reason, input.Command)
	result, err := req.Session.Elicit(ctx, &mcp.ElicitParams{Mode: "form", Message: message, RequestedSchema: jsonSchema(schema)})
	if err != nil || result == nil {
		o.ClientResponse = "elicitation_unavailable"
		return nil, o, nil
	}
	switch result.Action {
	case "accept":
		confirmed, ok := result.Content["confirm_dry_run"].(bool)
		if ok && confirmed {
			o.ClientResponse = "accepted_test"
		} else {
			o.ClientResponse = "not_confirmed"
		}
	case "decline":
		o.ClientResponse = "declined"
	case "cancel":
		o.ClientResponse = "dismissed"
	default:
		o.ClientResponse = "unexpected_response"
	}
	return nil, o, nil
}

type jsonSchema string

func (s jsonSchema) MarshalJSON() ([]byte, error) { return []byte(s), nil }

func httpHandler(token string) http.Handler {
	expected := sha256.Sum256([]byte("Bearer " + token))
	s := newServer()
	mux := http.NewServeMux()
	mux.Handle("/mcp", mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return s }, nil))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Defense in depth for a local-only HTTP smoke test; no web app needs browser access.
		host, _, err := net.SplitHostPort(r.Host)
		ip := net.ParseIP(host)
		if r.Header.Get("Origin") != "" || (token == "" && (err != nil || ip == nil || !ip.IsLoopback())) {
			http.Error(w, "origin or host not permitted", http.StatusForbidden)
			return
		}
		if token != "" {
			actual := sha256.Sum256([]byte(r.Header.Get("Authorization")))
			if subtle.ConstantTimeCompare(expected[:], actual[:]) != 1 {
				w.Header().Set("WWW-Authenticate", `Bearer realm="maintenance-poc"`)
				http.Error(w, "missing or invalid bearer token", http.StatusUnauthorized)
				return
			}
		}
		if r.Method == http.MethodPost {
			r.Body = http.MaxBytesReader(w, r.Body, 32<<10)
		}
		mux.ServeHTTP(w, r)
	})
}

func main() {
	switch {
	case len(os.Args) == 1:
		if err := newServer().Run(context.Background(), &mcp.StdioTransport{}); err != nil {
			log.Fatal(err)
		}
	case len(os.Args) == 2 && os.Args[1] == "--http":
		addr, token := os.Getenv("MCP_ADDR"), os.Getenv("MCP_BEARER_TOKEN")
		if addr == "" {
			addr = "127.0.0.1:8765"
		}
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			log.Fatal("invalid MCP_ADDR")
		}
		if (token != "" && len(token) < 32) || (!net.ParseIP(host).IsLoopback() && token == "") {
			log.Fatal("non-loopback bind requires MCP_BEARER_TOKEN; tokens must be at least 32 bytes")
		}
		srv := http.Server{Addr: addr, Handler: httpHandler(token), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second}
		log.Printf("dry-run MCP listening at http://%s/mcp", srv.Addr)
		log.Fatal(srv.ListenAndServe())
	default:
		log.Fatal("usage: maintenance-poc [--http]")
	}
}
