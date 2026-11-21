package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestScreen(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"uptime", "auto_candidate"}, {" \tuptime  ", "auto_candidate"},
		{"uptime # comment", "review"}, {"uptime;", "review"}, {"uptime\n", "review"},
		{"uptime\x00", "invalid"}, {"uptime\u202e", "invalid"}, {"df -h /srv/techleaddocker", "auto_candidate"},
		{"df -P /srv/techleaddocker", "review"}, {"uptime >/tmp/out", "review"},
		{"uptime | wc", "review"}, {"uptime && true", "review"}, {"uptime &", "review"},
		{"X=y uptime", "review"}, {"uptime $(date)", "review"}, {"sudo systemctl restart maintenance-demo.service", "review"},
		{"/usr/bin/uptime", "review"}, {"# comment only", "review"}, {"bash -c uptime", "review"},
		{"uptime '", "invalid"}, {strings.Repeat("x", maxCommand+1), "invalid"},
	} {
		if got, _ := screen(tc.in); got != tc.want {
			t.Errorf("%q: got %s, want %s", tc.in, got, tc.want)
		}
	}
}

type testAuthTransport struct{ token string }

func (tr testAuthTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	r := req.Clone(req.Context())
	r.Header.Set("Authorization", "Bearer "+tr.token)
	return http.DefaultTransport.RoundTrip(r)
}

func TestHTTPProtocol(t *testing.T) {
	token := strings.Repeat("t", 36)
	srv := httptest.NewServer(httpHandler(token))
	defer srv.Close()
	for _, tc := range []struct {
		command, action, response, decision string
		confirm                             bool
		calls                               int
	}{
		{"uptime", "", "not_requested", "auto_candidate", false, 0},
		{"uptime | wc", "accept", "accepted_test", "review", true, 1},
		{"uptime | wc", "accept", "not_confirmed", "review", false, 1},
		{"uptime | wc", "decline", "declined", "review", false, 1},
		{"uptime | wc", "cancel", "dismissed", "review", false, 1},
		{"uptime | wc", "", "elicitation_unavailable", "review", false, 0},
	} {
		t.Run(tc.action+tc.response, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
			defer cancel()
			forms := make(chan string, 3)
			opts := &mcp.ClientOptions{}
			if tc.action != "" {
				opts.ElicitationHandler = func(_ context.Context, r *mcp.ElicitRequest) (*mcp.ElicitResult, error) {
					forms <- r.Params.Message
					res := &mcp.ElicitResult{Action: tc.action}
					if tc.action == "accept" {
						res.Content = map[string]any{"confirm_dry_run": tc.confirm}
					}
					return res, nil
				}
			}
			client := mcp.NewClient(&mcp.Implementation{Name: "simulated-approval-client", Version: "0.1"}, opts)
			session, err := client.Connect(ctx, &mcp.StreamableClientTransport{Endpoint: srv.URL + "/mcp", HTTPClient: &http.Client{Transport: testAuthTransport{token}}}, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer session.Close()
			tools, err := session.ListTools(ctx, nil)
			if err != nil || len(tools.Tools) != 1 || tools.Tools[0].Name != "screen_maintenance_command" {
				t.Fatalf("list tools: %v %v", tools, err)
			}
			res, err := session.CallTool(ctx, &mcp.CallToolParams{Name: tools.Tools[0].Name, Arguments: proposal{Command: tc.command}})
			if err != nil || res.IsError {
				t.Fatalf("call failed: %v %v", res, err)
			}
			data, err := json.Marshal(res.StructuredContent)
			if err != nil {
				t.Fatal(err)
			}
			var o outcome
			if err = json.Unmarshal(data, &o); err != nil {
				t.Fatal(err)
			}
			if o.ID == "" || o.Executed || o.Decision != tc.decision || o.ClientResponse != tc.response {
				t.Fatalf("unexpected output: %+v", o)
			}
			if len(forms) != tc.calls {
				t.Fatalf("got %d forms, want %d", len(forms), tc.calls)
			}
			if tc.calls == 1 {
				msg := <-forms
				if !strings.Contains(msg, o.ID) || !strings.Contains(msg, tc.command) || !strings.Contains(msg, "DRY RUN") {
					t.Errorf("missing details in form: %q", msg)
				}
			}
		})
	}
}

func TestHTTPAccess(t *testing.T) {
	for _, tc := range []struct {
		token, host, origin, auth string
		status                    int
	}{
		{"secret", "example.test", "", "", 401},
		{"secret", "example.test", "https://untrusted.test", "Bearer secret", 403},
		{"", "example.test", "", "", 403},
		{"", "127.0.0.1:8765", "", "", 404},
	} {
		req := httptest.NewRequest("GET", "http://"+tc.host+"/missing", nil)
		req.Header.Set("Origin", tc.origin)
		req.Header.Set("Authorization", tc.auth)
		w := httptest.NewRecorder()
		httpHandler(tc.token).ServeHTTP(w, req)
		if w.Code != tc.status {
			t.Errorf("got %d want %d", w.Code, tc.status)
		}
	}
}
