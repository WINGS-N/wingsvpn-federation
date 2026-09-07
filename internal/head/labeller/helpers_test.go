package labeller

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// toolAnswer заворачивает вход инструмента в ответ модели
func toolAnswer(input string) string {
	return `{"content":[{"type":"tool_use","name":"label","input":` + input + `}]}`
}

// verdictsFor отвечает "чисто" на каждый id, который приехал в теле
func verdictsFor(sent string) string {
	var body struct {
		Messages []struct {
			Content string `json:"content"`
		} `json:"messages"`
	}
	if err := json.Unmarshal([]byte(sent), &body); err != nil || len(body.Messages) == 0 {
		return "[]"
	}
	lines := strings.Split(strings.TrimSpace(body.Messages[0].Content), "\n")
	parts := make([]string, 0, len(lines))
	for i, line := range lines {
		if i == 0 || line == "" {
			continue
		}
		id := strings.SplitN(line, ",", 2)[0]
		parts = append(parts, `{"id":`+id+`,"abuse":false}`)
	}
	return `{"verdicts":[` + strings.Join(parts, ",") + `]}`
}

// newFakeAPIFunc - заглушка, которая отвечает на присланное
func newFakeAPIFunc(t *testing.T, answer func(sent string) string) *fakeAPI {
	t.Helper()
	api := &fakeAPI{}
	api.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		api.sent = string(raw)
		_, _ = w.Write([]byte(toolAnswer(answer(api.sent))))
	}))
	t.Cleanup(api.srv.Close)
	return api
}
