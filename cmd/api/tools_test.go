package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/bogdanticu88/nia/internal/registry/tools"
)

func decodeTool(t *testing.T, rec *httptest.ResponseRecorder) tools.Tool {
	t.Helper()
	var tool tools.Tool
	if err := json.NewDecoder(rec.Body).Decode(&tool); err != nil {
		t.Fatalf("decode response body: %v", err)
	}
	return tool
}

func decodeTools(t *testing.T, rec *httptest.ResponseRecorder) []tools.Tool {
	t.Helper()
	var list []tools.Tool
	if err := json.NewDecoder(rec.Body).Decode(&list); err != nil {
		t.Fatalf("decode response body: %v", err)
	}
	return list
}

func TestHandleRegisterTool_DefaultsToReadOnly(t *testing.T) {
	s := newTestServer()
	mux := s.routes()

	rec := httptest.NewRecorder()
	body := `{"name":"invoice-lookup","description":"reads invoice status","transport":"http","owner":"bogdan"}`
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/tools", strings.NewReader(body)))
	if rec.Code != http.StatusCreated {
		t.Fatalf("register status = %d, want 201: %s", rec.Code, rec.Body.String())
	}
	tool := decodeTool(t, rec)
	if tool.Name != "invoice-lookup" || tool.RiskClass != tools.RiskReadOnly {
		t.Fatalf("got %+v, want invoice-lookup defaulted to read_only", tool)
	}
}

func TestHandleRegisterTool_RejectsUnknownRiskClass(t *testing.T) {
	s := newTestServer()
	mux := s.routes()

	rec := httptest.NewRecorder()
	body := `{"name":"invoice-lookup","risk_class":"very_risky"}`
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/tools", strings.NewReader(body)))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 for an unknown risk class: %s", rec.Code, rec.Body.String())
	}
}

func TestHandleRegisterTool_RejectsDuplicateName(t *testing.T) {
	s := newTestServer()
	mux := s.routes()

	body := `{"name":"invoice-lookup"}`
	mux.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/tools", strings.NewReader(body)))

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/tools", strings.NewReader(body)))
	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409 for a duplicate tool name: %s", rec.Code, rec.Body.String())
	}
}

func TestHandleListTools(t *testing.T) {
	s := newTestServer()
	mux := s.routes()

	for _, name := range []string{"invoice-lookup", "payment-issue"} {
		body := `{"name":"` + name + `","risk_class":"destructive"}`
		mux.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/tools", strings.NewReader(body)))
	}

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/tools", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	list := decodeTools(t, rec)
	if len(list) != 2 {
		t.Fatalf("got %d tools, want 2", len(list))
	}
}

func TestHandleGetTool_NotFound(t *testing.T) {
	s := newTestServer()
	mux := s.routes()

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/tools/does-not-exist", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 for an unknown tool: %s", rec.Code, rec.Body.String())
	}
}

func TestHandleGetTool_ReturnsRegistered(t *testing.T) {
	s := newTestServer()
	mux := s.routes()

	body := `{"name":"invoice-lookup","description":"reads invoice status","risk_class":"write","owner":"bogdan"}`
	mux.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/tools", strings.NewReader(body)))

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/tools/invoice-lookup", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	tool := decodeTool(t, rec)
	if tool.Name != "invoice-lookup" || tool.RiskClass != tools.RiskWrite || tool.Owner != "bogdan" {
		t.Fatalf("got %+v, want the registered invoice-lookup tool", tool)
	}
}
