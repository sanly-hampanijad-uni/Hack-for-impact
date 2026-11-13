package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNormalRoutes(t *testing.T) {
	handler, err := newHandler()
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/health", "/items"} {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, path, nil))
		if response.Code != http.StatusOK {
			t.Fatalf("%s returned %d", path, response.Code)
		}
	}
}

// Passing this test means the deliberately vulnerable behavior was reproduced,
// not that the application is secure. It is expected to fail after remediation.
func TestCVE2026100353Reproduces(t *testing.T) {
	handler, err := newHandler()
	if err != nil {
		t.Fatal(err)
	}
	if !reproduce(handler) {
		t.Fatal("expected the pinned vulnerable validator to panic")
	}
}
