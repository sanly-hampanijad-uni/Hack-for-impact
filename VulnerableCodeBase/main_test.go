package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHealthRoute(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "/health", nil)
	response := httptest.NewRecorder()

	newHandler().ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusOK)
	}
	if got := response.Header().Get("Content-Type"); got != "application/json; charset=utf-8" {
		t.Fatalf("Content-Type = %q, want JSON", got)
	}

	var body healthStatus
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body.Status != "ok" {
		t.Fatalf("status body = %q, want %q", body.Status, "ok")
	}
}

func TestAPIInfoRoute(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "/api/v1", nil)
	response := httptest.NewRecorder()

	newHandler().ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusOK)
	}

	var body apiInfo
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body.Name == "" || len(body.Routes) != 6 {
		t.Fatalf("unexpected API info: %+v", body)
	}
}

func TestLandingAndNotFoundPages(t *testing.T) {
	handler := newHandler()

	landing := httptest.NewRecorder()
	handler.ServeHTTP(landing, httptest.NewRequest(http.MethodGet, "/", nil))
	if landing.Code != http.StatusOK || !strings.Contains(landing.Body.String(), "Create account") {
		t.Fatalf("landing page status/content unexpected: %d", landing.Code)
	}

	notFound := httptest.NewRecorder()
	handler.ServeHTTP(notFound, httptest.NewRequest(http.MethodGet, "/missing", nil))
	if notFound.Code != http.StatusNotFound || !strings.Contains(notFound.Body.String(), "This page isn't here.") {
		t.Fatalf("not-found page status/content unexpected: %d", notFound.Code)
	}
}

func TestUnsupportedMethodAndRoute(t *testing.T) {
	t.Run("unsupported method", func(t *testing.T) {
		request := httptest.NewRequest(http.MethodPost, "/health", nil)
		response := httptest.NewRecorder()

		newHandler().ServeHTTP(response, request)

		if response.Code != http.StatusMethodNotAllowed {
			t.Fatalf("status = %d, want %d", response.Code, http.StatusMethodNotAllowed)
		}
		if got := response.Header().Get("Allow"); got != http.MethodGet {
			t.Fatalf("Allow = %q, want %q", got, http.MethodGet)
		}
	})

	for _, path := range []string{"/api/missing", "/health/extra"} {
		t.Run("unknown route "+path, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, path, nil)
			response := httptest.NewRecorder()

			newHandler().ServeHTTP(response, request)

			if response.Code != http.StatusNotFound {
				t.Fatalf("status = %d, want %d", response.Code, http.StatusNotFound)
			}
		})
	}
}

func TestRegisterLoginSessionAndLogout(t *testing.T) {
	service := newAuthService()
	handler := service.handler()

	register := httptest.NewRequest(http.MethodPost, "/api/v1/register", strings.NewReader(`{"username":"test_user","password":"correct-horse"}`))
	register.Header.Set("Content-Type", "application/json")
	registerResponse := httptest.NewRecorder()
	handler.ServeHTTP(registerResponse, register)
	if registerResponse.Code != http.StatusCreated {
		t.Fatalf("register status = %d, want %d: %s", registerResponse.Code, http.StatusCreated, registerResponse.Body.String())
	}
	if len(service.users) != 1 || string(service.users[0].PasswordHash) == "correct-horse" {
		t.Fatal("registration should store one user with a hashed password")
	}

	cookie := registerResponse.Result().Cookies()[0]
	accountRequest := httptest.NewRequest(http.MethodGet, "/account", nil)
	accountRequest.AddCookie(cookie)
	accountResponse := httptest.NewRecorder()
	handler.ServeHTTP(accountResponse, accountRequest)
	if accountResponse.Code != http.StatusOK || !strings.Contains(accountResponse.Body.String(), "test_user") {
		t.Fatalf("account page status/content unexpected: %d", accountResponse.Code)
	}

	me := httptest.NewRequest(http.MethodGet, "/api/v1/me", nil)
	me.AddCookie(cookie)
	meResponse := httptest.NewRecorder()
	handler.ServeHTTP(meResponse, me)
	if meResponse.Code != http.StatusOK || !strings.Contains(meResponse.Body.String(), "test_user") {
		t.Fatalf("session lookup failed: %d %s", meResponse.Code, meResponse.Body.String())
	}

	badLogin := httptest.NewRequest(http.MethodPost, "/api/v1/login", strings.NewReader(`{"username":"test_user","password":"wrong-password"}`))
	badLoginResponse := httptest.NewRecorder()
	handler.ServeHTTP(badLoginResponse, badLogin)
	if badLoginResponse.Code != http.StatusUnauthorized {
		t.Fatalf("invalid login status = %d, want %d", badLoginResponse.Code, http.StatusUnauthorized)
	}

	duplicate := httptest.NewRequest(http.MethodPost, "/api/v1/register", strings.NewReader(`{"username":"test_user","password":"another-horse"}`))
	duplicateResponse := httptest.NewRecorder()
	handler.ServeHTTP(duplicateResponse, duplicate)
	if duplicateResponse.Code != http.StatusConflict {
		t.Fatalf("duplicate registration status = %d, want %d", duplicateResponse.Code, http.StatusConflict)
	}

	logout := httptest.NewRequest(http.MethodPost, "/api/v1/logout", nil)
	logout.AddCookie(cookie)
	logoutResponse := httptest.NewRecorder()
	handler.ServeHTTP(logoutResponse, logout)
	if logoutResponse.Code != http.StatusNoContent {
		t.Fatalf("logout status = %d, want %d", logoutResponse.Code, http.StatusNoContent)
	}
	meAfterLogout := httptest.NewRequest(http.MethodGet, "/api/v1/me", nil)
	meAfterLogout.AddCookie(cookie)
	meAfterLogoutResponse := httptest.NewRecorder()
	handler.ServeHTTP(meAfterLogoutResponse, meAfterLogout)
	if meAfterLogoutResponse.Code != http.StatusUnauthorized {
		t.Fatalf("session after logout status = %d, want %d", meAfterLogoutResponse.Code, http.StatusUnauthorized)
	}
}

func TestAccountPageRedirectsWhenSignedOut(t *testing.T) {
	response := httptest.NewRecorder()
	newHandler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/account", nil))

	if response.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusSeeOther)
	}
	if got := response.Header().Get("Location"); got != "/" {
		t.Fatalf("Location = %q, want %q", got, "/")
	}
}
