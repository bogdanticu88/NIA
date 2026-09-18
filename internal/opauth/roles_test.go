package opauth

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRolePermissions_ViewerCannotWriteOrKill(t *testing.T) {
	op := Operator{Name: "reader", Roles: []Role{RoleViewer}}
	if !op.Can(PermRead) {
		t.Fatal("viewer cannot read")
	}
	if op.Can(PermWrite) {
		t.Fatal("viewer can write")
	}
	if op.Can(PermKill) {
		t.Fatal("viewer can kill")
	}
}

// TestRolePermissions_OperatorCannotKill is the specific separation this
// whole file exists for. "Any authenticated operator can kill any agent"
// was the named gap; an operator role that can issue credentials and
// write grants but not pull the kill switch is what closes it.
func TestRolePermissions_OperatorCannotKill(t *testing.T) {
	op := Operator{Name: "day-to-day", Roles: []Role{RoleOperator}}
	if !op.Can(PermRead) || !op.Can(PermWrite) {
		t.Fatal("operator cannot read or write")
	}
	if op.Can(PermKill) {
		t.Fatal("operator can kill, the kill switch is meant to be admin only")
	}
}

func TestRolePermissions_AdminCanEverything(t *testing.T) {
	op := Operator{Name: "admin", Roles: []Role{RoleAdmin}}
	for _, p := range []Permission{PermRead, PermWrite, PermKill} {
		if !op.Can(p) {
			t.Fatalf("admin cannot %q", p)
		}
	}
}

func TestRolePermissions_NoRolesCanDoNothing(t *testing.T) {
	// The safe direction for a value that failed to load.
	var op Operator
	for _, p := range []Permission{PermRead, PermWrite, PermKill} {
		if op.Can(p) {
			t.Fatalf("an operator with no roles can %q", p)
		}
	}
}

func TestRolePermissions_MultipleRolesUnion(t *testing.T) {
	op := Operator{Name: "both", Roles: []Role{RoleViewer, RoleAdmin}}
	if !op.Can(PermKill) {
		t.Fatal("holding admin alongside viewer lost the kill permission")
	}
}

func TestParseRole(t *testing.T) {
	for _, in := range []string{"viewer", "OPERATOR", " admin "} {
		if _, err := ParseRole(in); err != nil {
			t.Fatalf("ParseRole(%q): %v", in, err)
		}
	}
	// A typo must be an error, not a silently empty or silently
	// all-powerful role.
	for _, in := range []string{"admn", "root", "", "superuser"} {
		if _, err := ParseRole(in); err == nil {
			t.Fatalf("ParseRole(%q) was accepted", in)
		}
	}
}

func TestRequire_ForbidsWithoutThePermission(t *testing.T) {
	h := Require(PermKill, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	r := httptest.NewRequest(http.MethodPost, "/policy/kill", nil)
	r = r.WithContext(withOperator(r.Context(), Operator{Name: "day-to-day", Roles: []Role{RoleOperator}}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 for an authenticated operator without the permission", rec.Code)
	}
	// The message names who they are and what they hold: an operator
	// debugging their own access should not have to guess.
	body := rec.Body.String()
	for _, want := range []string{"day-to-day", "operator", "kill"} {
		if !contains(body, want) {
			t.Fatalf("403 body %q does not mention %q", body, want)
		}
	}
}

func TestRequire_AllowsWithThePermission(t *testing.T) {
	h := Require(PermKill, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	r := httptest.NewRequest(http.MethodPost, "/policy/kill", nil)
	r = r.WithContext(withOperator(r.Context(), Operator{Name: "admin", Roles: []Role{RoleAdmin}}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 for an admin", rec.Code)
	}
}

// TestRequire_PassesThroughWhenNoOperatorIsEstablished covers the
// NIA_ALLOW_UNAUTHENTICATED=1 case: there is no identity to authorize,
// every request is already trusted, and refusing here would make the
// escape hatch useless without making anything safer.
func TestRequire_PassesThroughWhenNoOperatorIsEstablished(t *testing.T) {
	h := Require(PermKill, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/policy/kill", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 when no operator auth is configured at all", rec.Code)
	}
}

func TestMiddleware_PutsRolesOnTheContext(t *testing.T) {
	store := NewStaticStoreWithOperators(map[string]Operator{
		"tok": {Name: "reader", Roles: []Role{RoleViewer}},
	})
	var seen Operator
	var ok bool
	h := Middleware(store, http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		seen, ok = FromContext(r.Context())
	}))

	r := httptest.NewRequest(http.MethodGet, "/agents", nil)
	r.Header.Set("Authorization", "Bearer tok")
	h.ServeHTTP(httptest.NewRecorder(), r)

	if !ok {
		t.Fatal("no operator on the context after a successful verify")
	}
	if seen.Name != "reader" || len(seen.Roles) != 1 || seen.Roles[0] != RoleViewer {
		t.Fatalf("context operator = %+v, want reader with the viewer role", seen)
	}
}

func contains(haystack, needle string) bool {
	return len(haystack) >= len(needle) && (len(needle) == 0 || indexOf(haystack, needle) >= 0)
}

func indexOf(haystack, needle string) int {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return i
		}
	}
	return -1
}
