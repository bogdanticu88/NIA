package opauth

import (
	"fmt"
	"sort"
	"strings"
)

// Permission is what an authenticated operator is allowed to do. Three
// of them, deliberately, because there are three genuinely different
// levels of consequence on cmd/api's surface and inventing more would
// be modelling an org chart nobody has yet:
//
//	PermRead   look at the inventory, grants, credentials metadata,
//	           the audit trail, incidents and the graph
//	PermWrite  change what exists: register agents and tools, write and
//	           delete grants, issue, rotate, revoke, disable and enable
//	           credentials, add graph nodes and edges
//	PermKill   pull the kill switch, and restore from it
//
// Kill is separated from write because it is the one action whose
// consequence is immediate and total: it deletes an agent's tuples and
// cascades into revoking every credential it holds. "Any authenticated
// operator can kill any agent" was the specific gap this package's own
// doc comment named, and splitting this permission out is what closes
// it.
//
// Reading is separated from writing for the ordinary reason: an
// on-call engineer investigating an incident needs the audit trail and
// the incident records, and does not need the ability to issue
// credentials while they are in there.
type Permission string

const (
	PermRead  Permission = "read"
	PermWrite Permission = "write"
	PermKill  Permission = "kill"
)

// Role is a named bundle of permissions. Roles are what a token file
// declares; permissions are what a handler demands. The indirection
// exists so the mapping lives in one place, here, rather than being
// re-derived at each of the thirty-odd routes.
type Role string

const (
	// RoleViewer can look at everything and change nothing.
	RoleViewer Role = "viewer"
	// RoleOperator is the day-to-day role: everything a viewer can do,
	// plus changing what exists. It cannot kill.
	RoleOperator Role = "operator"
	// RoleAdmin adds the kill switch and restore.
	RoleAdmin Role = "admin"
)

// rolePermissions is the whole authorization model, on purpose. A
// reader should be able to see every permission any role has without
// following a call chain.
var rolePermissions = map[Role][]Permission{
	RoleViewer:   {PermRead},
	RoleOperator: {PermRead, PermWrite},
	RoleAdmin:    {PermRead, PermWrite, PermKill},
}

// KnownRoles returns the valid role names, sorted, for error messages
// that tell an operator what they could have written instead.
func KnownRoles() []string {
	out := make([]string, 0, len(rolePermissions))
	for r := range rolePermissions {
		out = append(out, string(r))
	}
	sort.Strings(out)
	return out
}

// ParseRole validates a role name from a token file. An unknown role is
// an error rather than a silently ignored entry: a typo'd "admn" that
// quietly became "no permissions" would look like a broken deployment,
// and one that quietly became "everything" would be worse.
func ParseRole(raw string) (Role, error) {
	r := Role(strings.ToLower(strings.TrimSpace(raw)))
	if _, ok := rolePermissions[r]; !ok {
		return "", fmt.Errorf("unknown role %q, valid roles are %s", raw, strings.Join(KnownRoles(), ", "))
	}
	return r, nil
}

// Can reports whether this operator holds perm through any of its
// roles. An operator with no roles can do nothing, which is the safe
// direction for a value that failed to load properly.
func (o Operator) Can(perm Permission) bool {
	for _, role := range o.Roles {
		for _, p := range rolePermissions[role] {
			if p == perm {
				return true
			}
		}
	}
	return false
}

// RoleNames is the operator's roles as plain strings, for log lines and
// error messages.
func (o Operator) RoleNames() []string {
	out := make([]string, 0, len(o.Roles))
	for _, r := range o.Roles {
		out = append(out, string(r))
	}
	return out
}
