package connection

import "fmt"

// Activate returns the connection approved for logins. It accepts the
// untested creation state and the disabled incident state: both are explicit
// operator approvals, typically run right after a passing dry-run. An
// already-active connection returns unchanged (idempotent). There is no
// path back to untested, so a tested connection can never silently regress
// to pre-test state.
//
// WHY a pure transition on the domain type: the CLI and the admin API both
// approve connections, and the legal states must be decided once — here —
// instead of re-implemented per entry point where they could drift apart.
// Callers persist the returned Status themselves.
func (c Connection) Activate() (Connection, error) {
	switch c.Status {
	case ConnectionStatusActive:
		return c, nil
	case ConnectionStatusUntested, ConnectionStatusDisabled:
		c.Status = ConnectionStatusActive
		return c, nil
	default:
		return Connection{}, fmt.Errorf("connection: activate: connection %q has unknown status %q", c.ID, c.Status)
	}
}

// Disable returns the connection removed from login service without losing
// its config, e.g. after an incident or key rotation. Only active
// connections may be disabled: untested ones already refuse logins, so
// disabling them would be noise. An already-disabled connection returns
// unchanged (idempotent). Re-enabling goes through Activate.
func (c Connection) Disable() (Connection, error) {
	switch c.Status {
	case ConnectionStatusDisabled:
		return c, nil
	case ConnectionStatusActive:
		c.Status = ConnectionStatusDisabled
		return c, nil
	default:
		return Connection{}, fmt.Errorf("connection: disable: connection %q is %q, not active", c.ID, c.Status)
	}
}
