//go:build darwin && cgo

package sec

import "testing"

func TestErrorClassification(t *testing.T) {
	t.Parallel()

	laErr := func(code int) error {
		return &CFError{Domain: "com.apple.LocalAuthentication", Code: code}
	}
	osErr := func(code int) error {
		return &CFError{Domain: "NSOSStatusErrorDomain", Code: code}
	}

	cases := []struct {
		name         string
		err          error
		wantCanceled bool
		wantFailed   bool
	}{
		{"LA user cancel (-2)", laErr(-2), true, false},
		{"LA auth failed (-1)", laErr(-1), false, true},
		{"LA biometry lockout (-8)", laErr(-8), false, true},
		{"LA passcode not set (-5)", laErr(-5), false, false},
		{"LA biometry not available (-6)", laErr(-6), false, false},
		{"LA biometry not enrolled (-7)", laErr(-7), false, false},
		{"OSStatus user canceled", osErr(int(ErrUserCanceled)), true, false},
		{"OSStatus auth failed", osErr(int(ErrAuthFailed)), false, true},
		{"raw ErrUserCanceled", ErrUserCanceled, true, false},
		{"raw ErrAuthFailed", ErrAuthFailed, false, true},
		{"unrelated OSStatus", ErrItemNotFound, false, false},
	}

	for _, tc := range cases {
		if got := IsUserCanceled(tc.err); got != tc.wantCanceled {
			t.Errorf("%s: IsUserCanceled = %v, want %v", tc.name, got, tc.wantCanceled)
		}
		if got := IsAuthFailed(tc.err); got != tc.wantFailed {
			t.Errorf("%s: IsAuthFailed = %v, want %v", tc.name, got, tc.wantFailed)
		}
	}
}
