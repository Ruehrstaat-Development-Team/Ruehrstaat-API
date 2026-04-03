package users

import "testing"

func TestIsNoopEmailChange(t *testing.T) {
	tests := []struct {
		name      string
		current   string
		requested string
		want      bool
	}{
		{name: "exact match", current: "user@example.com", requested: "user@example.com", want: true},
		{name: "normalized match", current: "User@Example.com", requested: "  user@example.com  ", want: true},
		{name: "different email", current: "user@example.com", requested: "other@example.com", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isNoopEmailChange(tt.current, tt.requested); got != tt.want {
				t.Fatalf("isNoopEmailChange(%q, %q) = %v, want %v", tt.current, tt.requested, got, tt.want)
			}
		})
	}
}
