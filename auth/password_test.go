package auth

import "testing"

func TestValidatePasswordStrength(t *testing.T) {
	tests := []struct {
		name     string
		password string
		wantErr  bool
	}{
		{name: "too short", password: "Aa1!test", wantErr: true},
		{name: "missing uppercase", password: "lowercase1!x", wantErr: true},
		{name: "missing lowercase", password: "UPPERCASE1!X", wantErr: true},
		{name: "missing number", password: "NoNumbers!!", wantErr: true},
		{name: "missing special", password: "NoSpecial12", wantErr: true},
		{name: "valid exact minimum", password: "Abcdef1!xy", wantErr: false},
		{name: "valid long password", password: "StrongPassword1!", wantErr: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validatePasswordStrength(tt.password)
			if (err != nil) != tt.wantErr {
				t.Fatalf("validatePasswordStrength(%q) error = %v, wantErr %v", tt.password, err, tt.wantErr)
			}
			if err != nil && err != ErrPasswordTooWeak {
				t.Fatalf("validatePasswordStrength(%q) returned unexpected error: %v", tt.password, err)
			}
		})
	}
}
