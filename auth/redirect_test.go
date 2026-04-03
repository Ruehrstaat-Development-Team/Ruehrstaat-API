package auth

import "testing"

func TestNormalizeFrontendRedirectTarget(t *testing.T) {
	t.Setenv("FRONTEND_URL", "https://frontend.ruehrstaat.org/app")

	tests := []struct {
		name       string
		redirectTo string
		allowEmpty bool
		want       string
		wantErr    bool
	}{
		{name: "relative redirect allowed under frontend base path", redirectTo: "/login/discord/callback", want: "https://frontend.ruehrstaat.org/app/login/discord/callback"},
		{name: "same origin absolute redirect allowed within frontend base path", redirectTo: "https://frontend.ruehrstaat.org/app/welcome?from=discord", want: "https://frontend.ruehrstaat.org/app/welcome?from=discord"},
		{name: "same origin absolute redirect outside frontend base path rejected", redirectTo: "https://frontend.ruehrstaat.org/welcome?from=discord", wantErr: true},
		{name: "different origin rejected", redirectTo: "https://attacker.example/steal", wantErr: true},
		{name: "protocol relative rejected", redirectTo: "//attacker.example/steal", wantErr: true},
		{name: "missing redirect rejected", redirectTo: "", wantErr: true},
		{name: "missing redirect defaults when allowed", redirectTo: "", allowEmpty: true, want: "https://frontend.ruehrstaat.org/app"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NormalizeFrontendRedirectTarget(tt.redirectTo, tt.allowEmpty)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("NormalizeFrontendRedirectTarget() error = nil, want error")
				}
				return
			}

			if err != nil {
				t.Fatalf("NormalizeFrontendRedirectTarget() returned error: %v", err)
			}
			if got != tt.want {
				t.Fatalf("NormalizeFrontendRedirectTarget() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestNormalizeFrontendRedirectTargetRejectsMisconfiguredFrontendURL(t *testing.T) {
	t.Setenv("FRONTEND_URL", "://bad")

	_, err := NormalizeFrontendRedirectTarget("/callback", false)
	if err != ErrServer {
		t.Fatalf("NormalizeFrontendRedirectTarget() error = %v, want %v", err, ErrServer)
	}
}

func TestAppendRedirectQuery(t *testing.T) {
	got := AppendRedirectQuery("https://frontend.ruehrstaat.org/path?existing=1", map[string]string{"success": "true"})
	want := "https://frontend.ruehrstaat.org/path?existing=1&success=true"
	if got != want {
		t.Fatalf("AppendRedirectQuery() = %q, want %q", got, want)
	}
}

func TestResolveFrontendPath(t *testing.T) {
	t.Setenv("FRONTEND_URL", "https://frontend.ruehrstaat.org/app")

	got, err := ResolveFrontendPath("auth/callbacks/discord")
	if err != nil {
		t.Fatalf("ResolveFrontendPath() returned error: %v", err)
	}

	want := "https://frontend.ruehrstaat.org/app/auth/callbacks/discord"
	if got != want {
		t.Fatalf("ResolveFrontendPath() = %q, want %q", got, want)
	}
}
