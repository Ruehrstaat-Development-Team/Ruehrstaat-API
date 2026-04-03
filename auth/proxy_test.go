package auth

import (
	"crypto/tls"
	"net/http"
	"testing"
)

func TestRequestUsesSecureTransport(t *testing.T) {
	tests := []struct {
		name    string
		env     string
		request *http.Request
		want    bool
	}{
		{
			name:    "tls request",
			request: &http.Request{TLS: &tls.ConnectionState{Version: tls.VersionTLS13}, Header: make(http.Header)},
			want:    true,
		},
		{
			name:    "forwarded proto ignored from untrusted remote",
			request: &http.Request{RemoteAddr: "198.51.100.10:1234", Header: http.Header{"X-Forwarded-Proto": []string{"https"}}},
			want:    false,
		},
		{
			name:    "forwarded proto accepted from trusted remote",
			env:     "198.51.100.10/32",
			request: &http.Request{RemoteAddr: "198.51.100.10:1234", Header: http.Header{"X-Forwarded-Proto": []string{"https"}}},
			want:    true,
		},
		{
			name:    "forwarded header accepted from trusted remote",
			env:     "198.51.100.10/32",
			request: &http.Request{RemoteAddr: "198.51.100.10:1234", Header: http.Header{"Forwarded": []string{"for=192.0.2.1;proto=https;by=203.0.113.5"}}},
			want:    true,
		},
		{
			name:    "plain http request",
			request: &http.Request{RemoteAddr: "198.51.100.10:1234", Header: make(http.Header)},
			want:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("TRUSTED_PROXIES", tt.env)
			if got := RequestUsesSecureTransport(tt.request); got != tt.want {
				t.Fatalf("RequestUsesSecureTransport() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRefreshCookieSameSiteMode(t *testing.T) {
	tests := []struct {
		name    string
		env     string
		request *http.Request
		want    http.SameSite
	}{
		{name: "default lax", env: "", request: &http.Request{Header: make(http.Header)}, want: http.SameSiteLaxMode},
		{name: "strict config", env: "strict", request: &http.Request{Header: make(http.Header)}, want: http.SameSiteStrictMode},
		{name: "none requires secure transport", env: "none", request: &http.Request{TLS: &tls.ConnectionState{Version: tls.VersionTLS13}, Header: make(http.Header)}, want: http.SameSiteNoneMode},
		{name: "none falls back on insecure transport", env: "none", request: &http.Request{Header: make(http.Header)}, want: http.SameSiteLaxMode},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("REFRESH_COOKIE_SAMESITE", tt.env)
			if got := RefreshCookieSameSiteMode(tt.request); got != tt.want {
				t.Fatalf("RefreshCookieSameSiteMode() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestValidateCookieAuthRequest(t *testing.T) {
	tests := []struct {
		name        string
		sameSite    string
		frontend    string
		backend     string
		cors        string
		origin      string
		referer     string
		wantErr     bool
		wantErrCode string
	}{
		{name: "lax allows frontend origin", sameSite: "lax", frontend: "https://app.example/path", origin: "https://app.example", wantErr: false},
		{name: "strict allows backend referer", sameSite: "strict", backend: "https://api.example/base", referer: "https://api.example/v1/auth/refresh", wantErr: false},
		{name: "none allows frontend origin", sameSite: "none", frontend: "https://app.example/path", origin: "https://app.example", wantErr: false},
		{name: "none allows backend referer", sameSite: "none", backend: "https://api.example/base", referer: "https://api.example/v1/auth/refresh", wantErr: false},
		{name: "none allows explicit cors origin", sameSite: "none", cors: "https://spa.example", origin: "https://spa.example", wantErr: false},
		{name: "none allows one of multiple cors origins", sameSite: "none", cors: "https://spa.example, https://app.example/path", origin: "https://app.example", wantErr: false},
		{name: "lax rejects missing headers", sameSite: "lax", frontend: "https://app.example", wantErr: true, wantErrCode: "A4000"},
		{name: "strict rejects mismatched origin", sameSite: "strict", frontend: "https://app.example", origin: "https://evil.example", wantErr: true, wantErrCode: "A4000"},
		{name: "none rejects missing headers", sameSite: "none", frontend: "https://app.example", wantErr: true, wantErrCode: "A4000"},
		{name: "none rejects mismatched origin", sameSite: "none", frontend: "https://app.example", origin: "https://evil.example", wantErr: true, wantErrCode: "A4000"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("REFRESH_COOKIE_SAMESITE", tt.sameSite)
			t.Setenv("FRONTEND_URL", tt.frontend)
			t.Setenv("BACKEND_URL", tt.backend)
			t.Setenv("CORS_ALLOWED_ORIGINS", tt.cors)

			request := &http.Request{TLS: &tls.ConnectionState{Version: tls.VersionTLS13}, Header: make(http.Header)}
			if tt.origin != "" {
				request.Header.Set("Origin", tt.origin)
			}
			if tt.referer != "" {
				request.Header.Set("Referer", tt.referer)
			}

			err := ValidateCookieAuthRequest(request)
			if tt.wantErr {
				if err == nil {
					t.Fatal("ValidateCookieAuthRequest() error = nil, want error")
				}
				if err.Code() != tt.wantErrCode {
					t.Fatalf("ValidateCookieAuthRequest() code = %q, want %q", err.Code(), tt.wantErrCode)
				}
				return
			}

			if err != nil {
				t.Fatalf("ValidateCookieAuthRequest() error = %v, want nil", err)
			}
		})
	}
}

func TestValidateTrustedOriginRequest(t *testing.T) {
	tests := []struct {
		name         string
		frontend     string
		backend      string
		cors         string
		origin       string
		referer      string
		secFetchSite string
		wantErr      bool
		wantErrCode  string
	}{
		{name: "allows frontend origin", frontend: "https://app.example/path", origin: "https://app.example", wantErr: false},
		{name: "allows backend referer", backend: "https://api.example/base", referer: "https://api.example/v1/auth/quicklogin", wantErr: false},
		{name: "allows explicit cors origin", cors: "https://spa.example", origin: "https://spa.example", wantErr: false},
		{name: "allows requests without browser headers", frontend: "https://app.example", wantErr: false},
		{name: "rejects browser request missing trusted origin", frontend: "https://app.example", secFetchSite: "cross-site", wantErr: true, wantErrCode: "A4000"},
		{name: "rejects mismatched origin", frontend: "https://app.example", origin: "https://evil.example", wantErr: true, wantErrCode: "A4000"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("FRONTEND_URL", tt.frontend)
			t.Setenv("BACKEND_URL", tt.backend)
			t.Setenv("CORS_ALLOWED_ORIGINS", tt.cors)

			request := &http.Request{TLS: &tls.ConnectionState{Version: tls.VersionTLS13}, Header: make(http.Header)}
			if tt.origin != "" {
				request.Header.Set("Origin", tt.origin)
			}
			if tt.referer != "" {
				request.Header.Set("Referer", tt.referer)
			}
			if tt.secFetchSite != "" {
				request.Header.Set("Sec-Fetch-Site", tt.secFetchSite)
			}

			err := ValidateTrustedOriginRequest(request)
			if tt.wantErr {
				if err == nil {
					t.Fatal("ValidateTrustedOriginRequest() error = nil, want error")
				}
				if err.Code() != tt.wantErrCode {
					t.Fatalf("ValidateTrustedOriginRequest() code = %q, want %q", err.Code(), tt.wantErrCode)
				}
				return
			}

			if err != nil {
				t.Fatalf("ValidateTrustedOriginRequest() error = %v, want nil", err)
			}
		})
	}
}

func TestValidateSessionEstablishingRequest(t *testing.T) {
	tests := []struct {
		name         string
		frontend     string
		backend      string
		cors         string
		origin       string
		referer      string
		secFetchSite string
		userAgent    string
		accept       string
		wantErr      bool
		wantErrCode  string
	}{
		{name: "allows trusted browser origin", frontend: "https://app.example", origin: "https://app.example", userAgent: "Mozilla/5.0", accept: "application/json", wantErr: false},
		{name: "rejects browser without origin metadata", frontend: "https://app.example", userAgent: "Mozilla/5.0", accept: "application/json", wantErr: true, wantErrCode: "A4000"},
		{name: "rejects browser sec fetch metadata without trusted origin", frontend: "https://app.example", userAgent: "Mozilla/5.0", accept: "application/json", secFetchSite: "same-origin", wantErr: true, wantErrCode: "A4000"},
		{name: "allows non browser request without origin metadata", frontend: "https://app.example", userAgent: "Go-http-client/1.1", accept: "application/json", wantErr: false},
		{name: "rejects mismatched browser origin", frontend: "https://app.example", origin: "https://evil.example", userAgent: "Mozilla/5.0", accept: "application/json", wantErr: true, wantErrCode: "A4000"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("FRONTEND_URL", tt.frontend)
			t.Setenv("BACKEND_URL", tt.backend)
			t.Setenv("CORS_ALLOWED_ORIGINS", tt.cors)

			request := &http.Request{TLS: &tls.ConnectionState{Version: tls.VersionTLS13}, Header: make(http.Header)}
			if tt.origin != "" {
				request.Header.Set("Origin", tt.origin)
			}
			if tt.referer != "" {
				request.Header.Set("Referer", tt.referer)
			}
			if tt.secFetchSite != "" {
				request.Header.Set("Sec-Fetch-Site", tt.secFetchSite)
			}
			if tt.userAgent != "" {
				request.Header.Set("User-Agent", tt.userAgent)
			}
			if tt.accept != "" {
				request.Header.Set("Accept", tt.accept)
			}

			err := ValidateSessionEstablishingRequest(request)
			if tt.wantErr {
				if err == nil {
					t.Fatal("ValidateSessionEstablishingRequest() error = nil, want error")
				}
				if err.Code() != tt.wantErrCode {
					t.Fatalf("ValidateSessionEstablishingRequest() code = %q, want %q", err.Code(), tt.wantErrCode)
				}
				return
			}

			if err != nil {
				t.Fatalf("ValidateSessionEstablishingRequest() error = %v, want nil", err)
			}
		})
	}
}
