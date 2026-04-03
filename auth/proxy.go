package auth

import (
	"net"
	"net/http"
	"net/url"
	"os"
	apierrors "ruehrstaat-backend/errors"
	"strings"
)

func RefreshCookieSameSiteMode(r *http.Request) http.SameSite {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("REFRESH_COOKIE_SAMESITE"))) {
	case "strict":
		return http.SameSiteStrictMode
	case "none":
		if RequestUsesSecureTransport(r) {
			return http.SameSiteNoneMode
		}
	}

	return http.SameSiteLaxMode
}

func ValidateCookieAuthRequest(r *http.Request) *apierrors.RstError {
	return validateTrustedOriginRequest(r, false)
}

func ValidateTrustedOriginRequest(r *http.Request) *apierrors.RstError {
	return validateTrustedOriginRequest(r, true)
}

func ValidateSessionEstablishingRequest(r *http.Request) *apierrors.RstError {
	return validateSessionEstablishingRequest(r)
}

func allowsBearerOnlyNonBrowserRequest(r *http.Request) bool {
	if r == nil {
		return false
	}
	if !strings.HasPrefix(strings.ToLower(strings.TrimSpace(r.Header.Get("Authorization"))), "bearer ") {
		return false
	}
	return !requestCarriesBrowserOriginContext(r) && !requestLooksLikeBrowser(r)
}

func validateTrustedOriginRequest(r *http.Request, allowRequestsWithoutBrowserOrigin bool) *apierrors.RstError {
	if allowRequestsWithoutBrowserOrigin && !requestCarriesBrowserOriginContext(r) {
		return nil
	}

	allowedOrigins := AllowedOriginsFromEnv("FRONTEND_URL", "BACKEND_URL", "CORS_ALLOWED_ORIGINS")
	if len(allowedOrigins) == 0 {
		return ErrForbidden
	}

	if OriginAllowed(r.Header.Get("Origin"), allowedOrigins) {
		return nil
	}

	if OriginAllowed(r.Header.Get("Referer"), allowedOrigins) {
		return nil
	}

	return ErrForbidden
}

func validateSessionEstablishingRequest(r *http.Request) *apierrors.RstError {
	if !requestCarriesBrowserOriginContext(r) {
		if requestLooksLikeBrowser(r) {
			return ErrForbidden
		}
		return nil
	}

	return validateTrustedOriginRequest(r, false)
}

func requestCarriesBrowserOriginContext(r *http.Request) bool {
	if r == nil {
		return false
	}
	return strings.TrimSpace(r.Header.Get("Origin")) != "" || strings.TrimSpace(r.Header.Get("Referer")) != "" || strings.TrimSpace(r.Header.Get("Sec-Fetch-Site")) != ""
}

func requestLooksLikeBrowser(r *http.Request) bool {
	if r == nil {
		return false
	}

	for _, header := range []string{"Sec-Fetch-Mode", "Sec-Fetch-Dest", "Sec-Fetch-User", "Sec-CH-UA", "Sec-CH-UA-Platform", "Sec-CH-UA-Mobile"} {
		if strings.TrimSpace(r.Header.Get(header)) != "" {
			return true
		}
	}

	userAgent := strings.TrimSpace(r.Header.Get("User-Agent"))
	if userAgent == "" {
		return false
	}

	accept := strings.ToLower(strings.TrimSpace(r.Header.Get("Accept")))
	if strings.Contains(strings.ToLower(userAgent), "mozilla/") {
		return strings.Contains(accept, "text/html") || strings.Contains(accept, "application/xhtml+xml") || strings.Contains(accept, "text/plain") || strings.Contains(accept, "*/*") || strings.Contains(accept, "application/json")
	}

	return false
}

func AllowedOriginsFromEnv(envVars ...string) map[string]struct{} {
	allowed := map[string]struct{}{}
	for _, envVar := range envVars {
		for _, candidate := range strings.Split(os.Getenv(envVar), ",") {
			candidate = strings.TrimSpace(candidate)
			if candidate == "" || candidate == "*" {
				continue
			}

			parsed, err := url.Parse(candidate)
			if err != nil || parsed.Scheme == "" || parsed.Host == "" {
				continue
			}
			allowed[parsed.Scheme+"://"+parsed.Host] = struct{}{}
		}
	}
	return allowed
}

func OriginAllowed(raw string, allowed map[string]struct{}) bool {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return false
	}

	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return false
	}

	_, ok := allowed[parsed.Scheme+"://"+parsed.Host]
	return ok
}

func TrustedProxiesFromEnv() ([]string, error) {
	raw := strings.TrimSpace(os.Getenv("TRUSTED_PROXIES"))
	if raw == "" {
		return []string{}, nil
	}

	parts := strings.Split(raw, ",")
	trusted := make([]string, 0, len(parts))
	for _, part := range parts {
		proxy := strings.TrimSpace(part)
		if proxy == "" {
			continue
		}
		trusted = append(trusted, proxy)
	}

	return trusted, nil
}

func RequestUsesSecureTransport(r *http.Request) bool {
	if r == nil {
		return false
	}
	if r.TLS != nil {
		return true
	}
	if !requestComesFromTrustedProxy(r) {
		return false
	}
	if strings.EqualFold(strings.TrimSpace(r.Header.Get("X-Forwarded-Proto")), "https") {
		return true
	}
	for _, forwardedValue := range strings.Split(r.Header.Get("Forwarded"), ",") {
		for _, part := range strings.Split(forwardedValue, ";") {
			key, value, ok := strings.Cut(strings.TrimSpace(part), "=")
			if ok && strings.EqualFold(key, "proto") && strings.EqualFold(strings.Trim(value, `"`), "https") {
				return true
			}
		}
	}
	return false
}

func requestComesFromTrustedProxy(r *http.Request) bool {
	trusted, err := TrustedProxiesFromEnv()
	if err != nil || len(trusted) == 0 {
		return false
	}

	host, _, splitErr := net.SplitHostPort(strings.TrimSpace(r.RemoteAddr))
	if splitErr != nil {
		host = strings.TrimSpace(r.RemoteAddr)
	}
	remoteIP := net.ParseIP(host)
	if remoteIP == nil {
		return false
	}

	for _, proxy := range trusted {
		if ip := net.ParseIP(proxy); ip != nil && ip.Equal(remoteIP) {
			return true
		}
		if _, network, cidrErr := net.ParseCIDR(proxy); cidrErr == nil && network.Contains(remoteIP) {
			return true
		}
	}

	return false
}
