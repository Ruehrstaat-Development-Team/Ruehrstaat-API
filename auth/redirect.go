package auth

import (
	"net/url"
	"os"
	"strings"

	rsterrors "ruehrstaat-backend/errors"
)

func frontendRedirectBase() (*url.URL, *rsterrors.RstError) {
	frontendURL := strings.TrimSpace(os.Getenv("FRONTEND_URL"))
	frontendBase, err := url.Parse(frontendURL)
	if err != nil || frontendBase.Scheme == "" || frontendBase.Host == "" {
		return nil, ErrServer
	}

	base := *frontendBase
	if base.Path == "" {
		base.Path = "/"
	} else if !strings.HasSuffix(base.Path, "/") {
		base.Path += "/"
	}

	return &base, nil
}

func redirectPathWithinBase(basePath string, targetPath string) bool {
	if basePath == "" || basePath == "/" {
		return true
	}

	trimmedBase := strings.TrimSuffix(basePath, "/")
	return targetPath == trimmedBase || strings.HasPrefix(targetPath, trimmedBase+"/")
}

func NormalizeFrontendRedirectTarget(redirectTo string, allowEmpty bool) (string, *rsterrors.RstError) {
	redirectTo = strings.TrimSpace(redirectTo)

	frontendBase, frontendErr := frontendRedirectBase()
	if frontendErr != nil {
		return "", frontendErr
	}

	if redirectTo == "" {
		if !allowEmpty {
			return "", ErrRedirectUrlMissing
		}
		return strings.TrimRight(frontendBase.String(), "/"), nil
	}

	target, err := url.Parse(redirectTo)
	if err != nil {
		return "", ErrInvalidRedirectUrl
	}

	if target.User != nil {
		return "", ErrInvalidRedirectUrl
	}

	if target.IsAbs() || target.Host != "" {
		if !strings.EqualFold(target.Scheme, frontendBase.Scheme) || !strings.EqualFold(target.Host, frontendBase.Host) {
			return "", ErrInvalidRedirectUrl
		}
		if !redirectPathWithinBase(frontendBase.Path, target.Path) {
			return "", ErrInvalidRedirectUrl
		}
		return target.String(), nil
	}

	target.Path = strings.TrimLeft(target.Path, "/")
	target.RawPath = strings.TrimLeft(target.RawPath, "/")
	return frontendBase.ResolveReference(target).String(), nil
}

func ResolveFrontendPath(path string) (string, *rsterrors.RstError) {
	base, rstErr := frontendRedirectBase()
	if rstErr != nil {
		return "", rstErr
	}

	target, err := url.Parse(strings.TrimLeft(strings.TrimSpace(path), "/"))
	if err != nil {
		return "", ErrInvalidRedirectUrl
	}

	if target.IsAbs() || target.Host != "" || target.User != nil {
		return "", ErrInvalidRedirectUrl
	}

	return base.ResolveReference(target).String(), nil
}

func AppendRedirectQuery(redirectTo string, values map[string]string) string {
	parsed, err := url.Parse(redirectTo)
	if err != nil {
		return redirectTo
	}

	query := parsed.Query()
	for key, value := range values {
		query.Set(key, value)
	}
	parsed.RawQuery = query.Encode()
	return parsed.String()
}
