package mails

import (
	"net/url"
	"os"
	"path"
	"strings"

	"ruehrstaat-backend/services/locale"
)

func resolveLocalizedFrontendLink(mailLocale string, frontendPath string, fragment string) string {
	resolvedLocale := "en"
	if locale.DoesLocaleExist(mailLocale) {
		resolvedLocale = mailLocale
	}

	frontendURL := strings.TrimSpace(os.Getenv("FRONTEND_URL"))
	frontendBase, err := url.Parse(frontendURL)
	if err != nil || frontendBase.Scheme == "" || frontendBase.Host == "" {
		frontendURL = strings.TrimRight(frontendURL, "/")
		return frontendURL + "/" + strings.TrimLeft(path.Join(resolvedLocale, frontendPath), "/") + "#" + fragment
	}

	base := *frontendBase
	if base.Path == "" {
		base.Path = "/"
	} else if !strings.HasSuffix(base.Path, "/") {
		base.Path += "/"
	}

	target := &url.URL{
		Path:     strings.TrimLeft(path.Join(resolvedLocale, frontendPath), "/"),
		Fragment: fragment,
	}

	return base.ResolveReference(target).String()
}
