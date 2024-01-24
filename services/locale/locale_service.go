package locale

var locales = map[string]map[string]string{
	"en": {
		"email": "Email",
	},
	"de": {
		"email": "E-Mail",
	},
}

func Get(key string, locale string) string {
	// return locale if not exist return given key
	if _, ok := locales[locale]; !ok {
		return key
	}

	// return key if not exist return given key
	if _, ok := locales[locale][key]; !ok {
		return key
	}

	return locales[locale][key]
}

func DoesLocaleExist(locale string) bool {
	_, ok := locales[locale]
	return ok
}

func GetLocales() []string {
	keys := make([]string, 0, len(locales))
	for k := range locales {
		keys = append(keys, k)
	}
	return keys
}
