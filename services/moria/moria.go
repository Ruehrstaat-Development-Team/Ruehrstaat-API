package moria

import "ruehrstaat-backend/errors"

type MoriaInfo struct {
	MoriaUrl        string                   `json:"moriaUrl"`
	MoriaCategories map[string]MoriaCategory `json:"moriaCategories"`
}

type MoriaCategory struct {
	Name       string   `json:"name"`
	Path       string   `json:"path"`
	Pattern    string   `json:"pattern"`
	Categories []string `json:"categories"`
}

var MoriaCategories = map[string]MoriaCategory{
	"carrier": {
		Name:    "Carrier",
		Path:    "carrier",
		Pattern: "<id>_<category>",
		Categories: []string{
			"banner",
			"thumbnail",
		},
	},
}

var moriaUrl = ""
var moriaToken = ""

var enabled = false

func InitMoria(initMoriaUrl string, initMoriaToken string) *errors.RstError {
	if initMoriaUrl == "" {
		return ErrMoriaUrlEmpty
	}
	if initMoriaToken == "" {
		return ErrMoriaInitTokenEmpty
	}

	moriaToken = initMoriaToken
	moriaUrl = initMoriaUrl

	enabled = true

	return nil
}

func GetMoriaInfo() *MoriaInfo {
	if !enabled {
		return nil
	}

	return &MoriaInfo{
		MoriaUrl:        moriaUrl,
		MoriaCategories: MoriaCategories,
	}
}
