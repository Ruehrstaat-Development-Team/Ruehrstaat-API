package serialize

import (
	"ruehrstaat-backend/services/moria"

	"github.com/gin-gonic/gin"
)

type MoriaInfoSerializer struct{}

func (s *MoriaInfoSerializer) Serialize(moriaInfo moria.MoriaInfo) interface{} {
	obj := &JsonObj{
		"moriaUrl":        moriaInfo.MoriaUrl,
		"moriaCategories": DoMapToArr(&MoriaCategorySerializer{}, moriaInfo.MoriaCategories),
	}

	return obj
}

func (s *MoriaInfoSerializer) ParseFlags(c *gin.Context) *MoriaInfoSerializer {
	return s
}

type MoriaCategorySerializer struct{}

func (s *MoriaCategorySerializer) Serialize(category moria.MoriaCategory) interface{} {
	obj := &JsonObj{
		"name":       category.Name,
		"path":       category.Path,
		"pattern":    category.Pattern,
		"categories": category.Categories,
	}

	return obj
}

func (s *MoriaCategorySerializer) ParseFlags(c *gin.Context) *MoriaCategorySerializer {
	return s
}
