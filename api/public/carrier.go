package public

import (
	"ruehrstaat-backend/db"
	"ruehrstaat-backend/db/entities"
	"ruehrstaat-backend/errors"
	"ruehrstaat-backend/serialize"
	"ruehrstaat-backend/services/carrier"

	"github.com/gin-gonic/gin"
)

func publicGetCarrier(c *gin.Context) {
	carrierId := c.Param("id")
	if carrierId == "" {
		errors.ReturnWithError(c, carrier.ErrBadRequest)
		return
	}

	cr := entities.Carrier{}
	if res := db.DB.Where("id = ?", carrierId).Preload("Owner").First(&cr); res.Error != nil {
		errors.ReturnWithError(c, carrier.ErrCarrierNotFound)
		return
	}

	serialize.JSON[entities.Carrier](c, &serialize.CarrierSerializer{Limited: true, Full: false}, cr)
}

func publicGetAllCarriers(c *gin.Context) {
	carriers := []entities.Carrier{}
	categoryOrder := "CASE category " +
		"WHEN 'flagship' THEN 1 " +
		"WHEN 'freighter' THEN 2 " +
		"WHEN 'supportvessel' THEN 3 " +
		"ELSE 4 END, name ASC"

	if res := db.DB.Preload("Owner").Order(categoryOrder).Find(&carriers); res.Error != nil {
		c.JSON(404, gin.H{"error": "Carriers not found"})
		return
	}

	serialize.JSONArray(c, &serialize.CarrierSerializer{Limited: true, Full: false}, carriers)
}

func publicGetAllCarriersSortedByCategory(c *gin.Context) {
	// returns json {
	// 	"flagship": [Carrier, Carrier, ...],
	// 	"freighter": [Carrier, Carrier, ...],
	// 	"supportvessel": [Carrier, Carrier, ...],
	// 	"other": [Carrier, Carrier, ...]
	// }

	carriers := map[string][]entities.Carrier{
		"flagship":      {},
		"freighter":     {},
		"supportvessel": {},
		"other":         {},
	}

	tmpCarriers := []entities.Carrier{}
	if res := db.DB.Preload("Owner").Order("name ASC").Find(&tmpCarriers); res.Error != nil {
		c.JSON(404, gin.H{"error": "Carriers not found"})
		return
	}
	for _, carrier := range tmpCarriers {
		switch carrier.Category {
		case entities.CarrierCategoryFlagship:
			carriers["flagship"] = append(carriers["flagship"], carrier)
		case entities.CarrierCategoryFreighter:
			carriers["freighter"] = append(carriers["freighter"], carrier)
		case entities.CarrierCategorySupportVessel:
			carriers["supportvessel"] = append(carriers["supportvessel"], carrier)
		default:
			carriers["other"] = append(carriers["other"], carrier)
		}
	}
	c.JSON(200, carriers)
}
