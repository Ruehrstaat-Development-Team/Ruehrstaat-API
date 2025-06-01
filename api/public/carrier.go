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
	carriers := map[string][]interface{}{
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

	flagships := []entities.Carrier{}
	freighters := []entities.Carrier{}
	supportVessels := []entities.Carrier{}
	other := []entities.Carrier{}
	for _, carrier := range tmpCarriers {
		switch carrier.Category {
		case entities.CarrierCategoryFlagship:
			flagships = append(flagships, carrier)
		case entities.CarrierCategoryFreighter:
			freighters = append(freighters, carrier)
		case entities.CarrierCategorySupportVessel:
			supportVessels = append(supportVessels, carrier)
		default:
			other = append(other, carrier)
		}
	}
	carriers["flagship"] = serialize.DoArray(&serialize.CarrierSerializer{Limited: true, Full: false}, flagships)
	carriers["freighter"] = serialize.DoArray(&serialize.CarrierSerializer{Limited: true, Full: false}, freighters)
	carriers["supportvessel"] = serialize.DoArray(&serialize.CarrierSerializer{Limited: true, Full: false}, supportVessels)
	carriers["other"] = serialize.DoArray(&serialize.CarrierSerializer{Limited: true, Full: false}, other)

	c.JSON(200, carriers)
}
