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
	// order by category first all flagships, then freighters, then support vessels, then others
	// 	CarrierCategoryFlagship      CarrierCategory = "flagship"
	// 	CarrierCategoryFreighter     CarrierCategory = "freighter"
	// 	CarrierCategorySupportVessel CarrierCategory = "supportvessel"
	// CarrierCategoryOther         CarrierCategory = "other"
	// and within category by name ascending
	// Order by category (flagship -> freighter -> supportvessel -> other) and then by name ascending
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
