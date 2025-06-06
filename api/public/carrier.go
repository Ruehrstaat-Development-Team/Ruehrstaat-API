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
	if res := db.DB.Preload("Owner").Order(entities.GetCarrierCategorySortingOrder()).Find(&carriers); res.Error != nil {
		errors.ReturnWithError(c, carrier.ErrCarrierNotFound)
		return
	}

	serialize.JSONArray(c, &serialize.CarrierSerializer{Limited: true, Full: false}, carriers)
}

func publicGetAllCarriersSortedByCategory(c *gin.Context) {
	tmpCarriers := []entities.Carrier{}
	if res := db.DB.Preload("Owner").Order(entities.GetCarrierCategorySortingOrder()).Find(&tmpCarriers); res.Error != nil {
		errors.ReturnWithError(c, carrier.ErrCarrierNotFound)
		return
	}

	carriersByCategory := map[entities.CarrierCategory][]entities.Carrier{}
	for _, carrier := range tmpCarriers {
		carriersByCategory[carrier.Category] = append(carriersByCategory[carrier.Category], carrier)
	}

	carriersSlice := make([]entities.CarriersByCategory, 0, len(carriersByCategory))
	for category, carriers := range carriersByCategory {
		carriersSlice = append(carriersSlice, entities.CarriersByCategory{
			Category: string(category),
			Carriers: carriers,
		})
	}

	serialize.JSONArray(c, &serialize.CarriersByCategorySerializer{}, carriersSlice)
}
