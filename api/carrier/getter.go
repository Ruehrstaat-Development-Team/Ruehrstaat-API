package carrier

import (
	"ruehrstaat-backend/db"
	"ruehrstaat-backend/db/entities"
	"ruehrstaat-backend/errors"
	"ruehrstaat-backend/serialize"
	"ruehrstaat-backend/services/carrier"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

func getAllCarriers(c *gin.Context) {
	user := c.MustGet("user").(*entities.User)
	tokenValue, exists := c.Get("token")
	token := &entities.ApiToken{}
	if exists {
		token = tokenValue.(*entities.ApiToken)
	}

	carriers := []entities.Carrier{}

	if user.IsAdmin || (token != nil && token.HasFullReadAccess) {
		if res := db.DB.Find(&carriers).Preload("Owner"); res.Error != nil {
			c.Error(res.Error)
			errors.ReturnWithError(c, carrier.ErrInternalServerError)
			return
		}
	} else {
		// get carrier where owner id is user id
		if res := db.DB.Where("owner_id = ?", user.ID).Preload("Owner").Find(&carriers); res.Error != nil {
			c.Error(res.Error)
			errors.ReturnWithError(c, carrier.ErrInternalServerError)
			return
		}

		// if token is not nil, get append carriers where id is in token.HadReadAccessTo
		if token != nil {
			addtionalCarriers := []entities.Carrier{}
			if res := db.DB.Where("id IN (?)", token.HasReadAccessTo).Preload("Owner").Find(&addtionalCarriers); res.Error != nil {
				c.Error(res.Error)
				errors.ReturnWithError(c, carrier.ErrInternalServerError)
				return
			}
			carriers = append(carriers, addtionalCarriers...)
		}
	}

	serialize.JSONArray[entities.Carrier](c, (&serialize.CarrierSerializer{}).ParseFlags(c), carriers)
}

func getCarrier(c *gin.Context) {
	user := c.MustGet("user").(*entities.User)
	tokenValue, exists := c.Get("token")
	token := &entities.ApiToken{}
	if exists {
		token = tokenValue.(*entities.ApiToken)
	}

	carrierId := c.Param("id")
	if carrierId == "" {
		errors.ReturnWithError(c, carrier.ErrBadRequest)
		return
	}

	cr := entities.Carrier{}
	if res := db.DB.Where("id = ?", carrierId).Preload("Owner").First(&cr); res.Error != nil {
		if !user.IsAdmin {
			errors.ReturnWithError(c, carrier.ErrForbidden)
			return
		}
		errors.ReturnWithError(c, carrier.ErrCarrierNotFound)
		return
	}

	if !user.IsAdmin && (token == nil || !token.HasFullReadAccess) {
		if *cr.OwnerID != user.ID && !token.HasReadAccessToCarrier(cr.ID) {
			errors.ReturnWithError(c, carrier.ErrForbidden)
			return
		}
	}

	serialize.JSON[entities.Carrier](c, (&serialize.CarrierSerializer{}).ParseFlags(c), cr)
}

func getAllServices(c *gin.Context) {
	_, exists := c.Get("user")
	if !exists {
		errors.ReturnWithError(c, carrier.ErrUnauthorized)
		return
	}

	services := entities.CarrierServices
	serialize.JSONMapToArr[entities.CarrierService](c, (&serialize.CarrierServiceSerializer{}).ParseFlags(c), services)
}

func getCarrierService(c *gin.Context) {
	_, exists := c.Get("user")
	if !exists {
		errors.ReturnWithError(c, carrier.ErrUnauthorized)
		return
	}

	serviceId := c.Param("name")
	if serviceId == "" {
		errors.ReturnWithError(c, carrier.ErrBadRequest)
		return
	}

	// check if service exists in map
	service, exists := entities.CarrierServices[serviceId]
	if !exists {
		errors.ReturnWithError(c, carrier.ErrCarrierServiceNotFound)
		return
	}

	serialize.JSON[entities.CarrierService](c, (&serialize.CarrierServiceSerializer{}).ParseFlags(c), service)
}

// HEAD /carrier -> checks if edited since given timestamp
func checkIfEditedSince(c *gin.Context) {
	current := c.MustGet("user").(*entities.User)

	// get timestamp from query param
	timestamp := c.Query("timestamp")
	if timestamp == "" {
		errors.ReturnWithError(c, carrier.ErrBadRequest)
		return
	}

	// parse timestamp
	timestampParsed, err := time.Parse(time.RFC3339, timestamp)
	if err != nil {
		// check if parsing timestamp to int64 works
		timestampInt, err := strconv.ParseInt(timestamp, 10, 64)
		if err != nil {
			c.Error(err)
			errors.ReturnWithError(c, carrier.ErrBadRequest)
			return
		}

		timestampParsed = time.Unix(timestampInt, 0)
	}

	// check for :id in param
	carrierIdStr := c.Param("id")
	if carrierIdStr == "" {
		errors.ReturnWithError(c, carrier.ErrBadRequest)
		return
	}

	// parse carrier id
	carrierId, err := uuid.Parse(carrierIdStr)
	if err != nil {
		c.Error(err)
		errors.ReturnWithError(c, carrier.ErrBadRequest)
		return
	}

	// get carrier
	cr := entities.Carrier{}
	if res := db.DB.Where("id = ?", carrierId).First(&cr); res.Error != nil {
		if !current.IsAdmin {
			errors.ReturnWithError(c, carrier.ErrForbidden)
			return
		}
		errors.ReturnWithError(c, carrier.ErrCarrierNotFound)
		return
	}

	// check if carrier was edited since timestamp
	if cr.UpdatedAt.After(timestampParsed) {
		c.JSON(200, gin.H{"edited": true})
		return
	}

	c.JSON(304, gin.H{"edited": false})
}
