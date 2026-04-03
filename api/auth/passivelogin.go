package auth

import (
	"ruehrstaat-backend/api/dtoerr"
	"ruehrstaat-backend/auth"
	"ruehrstaat-backend/db"
	"ruehrstaat-backend/db/entities"
	"ruehrstaat-backend/errors"

	"github.com/gin-gonic/gin"
)

func requestPassiveLoginToken(c *gin.Context) {
	token, sessionId, err := auth.RequestPassiveLoginToken(c.Request.Context(), c.ClientIP())
	if err != nil {
		c.Error(err.Error())
		if err == auth.ErrPassiveLoginRequestRateLimited {
			errors.ReturnWithError(c, err)
			return
		}
		errors.ReturnWithError(c, auth.ErrPassiveLoginTokenRequestFailed)
		return
	}

	c.JSON(200, gin.H{"token": token, "sessionId": sessionId})
}

type VerifyPassiveLoginTokenDTO struct {
	Token string `json:"token"`
}

func verifyPassiveLoginToken(c *gin.Context) {
	user, err := auth.RequireSessionBoundAuth(c)
	if err != nil {
		errors.ReturnWithError(c, err)
		return
	}

	verifyDTO := VerifyPassiveLoginTokenDTO{}
	if err := c.ShouldBindJSON(&verifyDTO); err != nil {
		errors.ReturnWithError(c, dtoerr.InvalidDTO)
		return
	}

	token := verifyDTO.Token

	err = auth.VerifyPassiveLoginToken(c.Request.Context(), token, user)
	if err != nil {
		c.Error(err.Error())
		if err == auth.ErrPassiveLoginRateLimited || err == auth.ErrInvalidToken {
			errors.ReturnWithError(c, err)
			return
		}
		errors.ReturnWithError(c, auth.ErrPassiveLoginTokenValidationFailed)
		return
	}

	c.JSON(200, gin.H{"message": "Token verified"})
}

type CompletePassiveLoginDTO struct {
	Token     string `json:"token"`
	SessionID string `json:"sessionId"`
}

func completePassiveLogin(c *gin.Context) {
	if err := auth.ValidateSessionEstablishingRequest(c.Request); err != nil {
		errors.ReturnWithError(c, err)
		return
	}

	dto := CompletePassiveLoginDTO{}
	if err := c.ShouldBindJSON(&dto); err != nil {
		errors.ReturnWithError(c, dtoerr.InvalidDTO)
		return
	}

	token := dto.Token
	sessionID := dto.SessionID

	userId, err := auth.CompletePassiveLogin(token, sessionID)
	if err != nil {
		c.Error(err.Error())
		if err == auth.ErrPassiveLoginTokenNotYetVerified {
			errors.ReturnWithError(c, err)
			return
		}
		errors.ReturnWithError(c, auth.ErrPassiveLoginCompletionFailed)
		return
	}

	var user entities.User
	if res := db.DB.Where("id = ?", userId).First(&user); res.Error != nil {
		c.Error(res.Error)
		errors.ReturnWithError(c, auth.ErrPassiveLoginCompletionFailed)
		return
	}

	if err := auth.CheckUserLoginAllowance(&user); err != nil {
		c.Error(err.Error())
		if err == auth.ErrUserBanned {
			errors.ReturnWithError(c, auth.ErrUserBanned)
		} else if err == auth.ErrUserNotActivated {
			errors.ReturnWithError(c, auth.ErrUserNotActivated)
		} else {
			errors.ReturnWithError(c, auth.ErrPassiveLoginCompletionFailed)
		}
		return
	}

	jwttoken, err := auth.CreateTokenPairForUser(c, &user)
	if err != nil {
		c.Error(err.Error())
		errors.ReturnWithError(c, auth.ErrPassiveLoginCompletionFailed)
		return
	}

	writeSessionTokenResponse(c, jwttoken)
}
