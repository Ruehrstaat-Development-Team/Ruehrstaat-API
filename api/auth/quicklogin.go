package auth

import (
	"ruehrstaat-backend/api/dtoerr"
	"ruehrstaat-backend/auth"
	"ruehrstaat-backend/db"
	"ruehrstaat-backend/db/entities"
	"ruehrstaat-backend/errors"

	"github.com/gin-gonic/gin"
)

func requestQuickLoginToken(c *gin.Context) {
	token, sessionId, err := auth.RequestQuickLoginToken(c.Request.Context(), c.ClientIP())
	if err != nil {
		c.Error(err.Error())
		if err == auth.ErrQuickloginRequestRateLimited {
			errors.ReturnWithError(c, err)
			return
		}
		errors.ReturnWithError(c, auth.ErrQuickloginTokenRequestFailed)
		return
	}

	c.JSON(200, gin.H{"token": token, "sessionId": sessionId})
}

type verifyQuickLoginTokenDTO struct {
	Token string `json:"token"`
}

func verifyQuickLoginToken(c *gin.Context) {
	user, err := auth.RequireSessionBoundAuth(c)
	if err != nil {
		errors.ReturnWithError(c, err)
		return
	}

	verifyDTO := verifyQuickLoginTokenDTO{}
	if err := c.ShouldBindJSON(&verifyDTO); err != nil {
		errors.ReturnWithError(c, dtoerr.InvalidDTO)
		return
	}

	token := verifyDTO.Token

	err = auth.VerifyQuickLoginToken(c.Request.Context(), token, user)
	if err != nil {
		c.Error(err.Error())
		if err == auth.ErrQuickloginRateLimited || err == auth.ErrInvalidToken {
			errors.ReturnWithError(c, err)
			return
		}
		errors.ReturnWithError(c, auth.ErrQuickloginTokenValidationFailed)
		return
	}

	c.JSON(200, gin.H{"message": "Token verified"})
}

type completeQuickLoginDTO struct {
	Token     string `json:"token"`
	SessionID string `json:"sessionId"`
}

func completeQuickLogin(c *gin.Context) {
	if err := auth.ValidateSessionEstablishingRequest(c.Request); err != nil {
		errors.ReturnWithError(c, err)
		return
	}

	dto := completeQuickLoginDTO{}
	if err := c.ShouldBindJSON(&dto); err != nil {
		errors.ReturnWithError(c, dtoerr.InvalidDTO)
		return
	}

	token := dto.Token
	sessionID := dto.SessionID

	userId, err := auth.CompleteQuickLogin(token, sessionID)
	if err != nil {
		c.Error(err.Error())
		errors.ReturnWithError(c, auth.ErrQuickloginCompletionFailed)
		return
	}

	var user entities.User
	if res := db.DB.Where("id = ?", userId).First(&user); res.Error != nil {
		c.Error(res.Error)
		errors.ReturnWithError(c, auth.ErrQuickloginCompletionFailed)
		return
	}

	if err := auth.CheckUserLoginAllowance(&user); err != nil {
		c.Error(err.Error())
		if err == auth.ErrUserBanned {
			errors.ReturnWithError(c, auth.ErrUserBanned)
		} else if err == auth.ErrUserNotActivated {
			errors.ReturnWithError(c, auth.ErrUserNotActivated)
		} else {
			errors.ReturnWithError(c, auth.ErrQuickloginCompletionFailed)
		}
		return
	}

	jwttoken, err := auth.CreateTokenPairForUser(c, &user)
	if err != nil {
		c.Error(err.Error())
		errors.ReturnWithError(c, auth.ErrQuickloginCompletionFailed)
		return
	}

	writeSessionTokenResponse(c, jwttoken)
}
