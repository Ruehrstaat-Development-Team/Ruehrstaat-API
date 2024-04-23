package auth

import (
	"ruehrstaat-backend/db"
	"ruehrstaat-backend/db/entities"
	"ruehrstaat-backend/errors"

	"github.com/gin-gonic/gin"
	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

func CheckUserLoginAllowance(user *entities.User) *errors.RstError {
	if !user.IsActivated {
		return ErrUserNotActivated
	}

	if user.IsBanned {
		return ErrUserBanned
	}

	return nil
}

// Tries to login a user with the given email and password.
// Returns a token pair if successful, otherwise an error.
func Login(email string, password string, otp *string) (*TokenPair, *entities.User, *errors.RstError) {
	user := &entities.User{}

	if res := db.DB.Where("email = ?", email).First(user); res.Error != nil {
		return nil, nil, ErrUserNotFound
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password)); err != nil {
		return nil, nil, ErrInvalidCredentials
	}

	if err := CheckUserLoginAllowance(user); err != nil {
		return nil, user, err
	}

	if user.HasTwoFactor() {
		// check if otp is given and valid (6 - 8 characters)
		if otp == nil || len(*otp) < 6 || len(*otp) > 8 {
			return nil, user, ErrUserOtpMissing
		}

		if !totp.Validate(*otp, *user.OtpSecret) {
			if err := TryBackupCodes(user, otp); err != nil {
				return nil, user, err
			}
		}
	}

	if res := db.DB.Model(&entities.RefreshToken{}).Where("user_id = ?", user.ID).Update("is_revoked", true); res.Error != nil {
		return nil, user, errors.NewDBErrorFromError(res.Error)
	}

	tokenPair, err := generatePair(user.ID, nil)
	if err != nil {
		return nil, user, err
	}

	return &tokenPair, user, nil
}

func CreateTokenPairForUser(user *entities.User) (*TokenPair, *errors.RstError) {
	tokenPair, err := generatePair(user.ID, nil)
	if err != nil {
		return nil, err
	}

	refreshToken := &entities.RefreshToken{
		UserID: user.ID,
		Token:  tokenPair.RefreshToken,
	}

	if res := db.DB.Create(refreshToken); res.Error != nil {
		return nil, errors.NewDBErrorFromError(res.Error)
	}

	return &tokenPair, nil
}

// Tries to use a backup code to do a two factor authentication.
func TryBackupCodes(user *entities.User, otp *string) *errors.RstError {
	if user.OtpBackupCodes == nil || len(user.OtpBackupCodes) == 0 {
		return ErrUserOtpWrong
	}

	found := false
	for i, code := range user.OtpBackupCodes {
		if code == *otp {
			found = true
			user.OtpBackupCodes = append(user.OtpBackupCodes[:i], user.OtpBackupCodes[i+1:]...)
			break
		}
	}

	if !found {
		return ErrUserOtpWrong
	}

	if res := db.DB.Save(user); res.Error != nil {
		return errors.NewDBErrorFromError(res.Error)
	}

	return nil
}

// Logs out the user with the given refresh token.
// If all is true, all refresh tokens for the user will be deleted.
func Logout(refreshToken string, all bool) *errors.RstError {
	decoded, err := decodeToken(getRefreshTokenSecret(), refreshToken)
	if err != nil {
		return err
	}

	if all {
		if res := db.DB.Where("user_id = ?", decoded.Subject).Delete(&entities.RefreshToken{}); res.Error != nil {
			return errors.NewDBErrorFromError(res.Error)
		}
	} else {
		if res := db.DB.Where("token = ? OR (user_id = ? AND is_revoked = ?)", refreshToken, decoded.Subject, true).Delete(&entities.RefreshToken{}); res.Error != nil {
			return errors.NewDBErrorFromError(res.Error)
		}
	}

	return nil
}

// Refreshes the access token with the given refresh token. If the refresh token is invalid, an error is returned.
// The refresh token will be rotated, so that the old one is no longer valid.
func Refresh(refreshToken string) (*TokenPair, *errors.RstError) {
	decoded, err := decodeToken(getRefreshTokenSecret(), refreshToken)
	if err != nil {
		return nil, ErrUsedRefreshToken
	}

	existing := &entities.RefreshToken{}
	if res := db.DB.Where("token = ? AND user_id = ?", refreshToken, decoded.Subject).First(existing); res.Error != nil {
		if res.Error != gorm.ErrRecordNotFound {
			return nil, errors.NewDBErrorFromError(res.Error)
		}
	} else if existing.IsRevoked {
		Logout(refreshToken, true)
		return nil, ErrUsedRefreshToken
	}

	tokenPair, err := generatePair(decoded.Subject, nil)
	if err != nil {
		return nil, err
	}

	if res := db.DB.Model(&entities.RefreshToken{}).Where("user_id = ? AND token = ?", decoded.Subject, refreshToken).Update("is_revoked", true); res.Error != nil {
		return nil, errors.NewDBErrorFromError(res.Error)
	}

	refreshTokenEntity := &entities.RefreshToken{
		UserID: decoded.Subject,
		Token:  tokenPair.RefreshToken,
	}

	if res := db.DB.Create(refreshTokenEntity); res.Error != nil {
		return nil, errors.NewDBErrorFromError(res.Error)
	}

	return &tokenPair, nil
}

// Extracts the user from the given context by extracting the token from the Authorization header.
func Extract(ctx *gin.Context) *entities.User {
	idenityToken := ctx.GetHeader("Authorization")
	if idenityToken == "" {
		return nil
	}

	idenityToken = idenityToken[7:]
	decoded, err := decodeToken(getIdentityTokenSecret(), idenityToken)
	if err != nil {
		return nil
	}

	user := &entities.User{}
	if res := db.DB.Where("id = ?", decoded.Subject).First(user); res.Error != nil {
		return nil
	}

	return user
}
