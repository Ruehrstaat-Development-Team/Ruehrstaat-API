package auth

import (
	"net/url"
	"ruehrstaat-backend/db"
	"ruehrstaat-backend/db/entities"
	"ruehrstaat-backend/mailer"
	"ruehrstaat-backend/mailer/mails"
	"ruehrstaat-backend/util"

	"github.com/google/uuid"
	"github.com/lindell/go-burner-email-providers/burner"
	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

// Creates a new user with the given email and password.
// If the email is already taken, an error is returned.
// The password will be hashed before storing it in the database.
func Register(email string, password string, nickname string, cmdrName string, asAdmin bool) error {
	if !util.IsEmailValid(email) || burner.IsBurnerEmail(email) {
		return ErrInvalidEmail
	}

	existing := &entities.User{}

	if res := db.DB.Where("email = ?", email).Limit(1).Find(existing); res.Error != nil {
		if res.Error != gorm.ErrRecordNotFound {
			return res.Error
		}
	}

	if existing.Email == email {
		return ErrEmailTaken
	}

	hashed, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	user := &entities.User{
		Email:       email,
		Password:    string(hashed),
		Nickname:    nickname,
		CmdrName:    cmdrName,
		IsAdmin:     asAdmin,
		IsActivated: asAdmin,
	}

	if res := db.DB.Create(user); res.Error != nil {
		return res.Error
	}

	if !asAdmin {
		if err := GenerateActivationToken(user); err != nil {
			return err
		}
	}

	return nil
}

// Generates a new 3-day expiration activation token for the given user.
// The activation token is used to activate the user's account.
// It is sent to the user's email address.
func GenerateActivationToken(user *entities.User) error {
	token, err := generateCustomToken(user.ID.String(), "MTN Media Account Activation", 72)
	if err != nil {
		return err
	}

	user.ActivationToken = &token

	if res := db.DB.Save(user); res.Error != nil {
		return res.Error
	}

	mailer.SendMail(user.Email, mails.ActivationMail{
		UserID: user.ID,
		Email:  user.Email,
		Token:  url.QueryEscape(token),
	}, "en")

	return nil
}

// Activates the account with the given user ID and token.
// If the token is invalid, an error is returned.
func ActivateAccount(userID uuid.UUID, token string) error {
	unescaped, err := url.QueryUnescape(token)
	if err != nil {
		return err
	}

	decoded, err := decodeToken(getIdentityTokenSecret(), unescaped)
	if err != nil {
		return ErrInvalidActivationToken
	}

	if decoded.Subject != userID {
		return ErrInvalidActivationToken
	}

	user := &entities.User{}

	if res := db.DB.Where("id = ?", userID).First(user); res.Error != nil {
		return ErrUserNotFound
	}

	if user.ActivationToken == nil {
		return ErrUserAlreadyActivated
	}

	if *user.ActivationToken != token {
		return ErrInvalidActivationToken
	}

	user.IsActivated = true
	user.ActivationToken = nil

	if res := db.DB.Save(user); res.Error != nil {
		return res.Error
	}

	return nil
}

func GenerateResetPasswordToken(user *entities.User) error {
	token, err := generateCustomToken(user.ID.String(), "MTN-Media Account Passwort Reset", 1)
	if err != nil {
		return err
	}

	user.PasswordResetToken = &token

	if res := db.DB.Save(user); res.Error != nil {
		return res.Error
	}

	mailer.SendMail(user.Email, mails.PasswordResetMail{
		UserID:   user.ID,
		Totp:     user.HasTwoFactor(),
		Nickname: user.Nickname,
		Token:    url.QueryEscape(token),
	}, "en")
	return nil
}

func ResetPassword(userID uuid.UUID, token string, password string, otp *string) error {
	unescaped, err := url.QueryUnescape(token)
	if err != nil {
		return err
	}

	decoded, err := decodeToken(getIdentityTokenSecret(), unescaped)
	if err != nil {
		println("Error decoding token:")
		println(err.Error())
		return ErrInvalidResetToken
	}

	if decoded.Subject != userID {
		println("Invalid subject")
		return ErrInvalidResetToken
	}

	user := &entities.User{}

	if res := db.DB.Where("id = ?", userID).First(user); res.Error != nil {
		return ErrUserNotFound
	}

	if user.PasswordResetToken == nil {
		return ErrResetNotRequested
	}

	if *user.PasswordResetToken != token {
		println("Invalid token")
		return ErrInvalidResetToken
	}

	if user.HasTwoFactor() {
		if otp == nil {
			return ErrUserOtpMissing
		}

		if !totp.Validate(*otp, *user.OtpSecret) {
			if err := TryBackupCodes(user, otp); err != nil {
				return err
			}
		}
	}

	hashed, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	user.Password = string(hashed)
	user.PasswordResetToken = nil

	if res := db.DB.Save(user); res.Error != nil {
		return res.Error
	}

	return nil
}

func ChangePassword(user *entities.User, oldPassword string, newPassword string, otp *string) error {
	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(oldPassword)); err != nil {
		return ErrInvalidCredentials
	}

	if user.HasTwoFactor() {
		if otp == nil {
			return ErrUserOtpMissing
		}

		if !totp.Validate(*otp, *user.OtpSecret) {
			if err := TryBackupCodes(user, otp); err != nil {
				return err
			}
		}
	}

	hashed, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	user.Password = string(hashed)

	if res := db.DB.Save(user); res.Error != nil {
		return res.Error
	}

	return nil
}

// Generates a new 3-day expiration activation token for the given user.
// The activation token is used to activate the user's account.
// It is sent to the user's email address.
func GenerateEmailChangeToken(user *entities.User) error {
	token, err := generateCustomToken(user.ID.String(), "MTN Media email change", 72)
	if err != nil {
		return err
	}

	user.EmailChangeToken = &token

	if res := db.DB.Save(user); res.Error != nil {
		return res.Error
	}

	err = mailer.SendMailGraceful(user.Email, mails.ChangeEmailMail{
		UserID:   user.ID,
		Email:    user.Email,
		Nickname: user.Nickname,
		Token:    url.QueryEscape(token),
	}, "en")
	if err != nil {
		return err
	}

	return nil
}

func InitiateEmailChange(user *entities.User, newEmail string, password string, otp *string) error {
	if !util.IsEmailValid(newEmail) || burner.IsBurnerEmail(newEmail) {
		return ErrInvalidEmail
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password)); err != nil {
		return ErrInvalidCredentials
	}

	if user.HasTwoFactor() {
		if otp == nil {
			return ErrUserOtpMissing
		}

		if !totp.Validate(*otp, *user.OtpSecret) {
			if err := TryBackupCodes(user, otp); err != nil {
				return err
			}
		}
	}

	user.NewEmail = &newEmail

	err := GenerateEmailChangeToken(user)
	if err != nil {
		return err
	}

	return nil
}

func ChangeEmail(user *entities.User, token string) error {
	unescaped, err := url.QueryUnescape(token)
	if err != nil {
		return err
	}

	decoded, err := decodeToken(getIdentityTokenSecret(), unescaped)
	if err != nil {
		return ErrInvalidEmailChangeToken
	}

	if decoded.Subject != user.ID {
		return ErrInvalidEmailChangeToken
	}

	if user.EmailChangeToken == nil {
		return ErrEmailChangeNotRequested
	}

	if *user.EmailChangeToken != token {
		return ErrInvalidEmailChangeToken
	}

	user.Email = *user.NewEmail
	user.NewEmail = nil
	user.EmailChangeToken = nil

	if res := db.DB.Save(user); res.Error != nil {
		return res.Error
	}

	return nil
}
