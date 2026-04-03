package auth

import (
	"context"
	"net/url"
	"strings"

	"ruehrstaat-backend/db"
	"ruehrstaat-backend/db/entities"
	"ruehrstaat-backend/errors"
	"ruehrstaat-backend/logging"
	"ruehrstaat-backend/mailer"
	"ruehrstaat-backend/mailer/mails"
	"ruehrstaat-backend/services/locale"
	"ruehrstaat-backend/services/user_service"
	"ruehrstaat-backend/util"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/lindell/go-burner-email-providers/burner"
	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

const (
	activationLinkRefCategory    = "activation_link_ref"
	passwordResetLinkRefCategory = "password_reset_link_ref"
	emailChangeLinkRefCategory   = "email_change_link_ref"
)

func ResolveActivationTokenReference(value string) string {
	return resolveFrontendTokenReference(activationLinkRefCategory, value)
}

func DeleteActivationTokenReference(value string) {
	deleteFrontendTokenReference(activationLinkRefCategory, value)
}

func ResolvePasswordResetTokenReference(value string) string {
	return resolveFrontendTokenReference(passwordResetLinkRefCategory, value)
}

func DeletePasswordResetTokenReference(value string) {
	deleteFrontendTokenReference(passwordResetLinkRefCategory, value)
}

func ResolveEmailChangeTokenReference(value string) string {
	return resolveFrontendTokenReference(emailChangeLinkRefCategory, value)
}

func DeleteEmailChangeTokenReference(value string) {
	deleteFrontendTokenReference(emailChangeLinkRefCategory, value)
}

func buildChangeEmailConfirmationMail(user *entities.User, newEmail string, ref string) (string, mails.ChangeEmailMail) {
	return newEmail, mails.ChangeEmailMail{UserID: user.ID, Email: newEmail, Nickname: user.Nickname, Ref: ref}
}

func mailLocaleForUser(user *entities.User) string {
	if user != nil && locale.DoesLocaleExist(user.Locale) {
		return user.Locale
	}
	return "en"
}

func NormalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

func ValidateUserEmailAddress(email string) *errors.RstError {
	email = NormalizeEmail(email)
	if !util.IsEmailValid(email) || burner.IsBurnerEmail(email) {
		return ErrInvalidEmail
	}

	return nil
}

func normalizedEmailWhereClause() string {
	return "LOWER(REGEXP_REPLACE(email, '^[[:space:]]+|[[:space:]]+$', '', 'g')) = ?"
}

func normalizedEmailWhereClauseExcludingID() string {
	return normalizedEmailWhereClause() + " AND id <> ?"
}

func NormalizedEmailWhereClauseExcludingID() string {
	return normalizedEmailWhereClauseExcludingID()
}

func acquireNormalizedEmailLock(tx *gorm.DB, email string) error {
	if tx == nil || tx.Dialector.Name() != "postgres" {
		return nil
	}
	normalized := NormalizeEmail(email)
	if normalized == "" {
		return nil
	}
	return tx.Exec("SELECT pg_advisory_xact_lock(hashtext(?))", "email_ci:"+normalized).Error
}

func AcquireNormalizedEmailLock(tx *gorm.DB, email string) error {
	return acquireNormalizedEmailLock(tx, email)
}

func FindUniqueUserByEmail(ctx context.Context, email string, out *entities.User) *errors.RstError {
	email = NormalizeEmail(email)
	var users []entities.User
	if err := db.DB.WithContext(ctx).Where(normalizedEmailWhereClause(), email).Limit(2).Find(&users).Error; err != nil {
		return errors.NewDBErrorFromError(err)
	}
	if len(users) == 0 {
		return ErrUserNotFound
	}
	if len(users) > 1 {
		return ErrEmailAmbiguous
	}
	if out != nil {
		*out = users[0]
	}
	return nil
}

func hasOtherUserWithNormalizedEmail(ctx context.Context, tx *gorm.DB, email string, excludedID uuid.UUID) (bool, error) {
	email = NormalizeEmail(email)
	if email == "" {
		return false, nil
	}

	existing := &entities.User{}
	if err := tx.WithContext(ctx).Where(normalizedEmailWhereClauseExcludingID(), email, excludedID).Limit(1).Find(existing).Error; err != nil {
		return false, err
	}

	return existing.ID != uuid.Nil, nil
}

func isDuplicateEmailError(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "duplicate key") && strings.Contains(msg, "email")
}

func Register(c *gin.Context, email string, password string, nickname string, cmdrName string, asAdmin bool) *errors.RstError {
	email = NormalizeEmail(email)
	if err := checkRegistrationRateLimit(c.Request.Context(), email); err != nil {
		logging.LogSecurityEvent(logging.SecurityEvent{EventType: logging.EventRegistrationRateLimit, Email: email, IPAddress: c.ClientIP(), Success: false, ErrorReason: "rate_limited"})
		return err
	}

	var user *entities.User
	activationToken := ""
	txErr := db.DB.WithContext(c.Request.Context()).Transaction(func(tx *gorm.DB) error {
		if err := ValidateUserEmailAddress(email); err != nil {
			return err.Error()
		}
		if err := acquireNormalizedEmailLock(tx, email); err != nil {
			return err
		}

		existing := &entities.User{}
		if res := tx.WithContext(c.Request.Context()).Where(normalizedEmailWhereClause(), email).Limit(1).Find(existing); res.Error != nil {
			if res.Error != gorm.ErrRecordNotFound {
				return res.Error
			}
		}
		if existing.ID != uuid.Nil {
			return ErrEmailTaken.Error()
		}

		if err := validatePasswordStrength(password); err != nil {
			return err.Error()
		}

		hashed, err := bcrypt.GenerateFromPassword([]byte(password), BcryptCost)
		if err != nil {
			return err
		}

		user = &entities.User{ID: uuid.New(), Email: email, Password: string(hashed), Nickname: nickname, CmdrName: cmdrName, IsAdmin: asAdmin, IsActivated: asAdmin}
		if !asAdmin {
			var genErr *errors.RstError
			activationToken, genErr = generateCustomToken(user.ID.String(), "Ruehrstaat-Squadron Account Activation", 72)
			if genErr != nil {
				return genErr.Error()
			}
			hashedToken := util.HashToken(activationToken)
			user.ActivationToken = &hashedToken
		}

		if res := tx.WithContext(c.Request.Context()).Create(user); res.Error != nil {
			if isDuplicateEmailError(res.Error) {
				return ErrEmailTaken.Error()
			}
			return res.Error
		}

		if !asAdmin {
			if activationToken == "" {
				var genErr *errors.RstError
				activationToken, genErr = generateCustomToken(user.ID.String(), "Ruehrstaat-Squadron Account Activation", 72)
				if genErr != nil {
					return genErr.Error()
				}
				hashedToken := util.HashToken(activationToken)
				user.ActivationToken = &hashedToken
				if err := tx.WithContext(c.Request.Context()).Model(user).Update("activation_token", hashedToken).Error; err != nil {
					return err
				}
			}
		}

		return nil
	})
	if txErr != nil {
		incrementRegistrationFailedAttempt(c.Request.Context(), email)
		switch txErr.Error() {
		case ErrInvalidEmail.String():
			logging.LogRegistrationFailed(email, c.ClientIP(), "invalid_email")
			return ErrInvalidEmail
		case ErrEmailTaken.String():
			logging.LogRegistrationFailed(email, c.ClientIP(), "email_taken")
			return ErrEmailTaken
		case ErrPasswordTooWeak.String():
			logging.LogRegistrationFailed(email, c.ClientIP(), "weak_password")
			return ErrPasswordTooWeak
		default:
			logging.LogRegistrationFailed(email, c.ClientIP(), "db_or_tx_failure")
			return errors.NewDBErrorFromError(txErr)
		}
	}

	resetRegistrationFailedAttempts(c.Request.Context(), email)
	if user != nil {
		logging.LogRegistrationSuccess(user.ID, email, c.ClientIP())
	}

	if !asAdmin && user != nil {
		if err := sendActivationMail(user, activationToken); err != nil {
			return suppressCommittedMailFailure(c, err)
		}
	}

	return nil
}

func suppressCommittedMailFailure(c *gin.Context, err *errors.RstError) *errors.RstError {
	if err == nil {
		return nil
	}
	if err != mailer.ErrFailedToSendEmail {
		return err
	}
	c.Error(err.Error())
	return nil
}

func sendActivationMail(user *entities.User, token string) *errors.RstError {
	ref := createFrontendTokenReference(activationLinkRefCategory, token)
	return mailer.SendMailGraceful(user.Email, mails.ActivationMail{UserID: user.ID, Email: user.Email, Ref: ref}, mailLocaleForUser(user))
}

func GenerateActivationToken(c *gin.Context, user *entities.User) *errors.RstError {
	token, err := generateCustomToken(user.ID.String(), "Ruehrstaat-Squadron Account Activation", 72)
	if err != nil {
		return err
	}

	hashed := util.HashToken(token)
	if err := user_service.WithLockedUser(c.Request.Context(), db.DB, user.ID, func(tx *gorm.DB, lockedUser *entities.User) error {
		lockedUser.ActivationToken = &hashed
		return user_service.SaveUserColumns(c.Request.Context(), tx, lockedUser, "ActivationToken")
	}); err != nil {
		return errors.NewDBErrorFromError(err)
	}

	return suppressCommittedMailFailure(c, sendActivationMail(user, token))
}

func ActivateAccount(c *gin.Context, userID uuid.UUID, token string) *errors.RstError {
	unescaped, qerr := url.QueryUnescape(token)
	if qerr != nil {
		return errors.NewFromError(qerr)
	}

	decoded, err := decodeToken(getIdentityTokenSecret(), unescaped, "Ruehrstaat-Squadron Account Activation")
	if err != nil || decoded.Subject != userID {
		return ErrInvalidActivationToken
	}

	var userEmail string
	if err := user_service.WithLockedUser(c.Request.Context(), db.DB, userID, func(tx *gorm.DB, lockedUser *entities.User) error {
		userEmail = lockedUser.Email
		if lockedUser.ActivationToken == nil {
			return ErrUserAlreadyActivated.Error()
		}
		if util.HashToken(token) != *lockedUser.ActivationToken {
			logging.LogSecurityEvent(logging.SecurityEvent{EventType: logging.EventAccountActivationFail, UserID: &lockedUser.ID, Email: lockedUser.Email, IPAddress: c.ClientIP(), Success: false, ErrorReason: "invalid_token"})
			return ErrInvalidActivationToken.Error()
		}
		lockedUser.IsActivated = true
		lockedUser.ActivationToken = nil
		return user_service.SaveUserColumns(c.Request.Context(), tx, lockedUser, "IsActivated", "ActivationToken")
	}); err != nil {
		if err == gorm.ErrRecordNotFound {
			return ErrUserNotFound
		}
		switch err.Error() {
		case ErrUserAlreadyActivated.String():
			return ErrUserAlreadyActivated
		case ErrInvalidActivationToken.String():
			return ErrInvalidActivationToken
		default:
			return errors.NewDBErrorFromError(err)
		}
	}

	logging.LogAccountActivated(userID, userEmail, c.ClientIP())
	return nil
}

func GenerateResetPasswordToken(c *gin.Context, user *entities.User) *errors.RstError {
	token, err := generateCustomToken(user.ID.String(), "Ruehrstaat-Squadron Account Passwort Reset", 1)
	if err != nil {
		logging.LogSecurityEvent(logging.SecurityEvent{EventType: logging.EventPasswordResetFailed, UserID: &user.ID, Email: user.Email, IPAddress: c.ClientIP(), Success: false, ErrorReason: "token_generation_failed"})
		return err
	}

	hashed := util.HashToken(token)
	if err := user_service.WithLockedUser(c.Request.Context(), db.DB, user.ID, func(tx *gorm.DB, lockedUser *entities.User) error {
		lockedUser.PasswordResetToken = &hashed
		return user_service.SaveUserColumns(c.Request.Context(), tx, lockedUser, "PasswordResetToken")
	}); err != nil {
		logging.LogSecurityEvent(logging.SecurityEvent{EventType: logging.EventPasswordResetFailed, UserID: &user.ID, Email: user.Email, IPAddress: c.ClientIP(), Success: false, ErrorReason: "db_update_failed"})
		return errors.NewDBErrorFromError(err)
	}

	logging.LogSecurityEvent(logging.SecurityEvent{EventType: logging.EventPasswordResetRequest, UserID: &user.ID, Email: user.Email, IPAddress: c.ClientIP(), Success: true})
	ref := createFrontendTokenReference(passwordResetLinkRefCategory, token)
	if err := mailer.SendMailGraceful(user.Email, mails.PasswordResetMail{UserID: user.ID, Totp: user.HasTwoFactor(), Nickname: user.Nickname, Ref: ref}, mailLocaleForUser(user)); err != nil {
		logging.LogSecurityEvent(logging.SecurityEvent{EventType: logging.EventPasswordResetFailed, UserID: &user.ID, Email: user.Email, IPAddress: c.ClientIP(), Success: false, ErrorReason: "mail_send_failed"})
		return suppressCommittedMailFailure(c, err)
	}
	return nil
}

func ResetPassword(c *gin.Context, userID uuid.UUID, token string, password string, otp *string) *errors.RstError {
	unescaped, qerr := url.QueryUnescape(token)
	if qerr != nil {
		return errors.NewFromError(qerr)
	}

	decoded, err := decodeToken(getIdentityTokenSecret(), unescaped, "Ruehrstaat-Squadron Account Passwort Reset")
	if err != nil || decoded.Subject != userID {
		return ErrInvalidResetToken
	}

	if err := validatePasswordStrength(password); err != nil {
		return err
	}

	hashed, berr := bcrypt.GenerateFromPassword([]byte(password), BcryptCost)
	if berr != nil {
		return errors.NewFromError(berr)
	}

	var userEmail string
	otpChecked := false
	if err := user_service.WithLockedUser(c.Request.Context(), db.DB, userID, func(tx *gorm.DB, lockedUser *entities.User) error {
		userEmail = lockedUser.Email
		if lockedUser.PasswordResetToken == nil {
			return ErrResetNotRequested.Error()
		}
		if util.HashToken(token) != *lockedUser.PasswordResetToken {
			return ErrInvalidResetToken.Error()
		}

		columns := []string{"Password", "PasswordResetToken"}
		if lockedUser.HasTwoFactor() {
			otpChecked = true
			if err := checkOtpRateLimit(c.Request.Context(), lockedUser.ID.String()); err != nil {
				return err.Error()
			}
			if otp == nil {
				return ErrUserOtpMissing.Error()
			}

			plainSecret := ""
			if lockedUser.OtpSecret != nil {
				if dec, err := OtpDecryptString(*lockedUser.OtpSecret); err == nil {
					plainSecret = dec
				}
			}
			if !totp.Validate(*otp, plainSecret) {
				if !consumeBackupCodeFromUser(lockedUser, *otp) {
					return ErrUserOtpWrong.Error()
				}
				columns = append(columns, "OtpBackupCodes")
			}
		}

		lockedUser.Password = string(hashed)
		lockedUser.PasswordResetToken = nil
		if err := user_service.SaveUserColumns(c.Request.Context(), tx, lockedUser, columns...); err != nil {
			return err
		}

		if err := RevokeAllSessionsForUserTx(c.Request.Context(), tx, lockedUser.ID); err != nil {
			return err
		}

		return RevokeApiTokensForUser(c.Request.Context(), tx, lockedUser.ID)
	}); err != nil {
		if err == gorm.ErrRecordNotFound {
			return ErrUserNotFound
		}
		switch err.Error() {
		case ErrResetNotRequested.String():
			logging.LogSecurityEvent(logging.SecurityEvent{EventType: logging.EventPasswordResetFailed, UserID: &userID, Email: userEmail, IPAddress: c.ClientIP(), Success: false, ErrorReason: "reset_not_requested"})
			return ErrResetNotRequested
		case ErrInvalidResetToken.String():
			logging.LogSecurityEvent(logging.SecurityEvent{EventType: logging.EventPasswordResetFailed, UserID: &userID, Email: userEmail, IPAddress: c.ClientIP(), Success: false, ErrorReason: "invalid_token"})
			return ErrInvalidResetToken
		case ErrUserOtpMissing.String():
			logging.LogSecurityEvent(logging.SecurityEvent{EventType: logging.EventPasswordResetFailed, UserID: &userID, Email: userEmail, IPAddress: c.ClientIP(), Success: false, ErrorReason: "otp_missing"})
			return ErrUserOtpMissing
		case ErrUserOtpWrong.String():
			incrementOtpFailedAttempt(c.Request.Context(), userID.String())
			logging.LogSecurityEvent(logging.SecurityEvent{EventType: logging.EventPasswordResetFailed, UserID: &userID, Email: userEmail, IPAddress: c.ClientIP(), Success: false, ErrorReason: "invalid_otp"})
			logging.Log2FAFailed(userID, userEmail, c.ClientIP(), "invalid_otp")
			return ErrUserOtpWrong
		case ErrUserOtpRateLimited.String():
			logging.LogSecurityEvent(logging.SecurityEvent{EventType: logging.EventPasswordResetFailed, UserID: &userID, Email: userEmail, IPAddress: c.ClientIP(), Success: false, ErrorReason: "otp_rate_limited"})
			return ErrUserOtpRateLimited
		default:
			return errors.NewDBErrorFromError(err)
		}
	}

	if otpChecked {
		resetOtpFailedAttempts(c.Request.Context(), userID.String())
	}
	logging.LogPasswordReset(userID, userEmail, c.ClientIP())
	return nil
}

func ChangePassword(c *gin.Context, user *entities.User, oldPassword string, newPassword string, otp *string) *errors.RstError {
	if err := validatePasswordStrength(newPassword); err != nil {
		logging.LogSecurityEvent(logging.SecurityEvent{EventType: logging.EventPasswordChangeFailed, UserID: &user.ID, Email: user.Email, IPAddress: c.ClientIP(), Success: false, ErrorReason: "weak_password"})
		return err
	}

	hashed, err := bcrypt.GenerateFromPassword([]byte(newPassword), BcryptCost)
	if err != nil {
		return errors.NewFromError(err)
	}

	otpChecked := false
	if err := user_service.WithLockedUser(c.Request.Context(), db.DB, user.ID, func(tx *gorm.DB, lockedUser *entities.User) error {
		if err := bcrypt.CompareHashAndPassword([]byte(lockedUser.Password), []byte(oldPassword)); err != nil {
			return ErrInvalidCredentials.Error()
		}

		columns := []string{"Password"}
		if lockedUser.HasTwoFactor() {
			otpChecked = true
			if err := checkOtpRateLimit(c.Request.Context(), lockedUser.ID.String()); err != nil {
				return err.Error()
			}
			if otp == nil {
				return ErrUserOtpMissing.Error()
			}

			plainSecret := ""
			if lockedUser.OtpSecret != nil {
				if dec, err := OtpDecryptString(*lockedUser.OtpSecret); err == nil {
					plainSecret = dec
				}
			}
			if !totp.Validate(*otp, plainSecret) {
				if !consumeBackupCodeFromUser(lockedUser, *otp) {
					return ErrUserOtpWrong.Error()
				}
				columns = append(columns, "OtpBackupCodes")
			}
		}

		lockedUser.Password = string(hashed)
		if err := user_service.SaveUserColumns(c.Request.Context(), tx, lockedUser, columns...); err != nil {
			return err
		}

		if err := RevokeAllSessionsForUserTx(c.Request.Context(), tx, lockedUser.ID); err != nil {
			return err
		}

		return RevokeApiTokensForUser(c.Request.Context(), tx, lockedUser.ID)
	}); err != nil {
		switch err.Error() {
		case ErrInvalidCredentials.String():
			logging.LogSecurityEvent(logging.SecurityEvent{EventType: logging.EventPasswordChangeFailed, UserID: &user.ID, Email: user.Email, IPAddress: c.ClientIP(), Success: false, ErrorReason: "invalid_credentials"})
			return ErrInvalidCredentials
		case ErrUserOtpMissing.String():
			logging.LogSecurityEvent(logging.SecurityEvent{EventType: logging.EventPasswordChangeFailed, UserID: &user.ID, Email: user.Email, IPAddress: c.ClientIP(), Success: false, ErrorReason: "otp_missing"})
			return ErrUserOtpMissing
		case ErrUserOtpWrong.String():
			incrementOtpFailedAttempt(c.Request.Context(), user.ID.String())
			logging.LogSecurityEvent(logging.SecurityEvent{EventType: logging.EventPasswordChangeFailed, UserID: &user.ID, Email: user.Email, IPAddress: c.ClientIP(), Success: false, ErrorReason: "invalid_otp"})
			logging.Log2FAFailed(user.ID, user.Email, c.ClientIP(), "invalid_otp")
			return ErrUserOtpWrong
		case ErrUserOtpRateLimited.String():
			logging.LogSecurityEvent(logging.SecurityEvent{EventType: logging.EventPasswordChangeFailed, UserID: &user.ID, Email: user.Email, IPAddress: c.ClientIP(), Success: false, ErrorReason: "otp_rate_limited"})
			return ErrUserOtpRateLimited
		default:
			return errors.NewDBErrorFromError(err)
		}
	}

	if otpChecked {
		resetOtpFailedAttempts(c.Request.Context(), user.ID.String())
	}
	logging.LogPasswordChanged(user.ID, user.Email, c.ClientIP())
	return nil
}

func GenerateEmailChangeToken(c *gin.Context, user *entities.User) *errors.RstError {
	token, err := generateCustomToken(user.ID.String(), "Ruehrstaat-Squadron email change", 72)
	if err != nil {
		return err
	}

	hashed := util.HashToken(token)
	if err := user_service.WithLockedUser(c.Request.Context(), db.DB, user.ID, func(tx *gorm.DB, lockedUser *entities.User) error {
		lockedUser.EmailChangeToken = &hashed
		return user_service.SaveUserColumns(c.Request.Context(), tx, lockedUser, "EmailChangeToken")
	}); err != nil {
		return errors.NewDBErrorFromError(err)
	}

	ref := createFrontendTokenReference(emailChangeLinkRefCategory, token)
	return mailer.SendMailGraceful(user.Email, mails.ChangeEmailMail{UserID: user.ID, Email: user.Email, Nickname: user.Nickname, Ref: ref}, mailLocaleForUser(user))
}

func InitiateEmailChange(c *gin.Context, user *entities.User, newEmail string, password string, otp *string) *errors.RstError {
	newEmail = NormalizeEmail(newEmail)
	if err := ValidateUserEmailAddress(newEmail); err != nil {
		return err
	}

	token, err := generateCustomToken(user.ID.String(), "Ruehrstaat-Squadron email change", 72)
	if err != nil {
		return err
	}
	hashed := util.HashToken(token)
	var previousBackupCodes []string
	backupCodesChanged := false
	otpChecked := false

	err2 := user_service.WithLockedUser(c.Request.Context(), db.DB, user.ID, func(tx *gorm.DB, lockedUser *entities.User) error {
		if err := acquireNormalizedEmailLock(tx, newEmail); err != nil {
			return err
		}
		previousBackupCodes = append([]string{}, lockedUser.OtpBackupCodes...)

		var existing entities.User
		if err := tx.Where(normalizedEmailWhereClauseExcludingID(), newEmail, lockedUser.ID).First(&existing).Error; err == nil {
			return ErrEmailTaken.Error()
		} else if err != nil && err != gorm.ErrRecordNotFound {
			return err
		}

		if err := bcrypt.CompareHashAndPassword([]byte(lockedUser.Password), []byte(password)); err != nil {
			return ErrInvalidCredentials.Error()
		}

		columns := []string{"NewEmail", "EmailChangeToken"}
		if lockedUser.HasTwoFactor() {
			otpChecked = true
			if err := checkOtpRateLimit(c.Request.Context(), lockedUser.ID.String()); err != nil {
				return err.Error()
			}
			if otp == nil {
				return ErrUserOtpMissing.Error()
			}

			plainSecret := ""
			if lockedUser.OtpSecret != nil {
				if dec, err := OtpDecryptString(*lockedUser.OtpSecret); err == nil {
					plainSecret = dec
				}
			}
			if !totp.Validate(*otp, plainSecret) {
				if !consumeBackupCodeFromUser(lockedUser, *otp) {
					return ErrUserOtpWrong.Error()
				}
				backupCodesChanged = true
				columns = append(columns, "OtpBackupCodes")
			}
		}

		lockedUser.NewEmail = &newEmail
		lockedUser.EmailChangeToken = &hashed
		return user_service.SaveUserColumns(c.Request.Context(), tx, lockedUser, columns...)
	})
	if err2 != nil {
		switch err2.Error() {
		case ErrEmailTaken.String():
			return ErrEmailTaken
		case ErrInvalidCredentials.String():
			return ErrInvalidCredentials
		case ErrUserOtpMissing.String():
			return ErrUserOtpMissing
		case ErrUserOtpWrong.String():
			incrementOtpFailedAttempt(c.Request.Context(), user.ID.String())
			logging.LogSecurityEvent(logging.SecurityEvent{EventType: logging.EventEmailChangeFailed, UserID: &user.ID, Email: user.Email, IPAddress: c.ClientIP(), Success: false, ErrorReason: "invalid_otp"})
			return ErrUserOtpWrong
		case ErrUserOtpRateLimited.String():
			logging.LogSecurityEvent(logging.SecurityEvent{EventType: logging.EventEmailChangeFailed, UserID: &user.ID, Email: user.Email, IPAddress: c.ClientIP(), Success: false, ErrorReason: "otp_rate_limited"})
			return ErrUserOtpRateLimited
		default:
			return errors.NewDBErrorFromError(err2)
		}
	}

	if otpChecked {
		resetOtpFailedAttempts(c.Request.Context(), user.ID.String())
	}

	ref := createFrontendTokenReference(emailChangeLinkRefCategory, token)
	receiver, mail := buildChangeEmailConfirmationMail(user, newEmail, ref)
	err = mailer.SendMailGraceful(receiver, mail, mailLocaleForUser(user))
	if err != nil {
		_ = user_service.WithLockedUser(c.Request.Context(), db.DB, user.ID, func(tx *gorm.DB, lockedUser *entities.User) error {
			lockedUser.EmailChangeToken = nil
			lockedUser.NewEmail = nil
			columns := []string{"EmailChangeToken", "NewEmail"}
			if backupCodesChanged {
				lockedUser.OtpBackupCodes = previousBackupCodes
				columns = append(columns, "OtpBackupCodes")
			}
			return user_service.SaveUserColumns(c.Request.Context(), tx, lockedUser, columns...)
		})
		return err
	}

	logging.LogSecurityEvent(logging.SecurityEvent{EventType: logging.EventEmailChangeRequest, UserID: &user.ID, Email: user.Email, IPAddress: c.ClientIP(), Success: true, Details: map[string]any{"new_email": newEmail}})
	return nil
}

func ChangeEmail(c *gin.Context, user *entities.User, token string) *errors.RstError {
	unescaped, qerr := url.QueryUnescape(token)
	if qerr != nil {
		return errors.NewFromError(qerr)
	}

	decoded, err := decodeToken(getIdentityTokenSecret(), unescaped, "Ruehrstaat-Squadron email change")
	if err != nil || decoded.Subject != user.ID {
		return ErrInvalidEmailChangeToken
	}

	err2 := user_service.WithLockedUser(c.Request.Context(), db.DB, user.ID, func(tx *gorm.DB, lockedUser *entities.User) error {
		if lockedUser.EmailChangeToken == nil || lockedUser.NewEmail == nil {
			return ErrEmailChangeNotRequested.Error()
		}
		if err := acquireNormalizedEmailLock(tx, *lockedUser.NewEmail); err != nil {
			return err
		}
		if util.HashToken(token) != *lockedUser.EmailChangeToken {
			return ErrInvalidEmailChangeToken.Error()
		}

		taken, err := hasOtherUserWithNormalizedEmail(c.Request.Context(), tx, *lockedUser.NewEmail, lockedUser.ID)
		if err != nil {
			return err
		}
		if taken {
			return ErrEmailTaken.Error()
		}

		lockedUser.Email = *lockedUser.NewEmail
		lockedUser.NewEmail = nil
		lockedUser.EmailChangeToken = nil
		if err := user_service.SaveUserColumns(c.Request.Context(), tx, lockedUser, "Email", "NewEmail", "EmailChangeToken"); err != nil {
			if isDuplicateEmailError(err) {
				return ErrEmailTaken.Error()
			}
			return err
		}

		user.Email = lockedUser.Email
		user.NewEmail = nil
		user.EmailChangeToken = nil
		return nil
	})
	if err2 != nil {
		switch err2.Error() {
		case ErrEmailChangeNotRequested.String():
			return ErrEmailChangeNotRequested
		case ErrInvalidEmailChangeToken.String():
			logging.LogSecurityEvent(logging.SecurityEvent{EventType: logging.EventEmailChangeFailed, UserID: &user.ID, Email: user.Email, IPAddress: c.ClientIP(), Success: false, ErrorReason: "invalid_token"})
			return ErrInvalidEmailChangeToken
		case ErrEmailTaken.String():
			return ErrEmailTaken
		default:
			return errors.NewDBErrorFromError(err2)
		}
	}

	logging.LogSecurityEvent(logging.SecurityEvent{EventType: logging.EventEmailChanged, UserID: &user.ID, Email: user.Email, IPAddress: c.ClientIP(), Success: true})
	return nil
}
