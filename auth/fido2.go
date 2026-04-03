package auth

import (
	goerrors "errors"
	"os"
	"ruehrstaat-backend/cache"
	"ruehrstaat-backend/db"
	"ruehrstaat-backend/db/entities"
	"ruehrstaat-backend/errors"
	"ruehrstaat-backend/logging"
	"ruehrstaat-backend/util"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
	jsoniter "github.com/json-iterator/go"
	"gorm.io/gorm"
)

func isDuplicateFidoDisplayNameError(err error) bool {
	if err == nil {
		return false
	}

	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "duplicate key") && strings.Contains(msg, "fido2") && strings.Contains(msg, "display_name")
}

var authnClient *webauthn.WebAuthn = nil

type registerCachePayload struct {
	User              *entities.Fido2Login  `json:"user"`
	Session           *webauthn.SessionData `json:"session"`
	InitiatingUserID  uuid.UUID             `json:"initiatingUserId"`
	InitiatingSession uuid.UUID             `json:"initiatingSessionId"`
}

func InitializeWebauthn() {
	conf := &webauthn.Config{
		RPDisplayName: "Ruehrstaat-Squadron",
		RPID:          os.Getenv("FQDN"),
		RPOrigins:     []string{os.Getenv("FRONTEND_URL")},
	}

	if conf, err := webauthn.New(conf); err != nil {
		panic(err)
	} else {
		authnClient = conf
	}
	logging.Logger{Package: "auth-fido2"}.Println("Webauthn service enabled.")
}

func BeginFido2Register(user *entities.User, browserSession *entities.RefreshToken, displayName string) (string, *protocol.CredentialCreation, *errors.RstError) {
	fidoLogin := &entities.Fido2Login{
		UserID:      user.ID,
		DisplayName: displayName,
		Name:        displayName,
		Data:        "",
	}

	options, webauthnSession, err := authnClient.BeginRegistration(fidoLogin, webauthn.WithResidentKeyRequirement(protocol.ResidentKeyRequirementRequired))
	if err != nil {
		return "", nil, errors.NewAuthErrorFromError(err)
	}

	payload := &registerCachePayload{
		User:              fidoLogin,
		Session:           webauthnSession,
		InitiatingUserID:  user.ID,
		InitiatingSession: browserSession.ID,
	}

	state := cache.BeginState("fido2_register", payload, time.Minute*5)
	return state, options, nil
}

func FinishFido2Register(c *gin.Context, state string, user *entities.User, session *entities.RefreshToken, pcc *protocol.ParsedCredentialCreationData) *errors.RstError {
	payload := &registerCachePayload{}
	if !cache.EndState("fido2_register", state, payload) {
		return ErrInvalidState
	}
	if payload.InitiatingUserID != user.ID || payload.InitiatingSession != session.ID || payload.User == nil || payload.User.UserID != user.ID || payload.Session == nil {
		return ErrInvalidState
	}

	credential, err := authnClient.CreateCredential(payload.User, *payload.Session, pcc)
	if err != nil {
		return ErrInvalidFido2Ceremony
	}

	fidoLogin := payload.User
	plain, err := jsoniter.MarshalToString(credential)
	if err != nil {
		return errors.NewFromError(err)
	}
	enc, encErr := util.FidoEncryptString(plain)
	if encErr != nil {
		return errors.NewFromError(encErr)
	}
	fidoLogin.Data = enc

	var existing entities.Fido2Login
	if res := db.DB.WithContext(c.Request.Context()).Where("user_id = ? AND display_name = ?", fidoLogin.UserID, fidoLogin.DisplayName).First(&existing); res.Error == nil {
		return ErrDuplicateFidoDisplayName
	} else if res.Error != nil && res.Error != gorm.ErrRecordNotFound {
		return errors.NewDBErrorFromError(res.Error)
	}

	if res := db.DB.WithContext(c.Request.Context()).Model(fidoLogin).Save(fidoLogin); res.Error != nil {
		if isDuplicateFidoDisplayNameError(res.Error) {
			return ErrDuplicateFidoDisplayName
		}
		return errors.NewDBErrorFromError(res.Error)
	}
	logging.LogSecurityEvent(logging.SecurityEvent{EventType: logging.EventFido2Registered, UserID: &user.ID, Email: user.Email, IPAddress: c.ClientIP(), Success: true, Details: map[string]any{"display_name": fidoLogin.DisplayName}})

	return nil
}

func DeleteFido2Login(c *gin.Context, user *entities.User, userID uuid.UUID, displayName string) *errors.RstError {
	if res := db.DB.WithContext(c.Request.Context()).Where("user_id = ? AND display_name = ?", userID, displayName).Delete(&entities.Fido2Login{}); res.Error != nil {
		return errors.NewDBErrorFromError(res.Error)
	}
	logging.LogSecurityEvent(logging.SecurityEvent{EventType: logging.EventFido2Removed, UserID: &user.ID, Email: user.Email, IPAddress: c.ClientIP(), Success: true, Details: map[string]any{"display_name": displayName}})

	return nil
}

func BeginFido2Login() (string, *protocol.CredentialAssertion, *errors.RstError) {
	options, sessions, err := authnClient.BeginDiscoverableLogin()
	if err != nil {
		return "", nil, errors.NewAuthErrorFromError(err)
	}

	state := cache.BeginState("fido2_login", sessions, time.Minute*5)
	return state, options, nil
}

func FinishFido2Login(c *gin.Context, state string, pcc *protocol.ParsedCredentialAssertionData) (*entities.User, *errors.RstError) {
	session := &webauthn.SessionData{}
	if !cache.EndState("fido2_login", state, session) {
		return nil, ErrInvalidState
	}

	if session.UserID != nil {
		return nil, ErrInvalidSession
	}

	if pcc.Response.UserHandle == nil {
		return nil, ErrInvalidUserHandle
	}

	login, err := discoverLogin(c, pcc.Response.UserHandle)
	if err != nil {
		return nil, err
	}

	session.UserID = login.WebAuthnID()
	if dec, err := util.FidoDecryptString(login.Data); err == nil {
		login.Data = dec
	} else {
		logging.LogSecurityEvent(logging.SecurityEvent{EventType: logging.EventFido2LoginFailed, UserID: &login.UserID, IPAddress: c.ClientIP(), Success: false, ErrorReason: "credential_decrypt_failed"})
		return nil, ErrInvalidCredentials
	}

	if _, err2 := authnClient.ValidateLogin(login, *session, pcc); err2 != nil {
		if login != nil {
			logging.LogSecurityEvent(logging.SecurityEvent{EventType: logging.EventFido2LoginFailed, UserID: &login.UserID, IPAddress: c.ClientIP(), Success: false, ErrorReason: err2.Error()})
		}
		return nil, ErrInvalidFido2Ceremony
	}

	user := &entities.User{}
	if res := db.DB.WithContext(c.Request.Context()).Where("id = ?", login.UserID).First(user); res.Error != nil {
		return nil, errors.NewDBErrorFromError(res.Error)
	}

	return user, nil
}

func parseFido2UserHandle(userHandle []byte) (uuid.UUID, string, *errors.RstError) {
	parts := strings.SplitN(string(userHandle), ":", 2)
	if len(parts) != 2 {
		return uuid.Nil, "", ErrInvalidUserHandle
	}

	userID, err := uuid.Parse(parts[0])
	if err != nil {
		return uuid.Nil, "", ErrInvalidUserHandle
	}
	if parts[1] == "" {
		return uuid.Nil, "", ErrInvalidUserHandle
	}

	return userID, parts[1], nil
}

func discoverLogin(c *gin.Context, userHandle []byte) (*entities.Fido2Login, *errors.RstError) {
	userID, displayName, err := parseFido2UserHandle(userHandle)
	if err != nil {
		return nil, err
	}

	var user entities.Fido2Login
	if res := db.DB.WithContext(c.Request.Context()).Where("user_id = ? AND display_name = ?", userID, displayName).First(&user); res.Error != nil {
		if goerrors.Is(res.Error, gorm.ErrRecordNotFound) {
			return nil, ErrInvalidUserHandle
		}
		return nil, errors.NewDBErrorFromError(res.Error)
	}

	return &user, nil
}
