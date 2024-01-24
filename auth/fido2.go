package auth

import (
	"errors"
	"os"
	"ruehrstaat-backend/cache"
	"ruehrstaat-backend/db"
	"ruehrstaat-backend/db/entities"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
	jsoniter "github.com/json-iterator/go"
)

var authnClient *webauthn.WebAuthn = nil

type registerCachePayload struct {
	User    *entities.Fido2Login  `json:"user"`
	Session *webauthn.SessionData `json:"session"`
}

func InitializeWebauthn() {
	conf := &webauthn.Config{
		RPDisplayName: "MTN-Media",
		RPID:          os.Getenv("FQDN"),
		RPOrigins:     []string{os.Getenv("FRONTEND_URL")},
	}

	if conf, err := webauthn.New(conf); err != nil {
		panic(err)
	} else {
		authnClient = conf
	}
}

func BeginFido2Register(user *entities.User, displayName string) (string, *protocol.CredentialCreation, error) {
	fidoLogin := &entities.Fido2Login{
		UserID:      user.ID,
		DisplayName: displayName,
		Name:        displayName,
		Data:        "",
	}

	options, session, err := authnClient.BeginRegistration(fidoLogin, webauthn.WithResidentKeyRequirement(protocol.ResidentKeyRequirementRequired))
	if err != nil {
		return "", nil, err
	}

	payload := &registerCachePayload{
		User:    fidoLogin,
		Session: session,
	}

	state := cache.BeginState("fido2_register", payload, time.Minute*5)
	return state, options, nil
}

func FinishFido2Register(state string, user *entities.User, pcc *protocol.ParsedCredentialCreationData) error {
	payload := &registerCachePayload{}
	if !cache.EndState("fido2_register", state, payload) {
		return errors.New("invalid state")
	}

	credential, err := authnClient.CreateCredential(payload.User, *payload.Session, pcc)
	if err != nil {
		return err
	}

	fidoLogin := payload.User
	fidoLogin.Data, err = jsoniter.MarshalToString(credential)

	if err != nil {
		return err
	}

	if res := db.DB.Model(fidoLogin).Save(fidoLogin); res.Error != nil {
		return res.Error
	}

	return nil
}

func DeleteFido2Login(user *entities.User, userID uuid.UUID, displayName string) error {
	if res := db.DB.Where("user_id = ? AND display_name = ?", userID, displayName).Delete(&entities.Fido2Login{}); res.Error != nil {
		return res.Error
	}

	return nil
}

func BeginFido2Login() (string, *protocol.CredentialAssertion, error) {
	options, sessions, err := authnClient.BeginDiscoverableLogin()
	if err != nil {
		return "", nil, err
	}

	state := cache.BeginState("fido2_login", sessions, time.Minute*5)
	return state, options, nil
}

func FinishFido2Login(state string, pcc *protocol.ParsedCredentialAssertionData) (*entities.User, error) {
	session := &webauthn.SessionData{}
	if !cache.EndState("fido2_login", state, session) {
		return nil, errors.New("invalid state")
	}

	if session.UserID != nil {
		return nil, errors.New("invalid session")
	}

	if pcc.Response.UserHandle == nil {
		return nil, errors.New("invalid user handle")
	}

	login, err := discoverLogin(pcc.Response.UserHandle)
	if err != nil {
		return nil, err
	}

	session.UserID = login.WebAuthnID()

	if _, err = authnClient.ValidateLogin(login, *session, pcc); err != nil {
		return nil, err
	}

	user := &entities.User{}
	if res := db.DB.Where("id = ?", login.UserID).First(user); res.Error != nil {
		return nil, res.Error
	}

	return user, nil
}

func discoverLogin(userHandle []byte) (*entities.Fido2Login, error) {
	userHandleStr := string(userHandle)
	parts := strings.Split(userHandleStr, ":")

	userID := uuid.MustParse(parts[0])
	displayName := parts[1]

	var user entities.Fido2Login
	if res := db.DB.Where("user_id = ? AND display_name = ?", userID, displayName).First(&user); res.Error != nil {
		return nil, res.Error
	}

	return &user, nil
}
