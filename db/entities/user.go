package entities

import (
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
	jsoniter "github.com/json-iterator/go"
	"github.com/lib/pq"
	"gorm.io/gorm"
)

type User struct {
	gorm.Model
	// Basic user information
	ID       uuid.UUID `gorm:"type:uuid;default:uuid_generate_v4();primaryKey"`
	Email    string    `gorm:"type:varchar(255);unique;not null;index"`
	Nickname string    `gorm:"type:varchar(255);not null"`
	CmdrName string    `gorm:"type:varchar(255);not null"`
	Password string    `gorm:"type:varchar(255);not null"`
	IsAdmin  bool      `gorm:"type:boolean;default:false;index"`

	Locale string `gorm:"type:varchar(2);default:en"`

	// user banned
	IsBanned bool `gorm:"type:boolean;default:false"`

	// activation
	IsActivated        bool    `gorm:"type:boolean;default:false"`
	ActivationToken    *string `gorm:"type:text"`
	PasswordResetToken *string `gorm:"type:text"`

	//email change
	EmailChangeToken *string `gorm:"type:text"`
	NewEmail         *string `gorm:"type:varchar(255)"`

	// 2FA
	OtpActive      bool           `gorm:"type:boolean;default:false"`
	OtpVerified    bool           `gorm:"type:boolean;default:false"`
	OtpSecret      *string        `gorm:"type:varchar(255)"`
	OtpBackupCodes pq.StringArray `gorm:"type:text[];not null;default:ARRAY[]::text[]"`
	DiscordId      *string        `gorm:"type:text;index;unique"`
	DiscordName    *string        `gorm:"type:text"`
	RefreshTokens  []RefreshToken
	Fido2Login     []Fido2Login
}

// Whether the user has two factor authentication enabled and verified.
func (u *User) HasTwoFactor() bool {
	return u.OtpActive && u.OtpVerified
}

type RefreshToken struct {
	ID        uuid.UUID `gorm:"type:uuid;default:uuid_generate_v4();primaryKey"`
	UserID    uuid.UUID `gorm:"type:uuid;not null;constraint:OnUpdate:CASCADE,OnDelete:CASCADE;index"`
	Token     string    `gorm:"type:text;not null;index"`
	IsRevoked bool      `gorm:"type:boolean;default:false"`
}

type Fido2Login struct {
	UserID      uuid.UUID `gorm:"type:uuid;not null;constraint:OnUpdate:CASCADE,OnDelete:CASCADE;primaryKey" json:"user_id"`
	DisplayName string    `gorm:"type:varchar(255);not null;unique;primaryKey" json:"display_name"`
	Name        string    `gorm:"type:varchar(255);not null" json:"name"`
	Data        string    `gorm:"type:text;not null" json:"data"`
}

func (u *Fido2Login) WebAuthnID() []byte {
	return []byte(u.UserID.String() + ":" + u.DisplayName)
}

func (u *Fido2Login) WebAuthnName() string {
	return u.DisplayName
}

func (u *Fido2Login) WebAuthnDisplayName() string {
	return u.Name
}

func (u *Fido2Login) WebAuthnCredentials() []webauthn.Credential {
	cred := &webauthn.Credential{}

	err := jsoniter.UnmarshalFromString(u.Data, cred)
	if err != nil {
		panic(err)
	}

	return []webauthn.Credential{*cred}
}

func (u *Fido2Login) WebAuthnIcon() string {
	return ""
}
