package mails

import (
	"os"

	"github.com/google/uuid"
)

type ChangeEmailMail struct {
	UserID   uuid.UUID
	Email    string
	Nickname string
	Token    string
}

func (m ChangeEmailMail) GetSubject(locale string) string {
	switch locale {
	case "de":
		return "Bestätige deine Ruehrstaat-Account E-Mail Änderung"
	default:
		return "Confirm your Ruehrstaat account email change"
	}
}

func (m ChangeEmailMail) GetBody(locale string) string {
	link := os.Getenv("FRONTEND_URL") + "/changeMail/" + m.UserID.String() + "?ect=" + m.Token
	switch locale {
	case "de":
		return "Um deine E-Mail Änderung zu besstätigen, klicke bitte auf den folgenden Button: \n<a href=\"" + link + "\">Jetzt bestätigen!</a>\n\nFalls dieser nicht geht, versuche diesen Link:\n<a href=\"" + link + "\">" + link + "</a>\nWichtig: Dieser Link läuft nach 72 Stunden ab!"
	default:
		return "To confirm your email change, please click the following button: \n<a href=\"" + link + "\">Confirm now!</a>\n\nIf this does not work, try this link:\n<a href=\"" + link + "\">" + link + "</a>\nImportant: This link expires after 72 hours!"
	}
}

func (m ChangeEmailMail) GetName() string {
	return m.Nickname
}
