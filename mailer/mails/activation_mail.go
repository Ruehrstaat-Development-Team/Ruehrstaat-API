package mails

import (
	"os"

	"github.com/google/uuid"
)

type ActivationMail struct {
	UserID   uuid.UUID
	Email    string
	Nickanme string
	Token    string
}

func (m ActivationMail) GetSubject(locale string) string {
	switch locale {
	case "de":
		return "Aktiviere deinen Ruehrstaat-Account"
	default:
		return "Activate your Ruehrstaat account"
	}
}

func (m ActivationMail) GetBody(locale string) string {
	link := os.Getenv("FRONTEND_URL") + "/activate/" + m.UserID.String() + "?activation=" + m.Token
	switch locale {
	case "de":
		return "Um deinen Account zu aktivieren, klicke bitte auf den folgenden Button: \n<a href=\"" + link + "\">Jetzt aktivieren!</a>\n\nFalls dieser nicht geht, versuche diesen Link:\n<a href=\"" + link + "\">" + link + "</a>\nWichtig: Dieser Link läuft nach 72 Stunden ab! Falls du einen neuen brauchst, versuche dich einmal auf unserer Seite einzuloggen. Der Login wird zwar fehlschlagen, aber du kannst dann dort direkt einen neuen Aktivierungslink anfordern."
	default:
		return "To activate your account, please click the following button: \n<a href=\"" + link + "\">Activate now!</a>\n\nIf this does not work, try this link:\n<a href=\"" + link + "\">" + link + "</a>\nImportant: This link expires after 72 hours! If you need a new one, try to login on our site. The login will fail, but you can request a new activation link there."
	}
}

func (m ActivationMail) GetName() string {
	return m.Nickanme
}
