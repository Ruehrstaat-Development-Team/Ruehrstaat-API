package mailer

import (
	"crypto/tls"
	"net/mail"
	"net/smtp"
	"os"

	"ruehrstaat-backend/logging"
	"ruehrstaat-backend/mailer/mails"
	"ruehrstaat-backend/util"
)

var log = logging.Logger{Package: "mailer"}

func SendMail(receiver string, mail mails.Mail, locale string) {
	err := sendMail(receiver, mail, locale)

	if err != nil {
		log.Println("Failed to send:", err)
		panic(err)
	}
}

func SendMailGraceful(receiver string, mail mails.Mail, locale string) error {
	err := sendMail(receiver, mail, locale)

	if err != nil {
		return ErrFailedToSendEmail
	}
	return nil
}

func SendBulkMail(receivers []string, mail mails.Mail, locale string) {
	errors := make([]error, 0)

	for _, receiver := range receivers {
		err := sendMail(receiver, mail, locale)

		if err != nil {
			errors = append(errors, err)
		}
	}

	if len(errors) > 0 {
		panic(errors)
	}
}

func sendMail(toAddr string, mailTemplate mails.Mail, locale string) error {
	if os.Getenv("SMTP_DISABLED") == "true" {
		return nil
	}

	from, err := mail.ParseAddress(os.Getenv("SMTP_FROM"))

	if err != nil {
		log.Println("Failed to parse from address")
		return err
	}

	to := mail.Address{Address: toAddr, Name: ""}

	fromLine := "From: " + from.String() + "\n"
	toLine := "To: " + to.String() + "\n"
	subject := "Subject: " + mailTemplate.GetSubject(locale) + "!\n"
	mime := "MIME-version: 1.0;\nContent-Type: text/html; charset=\"UTF-8\";\n\n"
	body := buildTemplate(mailTemplate.GetName(), mailTemplate.GetBody(locale), locale)
	msg := []byte(fromLine + toLine + subject + mime + body)

	host := os.Getenv("SMTP_HOST")
	port := os.Getenv("SMTP_PORT")

	measure := util.MeasureTime("SEND_MAIL")

	auth := smtp.PlainAuth("", os.Getenv("SMTP_USER"), os.Getenv("SMTP_PASS"), host)

	tlsconfig := &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         host,
	}

	measure.BeginBreakpoint("Dial")
	client, err := smtp.Dial(host + ":" + port)
	if err != nil {
		return err
	}
	measure.EndBreakpoint("Dial")

	measure.BeginBreakpoint("StartTLS")
	client.StartTLS(tlsconfig)
	measure.EndBreakpoint("StartTLS")

	measure.BeginBreakpoint("Sending")
	if err = client.Auth(auth); err != nil {
		return err
	}
	if err = client.Mail(from.Address); err != nil {
		return err
	}

	if err = client.Rcpt(to.Address); err != nil {
		return err
	}

	w, err := client.Data()

	if err != nil {
		return err
	}

	_, err = w.Write(msg)

	if err != nil {
		return err
	}

	err = w.Close()

	if err != nil {
		return err
	}

	err = client.Quit()

	if err != nil {
		return err
	}

	measure.EndBreakpoint("Sending")
	measure.End()

	return nil
}
