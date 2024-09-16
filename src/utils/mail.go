package utils

import (
    "fmt"
    "os"
    "gopkg.in/gomail.v2"
)

var smtpDialer *gomail.Dialer

func InitSmtpDialer() {
    mail := os.Getenv("EMAIL")
    passMail := os.Getenv("PASS_APP_MAIL")

    if mail == "" || passMail == "" {
        fmt.Println("Missing email or password for SMTP")
        return
    }

    smtpDialer = gomail.NewDialer("smtp.gmail.com", 587, mail, passMail)
}


func SendEmail(toEmail, subject, body string) error {
    if smtpDialer == nil {
        return fmt.Errorf("SMTP dialer is not initialized")
    }

    m := gomail.NewMessage()
    m.SetHeader("From", os.Getenv("EMAIL"))
    m.SetHeader("To", toEmail)
    m.SetHeader("Subject", subject)
    m.SetBody("text/plain", body)

    if err := smtpDialer.DialAndSend(m); err != nil {
        return err
    }
    return nil
}

func SendEmailAsync(toEmail, subject, body string) {
    go func() {
        if err := SendEmail(toEmail, subject, body)
		err != nil {
            fmt.Printf("Error sending email: %v\n", err)
        }
    }()
}
