package utils

import (
	"os"
	"fmt"
	"gopkg.in/gomail.v2"
)



func SendEmail(toEmail, subject, body string) error {
	var mail = os.Getenv("EMAIL")
	var passMail = os.Getenv("PASS_APP_MAIL")

	m := gomail.NewMessage()
	m.SetHeader("From", mail)  
	m.SetHeader("To", toEmail)      
	m.SetHeader("Subject", subject) 
	m.SetBody("text/plain", body)   

	fmt.Println(mail)
	fmt.Println(passMail)

	d := gomail.NewDialer("smtp.gmail.com", 587, mail, passMail)

	// Gửi email
	if err := d.DialAndSend(m); err != nil {
		return err
	}
	return nil
}
