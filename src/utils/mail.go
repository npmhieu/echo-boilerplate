package utils

import (
	"gopkg.in/gomail.v2"
)

func sendEmail(fromEmail, toEmail, subject, body string) error {
	// Thiết lập thông tin email
	m := gomail.NewMessage()
	m.SetHeader("From", fromEmail)  // Email gửi
	m.SetHeader("To", toEmail)      // Email nhận
	m.SetHeader("Subject", subject) // Tiêu đề email
	m.SetBody("text/plain", body)   // Nội dung email (text/plain)

	// Thiết lập server SMTP (điều chỉnh email và mật khẩu)
	d := gomail.NewDialer("smtp.gmail.com", 587, "youremail@example.com", "yourpassword")

	// Gửi email
	if err := d.DialAndSend(m); err != nil {
		return err
	}
	return nil
}
