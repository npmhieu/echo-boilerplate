package utils

import (
    "fmt"
    "os"

    "github.com/sendgrid/sendgrid-go"
    "github.com/sendgrid/sendgrid-go/helpers/mail"
)

var sendgridAPIKey string

// InitSendGrid initializes the SendGrid API key
func InitSendMail() {
    sendgridAPIKey = os.Getenv("SENDGRID_KEY")
    if sendgridAPIKey == "" {
        fmt.Println("Missing SendGrid API key")
    }
}

func SendEmail(toEmail, subject, body string) error {
    if sendgridAPIKey == "" {
        return fmt.Errorf("SendGrid API key is not initialized")
    }

    from := mail.NewEmail(os.Getenv("FROM_NAME_MAIL"), os.Getenv("EMAIL"))
    to := mail.NewEmail("Recipient", toEmail)
    message := mail.NewSingleEmail(from, subject, to, body, body)

    client := sendgrid.NewSendClient(sendgridAPIKey)
    response, err := client.Send(message)
    if err != nil {
        return err
    }

    if response.StatusCode >= 400 {
        return fmt.Errorf("Failed to send email: %v", response.Body)
    }

    return nil
}

// SendEmailAsync sends an email asynchronously using SendGrid
func SendEmailAsync(toEmail, subject, body string) {
    go func() {
        if err := SendEmail(toEmail, subject, body); err != nil {
            fmt.Printf("Error sending email: %v\n", err)
        }
    }()
}
