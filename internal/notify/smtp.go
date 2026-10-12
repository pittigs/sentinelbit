package notify

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/smtp"
	"os"
	"time"
)

type Mailer struct {
	Host     string
	Port     string
	Username string
	Password string
	From     string
}

func NewMailerFromEnv() *Mailer {
	host := os.Getenv("SENTINELBIT_SMTP_HOST")
	port := os.Getenv("SENTINELBIT_SMTP_PORT")
	if port == "" {
		port = "587"
	}
	user := os.Getenv("SENTINELBIT_SMTP_USER")
	pass := os.Getenv("SENTINELBIT_SMTP_PASS")
	from := os.Getenv("SENTINELBIT_SMTP_FROM")
	if from == "" {
		from = "no-reply@sentinelbit.local"
	}

	if host == "" {
		return nil
	}

	return &Mailer{
		Host:     host,
		Port:     port,
		Username: user,
		Password: pass,
		From:     from,
	}
}

// SendAlert sends an email alert asynchronously
func (m *Mailer) SendAlert(toEmail, subject, bodyText string) error {
	if m == nil || m.Host == "" {
		return nil
	}

	msg := fmt.Sprintf("From: SentinelBit <%s>\r\n"+
		"To: %s\r\n"+
		"Subject: [SentinelBit] %s\r\n"+
		"MIME-Version: 1.0\r\n"+
		"Content-Type: text/plain; charset=UTF-8\r\n"+
		"Date: %s\r\n\r\n"+
		"%s\r\n", m.From, toEmail, subject, time.Now().Format(time.RFC1123Z), bodyText)

	addr := net.JoinHostPort(m.Host, m.Port)
	var auth smtp.Auth
	if m.Username != "" {
		auth = smtp.PlainAuth("", m.Username, m.Password, m.Host)
	}

	// Support implicit TLS (port 465) or STARTTLS (port 587/25)
	if m.Port == "465" {
		tlsConfig := &tls.Config{
			ServerName: m.Host,
		}
		conn, err := tls.Dial("tcp", addr, tlsConfig)
		if err != nil {
			return err
		}
		c, err := smtp.NewClient(conn, m.Host)
		if err != nil {
			return err
		}
		defer c.Quit()

		if auth != nil {
			if err = c.Auth(auth); err != nil {
				return err
			}
		}
		if err = c.Mail(m.From); err != nil {
			return err
		}
		if err = c.Rcpt(toEmail); err != nil {
			return err
		}
		w, err := c.Data()
		if err != nil {
			return err
		}
		_, err = w.Write([]byte(msg))
		if err != nil {
			return err
		}
		return w.Close()
	}

	return smtp.SendMail(addr, auth, m.From, []string{toEmail}, []byte(msg))
}
