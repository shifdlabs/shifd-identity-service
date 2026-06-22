package service

import (
	"context"
	"fmt"

	"github.com/ShifdLabs/shifd-identity-service/config"
	"github.com/resend/resend-go/v2"
)

// EmailService sends transactional emails via Resend.
type EmailService struct {
	client     *resend.Client
	fromEmail  string
	fromName   string
	appBaseURL string
}

func NewEmailService(cfg *config.Config) *EmailService {
	return &EmailService{
		client:     resend.NewClient(cfg.ResendAPIKey),
		fromEmail:  cfg.ResendFromEmail,
		fromName:   cfg.ResendFromName,
		appBaseURL: cfg.AppBaseURL,
	}
}

func (s *EmailService) from() string {
	return fmt.Sprintf("%s <%s>", s.fromName, s.fromEmail)
}

// SendPasswordReset emails toEmail a link to reset their password using resetToken.
func (s *EmailService) SendPasswordReset(ctx context.Context, toEmail string, toName string, resetToken string) error {
	resetLink := fmt.Sprintf("%s/reset-password?token=%s", s.appBaseURL, resetToken)

	html := fmt.Sprintf(
		`<p>Hi %s,</p><p>We received a request to reset your Shifd Labs password. Click the link below to choose a new one:</p><p><a href="%s">Reset your password</a></p><p>This link expires in 1 hour. If you didn't request this, you can safely ignore this email.</p>`,
		toName, resetLink,
	)

	_, err := s.client.Emails.SendWithContext(ctx, &resend.SendEmailRequest{
		From:    s.from(),
		To:      []string{toEmail},
		Subject: "Reset your Shifd Labs password",
		Html:    html,
	})
	if err != nil {
		return fmt.Errorf("email: failed to send password reset email to %s: %w", toEmail, err)
	}
	return nil
}

// SendOrgInvite emails toEmail an invitation to join orgName, sent by inviterName.
func (s *EmailService) SendOrgInvite(ctx context.Context, toEmail string, orgName string, inviterName string, inviteToken string) error {
	inviteLink := fmt.Sprintf("%s/accept-invite?token=%s", s.appBaseURL, inviteToken)

	html := fmt.Sprintf(
		`<p>Hi,</p><p>%s has invited you to join <strong>%s</strong> on Shifd Labs. Click the link below to accept the invitation:</p><p><a href="%s">Accept invitation</a></p><p>This link expires in 48 hours.</p>`,
		inviterName, orgName, inviteLink,
	)

	_, err := s.client.Emails.SendWithContext(ctx, &resend.SendEmailRequest{
		From:    s.from(),
		To:      []string{toEmail},
		Subject: fmt.Sprintf("%s invited you to join %s on Shifd Labs", inviterName, orgName),
		Html:    html,
	})
	if err != nil {
		return fmt.Errorf("email: failed to send org invite email to %s: %w", toEmail, err)
	}
	return nil
}
