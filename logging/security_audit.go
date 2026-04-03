package logging

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sync"
	"time"

	"github.com/google/uuid"
)

type SecurityEventType string

const (
	EventLoginSuccess          SecurityEventType = "LOGIN_SUCCESS"
	EventLoginFailed           SecurityEventType = "LOGIN_FAILED"
	EventLoginRateLimited      SecurityEventType = "LOGIN_RATE_LIMITED"
	EventLogout                SecurityEventType = "LOGOUT"
	EventLogoutAll             SecurityEventType = "LOGOUT_ALL"
	EventSessionRevoked        SecurityEventType = "SESSION_REVOKED"
	EventTokenRefresh          SecurityEventType = "TOKEN_REFRESH"
	EventTokenRefreshFailed    SecurityEventType = "TOKEN_REFRESH_FAILED"
	EventRegistrationSuccess   SecurityEventType = "REGISTRATION_SUCCESS"
	EventRegistrationFailed    SecurityEventType = "REGISTRATION_FAILED"
	EventRegistrationRateLimit SecurityEventType = "REGISTRATION_RATE_LIMITED"
	EventAccountActivated      SecurityEventType = "ACCOUNT_ACTIVATED"
	EventAccountActivationFail SecurityEventType = "ACCOUNT_ACTIVATION_FAILED"
	EventPasswordChanged       SecurityEventType = "PASSWORD_CHANGED"
	EventPasswordChangeFailed  SecurityEventType = "PASSWORD_CHANGE_FAILED"
	EventPasswordReset         SecurityEventType = "PASSWORD_RESET"
	EventPasswordResetRequest  SecurityEventType = "PASSWORD_RESET_REQUEST"
	EventPasswordResetFailed   SecurityEventType = "PASSWORD_RESET_FAILED"
	Event2FAEnabled            SecurityEventType = "2FA_ENABLED"
	Event2FADisabled           SecurityEventType = "2FA_DISABLED"
	Event2FAFailed             SecurityEventType = "2FA_FAILED"
	Event2FABackupCodeUsed     SecurityEventType = "2FA_BACKUP_CODE_USED"
	EventEmailChangeRequest    SecurityEventType = "EMAIL_CHANGE_REQUEST"
	EventEmailChanged          SecurityEventType = "EMAIL_CHANGED"
	EventEmailChangeFailed     SecurityEventType = "EMAIL_CHANGE_FAILED"
	EventFido2Registered       SecurityEventType = "FIDO2_REGISTERED"
	EventFido2Removed          SecurityEventType = "FIDO2_REMOVED"
	EventFido2LoginSuccess     SecurityEventType = "FIDO2_LOGIN_SUCCESS"
	EventFido2LoginFailed      SecurityEventType = "FIDO2_LOGIN_FAILED"
	EventDiscordLinked         SecurityEventType = "DISCORD_LINKED"
	EventDiscordLinkFailed     SecurityEventType = "DISCORD_LINK_FAILED"
	EventDiscordUnlinked       SecurityEventType = "DISCORD_UNLINKED"
	EventDiscordUnlinkFailed   SecurityEventType = "DISCORD_UNLINK_FAILED"
)

type SecurityEvent struct {
	Timestamp   time.Time         `json:"timestamp"`
	EventType   SecurityEventType `json:"event_type"`
	UserID      *uuid.UUID        `json:"user_id,omitempty"`
	Email       string            `json:"email,omitempty"`
	IPAddress   string            `json:"ip_address"`
	UserAgent   string            `json:"user_agent,omitempty"`
	Success     bool              `json:"success"`
	Details     map[string]any    `json:"details,omitempty"`
	ErrorReason string            `json:"error_reason,omitempty"`
}

const defaultSecurityLogFile = "security_audit.log"

var (
	securityLogWriter      io.Writer
	securityLogFile        *os.File
	securityLogMutex       sync.Mutex
	securityLogInitialized bool
)

func getSecurityLogPath() string {
	if path := os.Getenv("SECURITY_AUDIT_LOG_PATH"); path != "" {
		return path
	}
	return defaultSecurityLogFile
}

func InitSecurityAuditLog() error {
	securityLogMutex.Lock()
	defer securityLogMutex.Unlock()

	if securityLogInitialized {
		return nil
	}

	path := getSecurityLogPath()
	file, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_RDWR, 0600)
	if err != nil {
		return fmt.Errorf("failed to open security audit log at %s: %w", path, err)
	}

	securityLogFile = file
	securityLogWriter = io.MultiWriter(os.Stdout, securityLogFile)
	securityLogInitialized = true
	return nil
}

func LogSecurityEvent(event SecurityEvent) {
	if !securityLogInitialized {
		if err := InitSecurityAuditLog(); err != nil {
			return
		}
	}

	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now().UTC()
	}

	data, err := json.Marshal(event)
	if err != nil {
		return
	}

	securityLogMutex.Lock()
	defer securityLogMutex.Unlock()
	if securityLogWriter == nil {
		return
	}
	_, _ = securityLogWriter.Write(append(data, '\n'))
}

func LogLoginSuccess(userID uuid.UUID, email, ipAddress, userAgent string) {
	LogSecurityEvent(SecurityEvent{EventType: EventLoginSuccess, UserID: &userID, Email: email, IPAddress: ipAddress, UserAgent: userAgent, Success: true})
}

func LogLoginFailed(email, ipAddress, userAgent, reason string) {
	LogSecurityEvent(SecurityEvent{EventType: EventLoginFailed, Email: email, IPAddress: ipAddress, UserAgent: userAgent, Success: false, ErrorReason: reason})
}

func LogLogout(userID uuid.UUID, ipAddress string, allSessions bool) {
	eventType := EventLogout
	if allSessions {
		eventType = EventLogoutAll
	}
	LogSecurityEvent(SecurityEvent{EventType: eventType, UserID: &userID, IPAddress: ipAddress, Success: true, Details: map[string]any{"all_sessions": allSessions}})
}

func LogPasswordChanged(userID uuid.UUID, email, ipAddress string) {
	LogSecurityEvent(SecurityEvent{EventType: EventPasswordChanged, UserID: &userID, Email: email, IPAddress: ipAddress, Success: true})
}

func LogPasswordReset(userID uuid.UUID, email, ipAddress string) {
	LogSecurityEvent(SecurityEvent{EventType: EventPasswordReset, UserID: &userID, Email: email, IPAddress: ipAddress, Success: true})
}

func LogRegistrationSuccess(userID uuid.UUID, email, ipAddress string) {
	LogSecurityEvent(SecurityEvent{EventType: EventRegistrationSuccess, UserID: &userID, Email: email, IPAddress: ipAddress, Success: true})
}

func LogRegistrationFailed(email, ipAddress, reason string) {
	LogSecurityEvent(SecurityEvent{EventType: EventRegistrationFailed, Email: email, IPAddress: ipAddress, Success: false, ErrorReason: reason})
}

func LogAccountActivated(userID uuid.UUID, email, ipAddress string) {
	LogSecurityEvent(SecurityEvent{EventType: EventAccountActivated, UserID: &userID, Email: email, IPAddress: ipAddress, Success: true})
}

func Log2FAEnabled(userID uuid.UUID, email, ipAddress string) {
	LogSecurityEvent(SecurityEvent{EventType: Event2FAEnabled, UserID: &userID, Email: email, IPAddress: ipAddress, Success: true})
}

func Log2FADisabled(userID uuid.UUID, email, ipAddress string) {
	LogSecurityEvent(SecurityEvent{EventType: Event2FADisabled, UserID: &userID, Email: email, IPAddress: ipAddress, Success: true})
}

func Log2FAFailed(userID uuid.UUID, email, ipAddress, reason string) {
	LogSecurityEvent(SecurityEvent{EventType: Event2FAFailed, UserID: &userID, Email: email, IPAddress: ipAddress, Success: false, ErrorReason: reason})
}

func LogSessionRevoked(userID uuid.UUID, ipAddress string, sessionID uuid.UUID) {
	LogSecurityEvent(SecurityEvent{EventType: EventSessionRevoked, UserID: &userID, IPAddress: ipAddress, Success: true, Details: map[string]any{"session_id": sessionID.String()}})
}
