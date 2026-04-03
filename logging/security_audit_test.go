package logging

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestLogSecurityEventWritesNDJSONLine(t *testing.T) {
	var buf bytes.Buffer

	securityLogMutex.Lock()
	securityLogWriter = &buf
	securityLogInitialized = true
	securityLogFile = nil
	securityLogMutex.Unlock()

	LogSecurityEvent(SecurityEvent{EventType: EventLoginSuccess, IPAddress: "127.0.0.1", Success: true})

	line := buf.String()
	if !strings.HasSuffix(line, "\n") {
		t.Fatalf("log line %q does not end with newline", line)
	}
	if strings.Contains(line, "[SECURITY]") {
		t.Fatalf("log line %q contains logger prefix", line)
	}

	trimmed := strings.TrimSpace(line)
	var event SecurityEvent
	if err := json.Unmarshal([]byte(trimmed), &event); err != nil {
		t.Fatalf("failed to parse NDJSON line %q: %v", trimmed, err)
	}
	if event.EventType != EventLoginSuccess {
		t.Fatalf("event type = %q, want %q", event.EventType, EventLoginSuccess)
	}
	if event.IPAddress != "127.0.0.1" {
		t.Fatalf("ipAddress = %q, want %q", event.IPAddress, "127.0.0.1")
	}
}
