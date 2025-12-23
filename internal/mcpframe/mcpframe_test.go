package mcpframe

import (
	"bufio"
	"bytes"
	"strconv"
	"strings"
	"testing"
)

func TestWriteFrameUTF8Length(t *testing.T) {
	payload := []byte(`{"message":"こんにちは"}`)
	var buf bytes.Buffer
	if err := WriteFrame(&buf, payload); err != nil {
		t.Fatalf("WriteFrame failed: %v", err)
	}
	data := buf.String()
	parts := strings.SplitN(data, "\r\n\r\n", 2)
	if len(parts) != 2 {
		t.Fatalf("expected header separator, got %q", data)
	}
	header := parts[0]
	if !strings.Contains(header, "Content-Length: ") {
		t.Fatalf("missing Content-Length header: %q", header)
	}
	lengthText := strings.TrimSpace(strings.TrimPrefix(header, "Content-Length:"))
	length, err := strconv.Atoi(lengthText)
	if err != nil {
		t.Fatalf("failed to parse Content-Length %q: %v", lengthText, err)
	}
	if length != len(payload) {
		t.Fatalf("expected Content-Length %d, got %d", len(payload), length)
	}
}

func TestReadFrameRoundTrip(t *testing.T) {
	payload := []byte(`{"jsonrpc":"2.0","id":1,"result":{"ok":true}}`)
	var buf bytes.Buffer
	if err := WriteFrame(&buf, payload); err != nil {
		t.Fatalf("WriteFrame failed: %v", err)
	}
	reader := bufio.NewReader(bytes.NewReader(buf.Bytes()))
	out, err := ReadFrame(reader)
	if err != nil {
		t.Fatalf("ReadFrame failed: %v", err)
	}
	if string(out) != string(payload) {
		t.Fatalf("payload mismatch: %q", string(out))
	}
}

func TestReadFrameMultiple(t *testing.T) {
	first := []byte(`{"id":1}`)
	second := []byte(`{"id":2}`)
	var buf bytes.Buffer
	if err := WriteFrame(&buf, first); err != nil {
		t.Fatalf("WriteFrame first failed: %v", err)
	}
	if err := WriteFrame(&buf, second); err != nil {
		t.Fatalf("WriteFrame second failed: %v", err)
	}
	reader := bufio.NewReader(bytes.NewReader(buf.Bytes()))
	out1, err := ReadFrame(reader)
	if err != nil {
		t.Fatalf("ReadFrame first failed: %v", err)
	}
	out2, err := ReadFrame(reader)
	if err != nil {
		t.Fatalf("ReadFrame second failed: %v", err)
	}
	if string(out1) != string(first) || string(out2) != string(second) {
		t.Fatalf("frame order mismatch: %q %q", string(out1), string(out2))
	}
}
