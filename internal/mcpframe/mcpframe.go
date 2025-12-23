package mcpframe

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// WriteFrame writes a JSON-RPC payload with MCP Content-Length framing.
func WriteFrame(w io.Writer, payload []byte) error {
	header := fmt.Sprintf("Content-Length: %d\r\n\r\n", len(payload))
	if _, err := w.Write([]byte(header)); err != nil {
		return err
	}
	_, err := w.Write(payload)
	return err
}

// ReadFrame reads one MCP frame from the reader and returns the raw JSON bytes.
func ReadFrame(r *bufio.Reader) ([]byte, error) {
	var contentLength int
	seenNonBlankHeaderLine := false
	seenContentLength := false

	for {
		line, err := r.ReadString('\n')
		if err != nil && !errors.Is(err, io.EOF) {
			return nil, err
		}
		if errors.Is(err, io.EOF) && len(line) == 0 {
			if !seenNonBlankHeaderLine {
				return nil, io.EOF
			}
			if !seenContentLength {
				return nil, fmt.Errorf("missing Content-Length")
			}
			return nil, io.ErrUnexpectedEOF
		}
		line = strings.TrimRight(line, "\r\n")
		if strings.TrimSpace(line) == "" {
			if !seenNonBlankHeaderLine {
				if errors.Is(err, io.EOF) {
					return nil, io.EOF
				}
				continue
			}
			break
		}
		seenNonBlankHeaderLine = true
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			if errors.Is(err, io.EOF) {
				if !seenContentLength {
					return nil, fmt.Errorf("missing Content-Length")
				}
				return nil, io.ErrUnexpectedEOF
			}
			continue
		}
		if strings.EqualFold(strings.TrimSpace(parts[0]), "Content-Length") {
			length, err := strconv.Atoi(strings.TrimSpace(parts[1]))
			if err != nil || length <= 0 {
				return nil, fmt.Errorf("invalid Content-Length")
			}
			contentLength = length
			seenContentLength = true
		}
		if errors.Is(err, io.EOF) {
			if !seenContentLength {
				return nil, fmt.Errorf("missing Content-Length")
			}
			return nil, io.ErrUnexpectedEOF
		}
	}

	if !seenContentLength || contentLength <= 0 {
		return nil, fmt.Errorf("missing Content-Length")
	}

	payload := make([]byte, contentLength)
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, err
	}
	return payload, nil
}
