package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"gate/internal/mcpframe"
)

type stringList []string

func (s *stringList) String() string {
	return strings.Join(*s, ",")
}

func (s *stringList) Set(value string) error {
	*s = append(*s, value)
	return nil
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "send":
		if err := runSend(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "gatec send failed: %v\n", err)
			os.Exit(1)
		}
	default:
		usage()
		os.Exit(1)
	}
}

func usage() {
	exe := filepath.Base(os.Args[0])
	fmt.Fprintf(os.Stderr, "Usage:\n")
	fmt.Fprintf(os.Stderr, "  %s send --file <requests.jsonl>\n", exe)
	fmt.Fprintf(os.Stderr, "    [--server-exe <exe>] [--server-arg <arg>...]\n")
	fmt.Fprintf(os.Stderr, "    [--pretty]\n")
}

func runSend(args []string) error {
	fs := flag.NewFlagSet("send", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var (
		filePath   string
		serverExe  string
		serverArgs stringList
		pretty     bool
	)
	fs.StringVar(&filePath, "file", "", "Path to requests JSONL or JSON array")
	fs.StringVar(&serverExe, "server-exe", "go", "Server executable")
	fs.Var(&serverArgs, "server-arg", "Server args (repeatable)")
	fs.BoolVar(&pretty, "pretty", false, "Pretty-print JSON responses")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if filePath == "" {
		return fmt.Errorf("missing --file")
	}

	requests, err := readRequests(filePath)
	if err != nil {
		return err
	}
	if len(serverArgs) == 0 {
		serverArgs = []string{"run", ".", "mcp"}
	}

	cmd := exec.Command(serverExe, serverArgs...)
	cmd.Stdout = nil
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return err
	}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return err
	}

	if err := cmd.Start(); err != nil {
		return err
	}

	go func() {
		_, _ = io.Copy(io.Discard, stderr)
	}()

	writer := bufio.NewWriter(stdin)
	reader := bufio.NewReader(stdout)
	var lastRequestID *int

	for _, payload := range requests {
		finalPayload, err := applyRequestID(payload, lastRequestID)
		if err != nil {
			_ = stdin.Close()
			_ = cmd.Wait()
			return err
		}

		if err := mcpframe.WriteFrame(writer, []byte(finalPayload)); err != nil {
			_ = stdin.Close()
			_ = cmd.Wait()
			return err
		}
		if err := writer.Flush(); err != nil {
			_ = stdin.Close()
			_ = cmd.Wait()
			return err
		}

		response, err := mcpframe.ReadFrame(reader)
		if err != nil {
			_ = stdin.Close()
			_ = cmd.Wait()
			return err
		}
		if pretty {
			var out bytes.Buffer
			if err := json.Indent(&out, response, "", "  "); err == nil {
				fmt.Println(out.String())
			} else {
				fmt.Println(string(response))
			}
		} else {
			fmt.Println(string(response))
		}

		if id, ok := extractRequestID(response); ok {
			lastRequestID = &id
		}
	}

	_ = stdin.Close()
	return cmd.Wait()
}

func readRequests(path string) ([]string, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	raw := strings.TrimSpace(string(content))
	if raw == "" {
		return nil, fmt.Errorf("empty request file")
	}
	if strings.HasPrefix(raw, "[") {
		var list []json.RawMessage
		if err := json.Unmarshal(content, &list); err != nil {
			return nil, fmt.Errorf("invalid JSON array: %w", err)
		}
		out := make([]string, 0, len(list))
		for _, item := range list {
			out = append(out, strings.TrimSpace(string(item)))
		}
		return out, nil
	}

	lines := strings.Split(raw, "\n")
	out := make([]string, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		out = append(out, line)
	}
	return out, nil
}

func applyRequestID(payload string, lastID *int) (string, error) {
	if !strings.Contains(payload, "{{request_id}}") {
		return payload, nil
	}
	if lastID == nil {
		return "", fmt.Errorf("request_id placeholder used before any response")
	}
	value := strconv.Itoa(*lastID)
	withQuotes := strings.ReplaceAll(payload, "\"{{request_id}}\"", value)
	return strings.ReplaceAll(withQuotes, "{{request_id}}", value), nil
}

func extractRequestID(response []byte) (int, bool) {
	var parsed map[string]interface{}
	if err := json.Unmarshal(response, &parsed); err != nil {
		return 0, false
	}
	result, ok := parsed["result"].(map[string]interface{})
	if !ok {
		return 0, false
	}
	raw, ok := result["request_id"]
	if !ok {
		return 0, false
	}
	switch v := raw.(type) {
	case float64:
		return int(v), true
	case int:
		return v, true
	case int64:
		return int(v), true
	default:
		return 0, false
	}
}
