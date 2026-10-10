package main

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"strconv"
)

var (
	errHeadTooLarge = errors.New("HTTP head too large")
	errNotHTTP      = errors.New("not an HTTP response")
)

// readHead reads an HTTP message head (start line + headers + blank line)
// and returns its exact bytes. Nothing past the head is consumed from br
// beyond what br has already buffered, so the caller can forward br.Buffered()
// as the first bytes of the stream that follows. Leading blank lines are
// skipped; both CRLF and bare LF line endings are accepted.
func readHead(br *bufio.Reader, max int) ([]byte, error) {
	var head []byte
	for {
		line, err := br.ReadSlice('\n')
		if len(head)+len(line) > max {
			return nil, errHeadTooLarge
		}
		head = append(head, line...)
		if err == bufio.ErrBufferFull {
			continue // a very long line; keep accumulating
		}
		if err != nil {
			return nil, err
		}
		if isBlankLine(line) {
			if len(head) == len(line) { // blank line before the start line
				head = head[:0]
				continue
			}
			return head, nil
		}
	}
}

func isBlankLine(l []byte) bool {
	return (len(l) == 2 && l[0] == '\r' && l[1] == '\n') || (len(l) == 1 && l[0] == '\n')
}

// parseStatusCode extracts the status code from a response head. Reason
// phrases are ignored, so custom ones ("101 <font color=...>") are fine.
func parseStatusCode(head []byte) (int, error) {
	line := head
	if i := bytes.IndexByte(head, '\n'); i >= 0 {
		line = head[:i]
	}
	line = bytes.TrimRight(line, "\r")
	if !bytes.HasPrefix(line, []byte("HTTP/")) {
		return 0, errNotHTTP
	}
	sp := bytes.IndexByte(line, ' ')
	if sp < 0 || len(line) < sp+4 {
		return 0, fmt.Errorf("malformed status line %q", truncate(string(line), 80))
	}
	code, err := strconv.Atoi(string(line[sp+1 : sp+4]))
	if err != nil || code < 100 || code > 999 {
		return 0, fmt.Errorf("malformed status line %q", truncate(string(line), 80))
	}
	return code, nil
}

// sniffStatus returns the status code if b starts with an HTTP status line.
func sniffStatus(b []byte) int {
	if !bytes.HasPrefix(b, []byte("HTTP/")) {
		return 0
	}
	code, err := parseStatusCode(b)
	if err != nil {
		return 0
	}
	return code
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
