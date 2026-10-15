package main

import (
	"net"
	"os"
)

// sdNotify sends a state string to systemd (Type=notify). It is a no-op when
// not running under systemd. It returns whether a message was sent.
func sdNotify(state string) (bool, error) {
	name := os.Getenv("NOTIFY_SOCKET")
	if name == "" {
		return false, nil
	}
	if name[0] == '@' { // abstract socket
		name = "\x00" + name[1:]
	}
	conn, err := net.DialUnix("unixgram", nil, &net.UnixAddr{Name: name, Net: "unixgram"})
	if err != nil {
		return false, err
	}
	defer conn.Close()
	if _, err := conn.Write([]byte(state)); err != nil {
		return false, err
	}
	return true, nil
}
