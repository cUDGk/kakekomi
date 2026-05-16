package kakekomi

import (
	"bufio"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"
)

// Minimal Tor control client. Speaks the Tor Control Protocol over a TCP
// (or Unix) socket. Just enough for kakekomi's needs:
//
//   - AUTHENTICATE (cookie or password)
//   - ADD_ONION new:ED25519-V3 Port=80,host:port [ClientAuthV3=...]
//   - DEL_ONION <ServiceID>
//
// We deliberately avoid an external dep (github.com/cretz/bine) since the
// surface we need is tiny and pulling in a 5k-line lib for an opinionated
// security product is hostile to audit.

type TorControl struct {
	conn net.Conn
	rd   *bufio.Reader
}

// DialTorControl connects to the tor control socket.
// addr forms accepted: "tcp:127.0.0.1:9051" / "unix:/var/run/tor/control" / "127.0.0.1:9051"
func DialTorControl(addr string) (*TorControl, error) {
	network, target := "tcp", addr
	if strings.HasPrefix(addr, "tcp:") {
		target = strings.TrimPrefix(addr, "tcp:")
	} else if strings.HasPrefix(addr, "unix:") {
		network, target = "unix", strings.TrimPrefix(addr, "unix:")
	}
	c, err := net.DialTimeout(network, target, 5*time.Second)
	if err != nil {
		return nil, fmt.Errorf("tor control dial: %w", err)
	}
	return &TorControl{conn: c, rd: bufio.NewReader(c)}, nil
}

func (t *TorControl) Close() error { return t.conn.Close() }

func (t *TorControl) send(line string) error {
	_, err := io.WriteString(t.conn, line+"\r\n")
	return err
}

// readReply reads one tor control reply group. Returns the lines (without
// status code) and the trailing status code (e.g. 250).
func (t *TorControl) readReply() ([]string, int, error) {
	var lines []string
	for {
		line, err := t.rd.ReadString('\n')
		if err != nil {
			return nil, 0, err
		}
		line = strings.TrimRight(line, "\r\n")
		if len(line) < 4 {
			return nil, 0, errors.New("short reply: " + line)
		}
		code := atoi3(line[:3])
		sep := line[3]
		body := line[4:]
		lines = append(lines, body)
		// '-' = mid-reply, '+' = data block follows, ' ' = end.
		if sep == ' ' {
			if code/100 != 2 {
				return lines, code, fmt.Errorf("tor error %d: %s", code, body)
			}
			return lines, code, nil
		}
	}
}

func atoi3(s string) int {
	n := 0
	for _, c := range s {
		n = n*10 + int(c-'0')
	}
	return n
}

// AuthenticateCookie reads the auth cookie file and sends AUTHENTICATE <hex>.
func (t *TorControl) AuthenticateCookie(cookieFile string) error {
	cookie, err := os.ReadFile(cookieFile)
	if err != nil {
		return fmt.Errorf("read auth cookie: %w", err)
	}
	if err := t.send("AUTHENTICATE " + hex.EncodeToString(cookie)); err != nil {
		return err
	}
	_, _, err2 := t.readReply()
	return err2
}

// AuthenticatePassword sends AUTHENTICATE "password".
func (t *TorControl) AuthenticatePassword(password string) error {
	if hasControlBytes(password) {
		return errors.New("tor password contains forbidden control bytes (\\r/\\n/\\0)")
	}
	q := strings.ReplaceAll(password, `"`, `\"`)
	if err := t.send(fmt.Sprintf(`AUTHENTICATE "%s"`, q)); err != nil {
		return err
	}
	_, _, err := t.readReply()
	return err
}

// hasControlBytes rejects values that could inject Tor control protocol commands.
func hasControlBytes(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '\r' || c == '\n' || c == 0 {
			return true
		}
	}
	return false
}

// AuthenticateAuto tries cookie first (if file given), then password.
func (t *TorControl) AuthenticateAuto(cookieFile, password string) error {
	if cookieFile != "" {
		if err := t.AuthenticateCookie(cookieFile); err == nil {
			return nil
		}
	}
	if password != "" {
		return t.AuthenticatePassword(password)
	}
	// Try cookie-less null auth (only works if no auth configured).
	if err := t.send("AUTHENTICATE"); err != nil {
		return err
	}
	_, _, err := t.readReply()
	return err
}

// AddOnionV3 registers an ephemeral v3 hidden service that forwards
// virtual port 80 to the given local target. Returns the service ID
// (e.g. "abc...xyz", append ".onion" for full address) and the private key.
//
// clientPubKeys is optional: if non-empty, the service requires Client Auth.
func (t *TorControl) AddOnionV3(targetHostPort string, clientPubKeys []string) (serviceID, privKey string, err error) {
	if hasControlBytes(targetHostPort) {
		return "", "", errors.New("targetHostPort contains forbidden control bytes")
	}
	for _, pk := range clientPubKeys {
		if hasControlBytes(pk) || strings.ContainsAny(pk, " \t") {
			return "", "", errors.New("clientPubKey contains forbidden bytes")
		}
	}
	cmd := "ADD_ONION NEW:ED25519-V3 Flags=Detach Port=80," + targetHostPort
	for _, pk := range clientPubKeys {
		cmd += " ClientAuthV3=" + pk
	}
	if err := t.send(cmd); err != nil {
		return "", "", err
	}
	lines, _, err := t.readReply()
	if err != nil {
		return "", "", err
	}
	for _, l := range lines {
		if strings.HasPrefix(l, "ServiceID=") {
			serviceID = strings.TrimPrefix(l, "ServiceID=")
		} else if strings.HasPrefix(l, "PrivateKey=") {
			privKey = strings.TrimPrefix(l, "PrivateKey=")
		}
	}
	if serviceID == "" {
		return "", "", errors.New("tor ADD_ONION did not return ServiceID")
	}
	return serviceID, privKey, nil
}

// AddOnionExistingKey registers a hidden service from a stored private key
// (returned from a previous AddOnionV3). The .onion address stays the same
// across restarts.
func (t *TorControl) AddOnionExistingKey(privKey, targetHostPort string, clientPubKeys []string) (string, error) {
	// C2 fix: a tampered ingress.key file could otherwise inject arbitrary tor
	// control commands. Tor's KeyBlob format is "ED25519-V3:<base64>" with no
	// whitespace, no control bytes.
	if hasControlBytes(privKey) || strings.ContainsAny(privKey, " \t") {
		return "", errors.New("tor private key contains forbidden bytes")
	}
	if !strings.HasPrefix(privKey, "ED25519-V3:") {
		return "", errors.New("tor private key has unexpected format")
	}
	if hasControlBytes(targetHostPort) {
		return "", errors.New("targetHostPort contains forbidden control bytes")
	}
	for _, pk := range clientPubKeys {
		if hasControlBytes(pk) || strings.ContainsAny(pk, " \t") {
			return "", errors.New("clientPubKey contains forbidden bytes")
		}
	}
	cmd := "ADD_ONION " + privKey + " Flags=Detach Port=80," + targetHostPort
	for _, pk := range clientPubKeys {
		cmd += " ClientAuthV3=" + pk
	}
	if err := t.send(cmd); err != nil {
		return "", err
	}
	lines, _, err := t.readReply()
	if err != nil {
		return "", err
	}
	for _, l := range lines {
		if strings.HasPrefix(l, "ServiceID=") {
			return strings.TrimPrefix(l, "ServiceID="), nil
		}
	}
	return "", errors.New("tor ADD_ONION did not return ServiceID")
}

// DelOnion tears down an ephemeral hidden service by its ServiceID.
func (t *TorControl) DelOnion(serviceID string) error {
	if err := t.send("DEL_ONION " + serviceID); err != nil {
		return err
	}
	_, _, err := t.readReply()
	return err
}
