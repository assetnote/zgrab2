package shadowsocks

import (
	"errors"
	"io"
	"log"
	"net"
	"time"

	"github.com/zmap/zgrab2"
)

// Flags holds the command-line configuration for the Shadowsocks scan module.
type Flags struct {
	zgrab2.BaseFlags
}

// Module implements the zgrab2.Module interface
type Module struct{}

// Scanner implements the zgrab2.Scanner interface
type Scanner struct {
	config *Flags
}

// Results contains the findings from the scan
type Results struct {
	HandshakeResponse []byte `json:"handshake_response,omitempty"`
	IsSSServer        bool   `json:"is_shadowsocks_server"`
}

// RegisterModule registers the zgrab2 module
func RegisterModule() {
	var module Module
	_, err := zgrab2.AddCommand("shadowsocks", "Shadowsocks Server Scanner", module.Description(), 8388, &module)
	if err != nil {
		log.Fatal(err)
	}
}

// NewFlags returns a default Flags object
func (m *Module) NewFlags() interface{} {
	return new(Flags)
}

// NewScanner returns a new Scanner instance
func (m *Module) NewScanner() zgrab2.Scanner {
	return new(Scanner)
}

// Description returns an overview of this module
func (m *Module) Description() string {
	return "Probe for shadowsocks servers"
}

// Validate checks that the flags are valid
func (f *Flags) Validate(args []string) error {
	return nil
}

// Help returns help text
func (f *Flags) Help() string {
	return ""
}

// Init initializes the Scanner with the flags
func (s *Scanner) Init(flags zgrab2.ScanFlags) error {
	f, _ := flags.(*Flags)
	s.config = f
	return nil
}

// InitPerSender initializes the scanner for each send
func (s *Scanner) InitPerSender(senderID int) error {
	return nil
}

// GetName returns the scanner name
func (s *Scanner) GetName() string {
	return s.config.Name
}

// GetTrigger returns the scanner trigger
func (s *Scanner) GetTrigger() string {
	return s.config.Trigger
}

// Protocol returns the protocol identifier
func (s *Scanner) Protocol() string {
	return "shadowsocks"
}

// Scan performs the shadowsocks scan
func (s *Scanner) Scan(target zgrab2.ScanTarget) (zgrab2.ScanStatus, interface{}, error) {
	results := Results{}

	conn, err := target.Open(&s.config.BaseFlags)
	if err != nil {
		return zgrab2.TryGetScanStatus(err), &results, err
	}
	defer conn.Close()

	// Set a read timeout
	conn.SetReadDeadline(time.Now().Add(s.config.Timeout))

	// Try AEAD handshake
	handshake := []byte{0x03, 0x03}
	_, err = conn.Write(handshake)
	if err != nil {
		return zgrab2.TryGetScanStatus(err), &results, err
	}

	// Try to read response
	response := make([]byte, 1024)
	n, err := conn.Read(response)
	if err != nil {
		// this could be very prone to false positives
		if err == io.EOF || errors.Is(err, net.Error(nil)) {
			// No response is typical for shadowsocks
			results.IsSSServer = true
			return zgrab2.SCAN_SUCCESS, &results, nil
		}
		return zgrab2.TryGetScanStatus(err), &results, err
	}

	results.HandshakeResponse = response[:n]

	// If we get here with no error and no response, likely a shadowsocks server
	if n == 0 {
		results.IsSSServer = true
	}

	return zgrab2.SCAN_SUCCESS, &results, nil
}
