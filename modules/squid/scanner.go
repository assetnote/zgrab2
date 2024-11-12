package squid

import (
	"log"
	"strings"

	"github.com/zmap/zgrab2"
	"github.com/zmap/zgrab2/lib/http"
	http_scanner "github.com/zmap/zgrab2/modules/http"
)

// Flags holds the command-line configuration for the Squid scan module.
type Flags struct {
	zgrab2.BaseFlags
	zgrab2.TLSFlags
	Method    string `long:"method" default:"HEAD" description:"Set HTTP request method type"`
	Endpoint  string `long:"endpoint" default:"/" description:"Send an HTTP request to an endpoint"`
	UserAgent string `long:"user-agent" default:"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36" description:"Set a custom user agent"`
}

// Module implements the zgrab2.Module interface
type Module struct{}

// Scanner implements the zgrab2.Scanner interface
type Scanner struct {
	config *Flags
}

// Results contains the findings from the scan
type Results struct {
	Response *http.Response `json:"response,omitempty"`
	IsSquid  bool           `json:"is_squid"`
	Version  string         `json:"version,omitempty"`
}

// RegisterModule registers the zgrab2 module
func RegisterModule() {
	var module Module
	_, err := zgrab2.AddCommand("squid", "Squid Proxy Scanner", module.Description(), 3128, &module)
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
	return "Detect Squid proxy servers and their versions"
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
	return "squid"
}

// Scan performs the squid scan
func (s *Scanner) Scan(t zgrab2.ScanTarget) (zgrab2.ScanStatus, interface{}, error) {
	const squidServerHeader = "squid/"
	results := Results{}

	// Create an HTTP scanner to perform the actual HTTP request
	httpScanner := new(http_scanner.Scanner)
	httpFlags := http_scanner.Flags{
		BaseFlags: s.config.BaseFlags,
		TLSFlags:  s.config.TLSFlags,
		Method:    s.config.Method,
		Endpoint:  s.config.Endpoint,
		UserAgent: s.config.UserAgent,
	}

	if err := httpScanner.Init(&httpFlags); err != nil {
		return zgrab2.SCAN_UNKNOWN_ERROR, nil, err
	}

	// Perform the HTTP scan
	status, httpResults, err := httpScanner.Scan(t)
	if err != nil {
		return status, nil, err
	}

	// Extract the HTTP response
	if httpResults != nil {
		if resp, ok := httpResults.(*http_scanner.Results); ok && resp.Response != nil {
			results.Response = resp.Response

			// Check for Squid in Server header
			if server := resp.Response.Header.Get("Server"); server != "" {
				if strings.Contains(strings.ToLower(server), squidServerHeader) {
					results.IsSquid = true
					results.Version = server
				}
			}
		}
	}

	return zgrab2.SCAN_SUCCESS, &results, nil
}
