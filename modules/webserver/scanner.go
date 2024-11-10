package webserver

import (
	"log"
	"strings"

	"github.com/zmap/zgrab2"
	"github.com/zmap/zgrab2/lib/http"
	http_scanner "github.com/zmap/zgrab2/modules/http"
)

// Flags holds the command-line configuration for the web server scan module.
type Flags struct {
	zgrab2.BaseFlags
	zgrab2.TLSFlags
	Method    string `long:"method" default:"HEAD" description:"Set HTTP request method type"`
	Endpoint  string `long:"endpoint" default:"/" description:"Send an HTTP request to an endpoint"`
	UserAgent string `long:"user-agent" default:"Mozilla/5.0 zgrab/0.x" description:"Set a custom user agent"`
}

// Module implements the zgrab2.Module interface
type Module struct{}

// Scanner implements the zgrab2.Scanner interface
type Scanner struct {
	config *Flags
}

// ServerType represents the identified web server type
type ServerType string

const (
	ServerApache     ServerType = "apache"
	ServerNginx      ServerType = "nginx"
	ServerHAProxy    ServerType = "haproxy"
	ServerSquid      ServerType = "squid"
	ServerCloudflare ServerType = "cloudflare"
	ServerUnknown    ServerType = "unknown"
)

// Results contains the findings from the scan
type Results struct {
	Response    *http.Response `json:"response,omitempty"`
	ServerType  ServerType     `json:"server_type"`
	ServerValue string         `json:"server_value,omitempty"`
}

// RegisterModule registers the zgrab2 module
func RegisterModule() {
	var module Module
	_, err := zgrab2.AddCommand("webserver", "Web Server Scanner", module.Description(), 443, &module)
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
	return "Detect and identify common web servers (Apache, Nginx, HAProxy, Squid)"
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
	return "webserver"
}

// identifyServer examines the Server header to determine the server type
func identifyServer(serverHeader string) (ServerType, string) {
	if serverHeader == "" {
		return ServerUnknown, ""
	}

	headerLower := strings.ToLower(serverHeader)

	switch {
	case strings.Contains(headerLower, "apache/"):
		return ServerApache, serverHeader
	case strings.Contains(headerLower, "nginx/"):
		return ServerNginx, serverHeader
	case strings.Contains(headerLower, "haproxy/"):
		return ServerHAProxy, serverHeader
	case strings.Contains(headerLower, "squid/"):
		return ServerSquid, serverHeader
	case strings.Contains(headerLower, "cloudflare"):
		return ServerCloudflare, serverHeader
	default:
		return ServerUnknown, serverHeader
	}
}

// Scan performs the web server scan
func (s *Scanner) Scan(t zgrab2.ScanTarget) (zgrab2.ScanStatus, interface{}, error) {
	results := Results{
		ServerType: ServerUnknown,
	}

	// Create an HTTP scanner to perform the actual HTTP request
	httpScanner := new(http_scanner.Scanner)
	httpFlags := http_scanner.Flags{
		BaseFlags:       s.config.BaseFlags,
		TLSFlags:        s.config.TLSFlags,
		Method:          s.config.Method,
		Endpoint:        s.config.Endpoint,
		UserAgent:       s.config.UserAgent,
		FailHTTPToHTTPS: true,
		RetryHTTPS:      true,
	}

	if err := httpScanner.Init(&httpFlags); err != nil {
		return zgrab2.SCAN_UNKNOWN_ERROR, nil, err
	}

	// Perform the HTTP scan
	status, httpResults, err := httpScanner.Scan(t)
	if err != nil {
		return status, nil, err
	}

	if httpResults != nil {
		if resp, ok := httpResults.(*http_scanner.Results); ok && resp.Response != nil {
			results.Response = resp.Response

			serverHeader := resp.Response.Header.Get("Server")
			results.ServerType, results.ServerValue = identifyServer(serverHeader)

			// Only return protocol error for unknown server type if we got a valid response
			// and it wasn't a 400 Bad Request (which might indicate HTTPS required)
			if results.ServerType == ServerUnknown && resp.Response.StatusCode != 400 {
				return zgrab2.SCAN_PROTOCOL_ERROR, nil, zgrab2.NewScanError(zgrab2.SCAN_PROTOCOL_ERROR, nil)
			}
		}
	}

	return zgrab2.SCAN_SUCCESS, &results, nil
}
