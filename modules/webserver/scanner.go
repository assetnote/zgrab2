package webserver

import (
	"fmt"
	"strings"

	log "github.com/sirupsen/logrus"
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
	UserAgent string `long:"user-agent" default:"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36" description:"Set a custom user agent"`
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
	ServerPrivoxy    ServerType = "privoxy"
	ServerUnknown    ServerType = "unknown"
)

type ServerVersion struct {
	Major int `json:"major"`
	Minor int `json:"minor"`
	Patch int `json:"patch"`
}

func (v *ServerVersion) isLessThanOrEqual(other *ServerVersion) bool {
	if v.Major != other.Major {
		return v.Major <= other.Major
	}
	if v.Minor != other.Minor {
		return v.Minor <= other.Minor
	}
	return v.Patch <= other.Patch
}

// ProxySignature describes server versions where proxy functionality is enabled by default
type ProxySignature struct {
	VulnerableVersion *ServerVersion `json:"vulnerable_version"`
	CVE               string         `json:"cve"`
	Details           string         `json:"details"`
	IsMatch           bool           `json:"is_match"`
}

var ServerProxySignatures = map[ServerType][]ProxySignature{
	ServerApache: {
		{
			VulnerableVersion: &ServerVersion{2, 4, 48},
			CVE:               "CVE-2021-40438",
			Details:           "mod_proxy enabled by default, vulnerable to SSRF",
		},
	},
	ServerPrivoxy: {
		{
			VulnerableVersion: &ServerVersion{3, 0, 19},
			CVE:               "",
			Details:           "",
		},
	},
}

// Results contains the findings from the scan
type Results struct {
	Response       *http.Response `json:"response,omitempty"`
	ServerType     ServerType     `json:"server_type"`
	ServerValue    string         `json:"server_value,omitempty"`
	Proxy          bool           `json:"proxy"`
	ProxySignature ProxySignature `json:"proxy_signature,omitempty"`
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

// parseVersion parses a version string into a VersionInfo
func parseVersion(versionStr string) *ServerVersion {
	// extract version number before any parentheses or spaces
	parts := strings.Split(versionStr, " ")
	if len(parts) == 0 {
		return nil
	}

	// split version component (e.g., "Apache/2.4.18")
	versionParts := strings.Split(parts[0], "/")
	if len(versionParts) != 2 {
		return nil
	}

	var major, minor, patch int
	_, err := fmt.Sscanf(versionParts[1], "%d.%d.%d", &major, &minor, &patch)
	if err != nil {
		// try parsing just major.minor
		if _, err := fmt.Sscanf(versionParts[1], "%d.%d", &major, &minor); err != nil {
			return nil
		}
		patch = 0
	}

	return &ServerVersion{Major: major, Minor: minor, Patch: patch}
}

func identifyServer(serverHeader string) (ServerType, string, ProxySignature) {
	if serverHeader == "" {
		return ServerUnknown, "", ProxySignature{}
	}

	headerLower := strings.ToLower(serverHeader)
	version := parseVersion(serverHeader)

	serverTypes := map[string]ServerType{
		"apache/":    ServerApache,
		"nginx":      ServerNginx,
		"haproxy/":   ServerHAProxy,
		"squid/":     ServerSquid,
		"cloudflare": ServerCloudflare,
	}

	for substr, serverType := range serverTypes {
		if strings.Contains(headerLower, substr) {
			if version != nil {
				if configs, exists := ServerProxySignatures[serverType]; exists {
					for _, config := range configs {
						if version.isLessThanOrEqual(config.VulnerableVersion) {
							config.IsMatch = true
							return serverType, serverHeader, config
						}
					}
				}
			} else {
				log.Warnf("failed to parse version from %s", serverHeader)
			}
			return serverType, serverHeader, ProxySignature{}
		}
	}

	return ServerUnknown, serverHeader, ProxySignature{}
}

func identifyProxyAgent(proxyAgent string) (ServerType, string, ProxySignature) {
	if strings.Contains(strings.ToLower(proxyAgent), "privoxy") {
		if version := parseVersion(proxyAgent); version != nil {
			if configs, exists := ServerProxySignatures[ServerPrivoxy]; exists {
				for _, config := range configs {
					if version.isLessThanOrEqual(config.VulnerableVersion) {
						config.IsMatch = true
						return ServerPrivoxy, proxyAgent, config
					}
				}
			}
		}
		return ServerPrivoxy, proxyAgent, ProxySignature{}
	}
	return ServerUnknown, "", ProxySignature{}
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
			results.ServerType, results.ServerValue, results.ProxySignature = identifyServer(serverHeader)

			// no server header so check proxy agent
			if serverHeader == "" {
				proxyAgent := resp.Response.Header.Get("Proxy-Agent")
				results.ServerType, results.ServerValue, results.ProxySignature = identifyProxyAgent(proxyAgent)
			}

			results.Proxy = results.ProxySignature.IsMatch

			// Only return protocol error for unknown server type if we got a valid response
			// and it wasn't a 400 Bad Request (which might indicate HTTPS required)
			if results.ServerType == ServerUnknown && resp.Response.StatusCode != 400 {
				return zgrab2.SCAN_PROTOCOL_ERROR, nil, zgrab2.NewScanError(zgrab2.SCAN_PROTOCOL_ERROR, nil)
			}
		}
	}

	return zgrab2.SCAN_SUCCESS, &results, nil
}
