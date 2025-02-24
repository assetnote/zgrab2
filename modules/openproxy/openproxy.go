package openproxy

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
	regexp "github.com/wasilibs/go-re2"

	"github.com/zmap/zgrab2"
	"golang.org/x/net/proxy"
)

var (
	// Compile regex patterns once
	apacheEtagRegex = regexp.MustCompile(`"?\d+-\d+-\d+"?`)
	nginxEtagRegex  = regexp.MustCompile(`"?[a-f0-9]{32}:\d+\.\d+"?`)
	iisEtagRegex    = regexp.MustCompile(`"[a-f0-9]+:[0-9]+"`)
)

// ProxyTest defines a proxy configuration to test
type ProxyTest struct {
	Name     string `json:"name"`
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
}

// Results contains the scan results for a proxy test
type Results struct {
	Name        string                    `json:"name"`
	Protocol    string                    `json:"protocol"`
	IsOpen      bool                      `json:"is_open"`
	TestResults map[string]*URLTestResult `json:"test_results"`
}

// URLTestResult contains results for a single URL test
type URLTestResult struct {
	Success      bool                `json:"success"`
	StatusCode   int                 `json:"status_code,omitempty"`
	ResponseTime string              `json:"response_time,omitempty"`
	ResponseSize int64               `json:"response_size,omitempty"`
	Headers      map[string][]string `json:"headers,omitempty"`
	Body         []byte              `json:"body,omitempty"`
	Error        string              `json:"error,omitempty"`
}

// Flags contains configuration options
type Flags struct {
	zgrab2.BaseFlags
	ProxyTests []ProxyTest `json:"proxy_tests"`
	TestURLs   []string    `json:"test_urls"`
}

// Module implements the zgrab2.Module interface
type Module struct{}

// Scanner implements the zgrab2.Scanner interface
type Scanner struct {
	config *Flags
}

// RegisterModule registers the zgrab2 module
func RegisterModule() {
	var module Module
	_, err := zgrab2.AddCommand("openproxy", "OpenProxy scanner", module.Description(), 80, &module)
	if err != nil {
		log.Fatal(err)
	}
}

func (module *Module) NewFlags() interface{} {
	uniqueTests := make(map[string]ProxyTest)

	for _, tests := range serverTypes {
		for _, test := range tests {
			key := fmt.Sprintf("%d-%s", test.Port, test.Protocol)
			uniqueTests[key] = ProxyTest{
				Name:     test.Name, // Include name for better logging
				Port:     test.Port,
				Protocol: test.Protocol,
			}
		}
	}

	proxyTests := make([]ProxyTest, 0, len(uniqueTests))
	for _, test := range uniqueTests {
		proxyTests = append(proxyTests, test)
	}

	return &Flags{
		ProxyTests: proxyTests,
		TestURLs: []string{
			"http://example.com",
			"https://example.com",
		},
	}
}

// serverTypes maps ports to potential server types that should be checked
var serverTypes = map[int][]ProxyTest{
	80:   {{Name: "Apache HTTP", Port: 80, Protocol: "http"}, {Name: "Nginx HTTP", Port: 80, Protocol: "http"}},
	443:  {{Name: "Apache HTTPS", Port: 443, Protocol: "https"}, {Name: "Nginx HTTPS", Port: 443, Protocol: "https"}},
	3128: {{Name: "Squid", Port: 3128, Protocol: "http"}},
	8118: {{Name: "Privoxy", Port: 8118, Protocol: "http"}},
	8388: {{Name: "Shadowsocks", Port: 8388, Protocol: "socks5"}},
}

// TODO: wire up internal service checks
var internalServiceChecks = []struct {
	Name    string
	Regex   *regexp.Regexp
	URIPath string
}{
	{
		Name:    "SSH",
		Regex:   regexp.MustCompile(`(?i)SSH-\d+\.\d+-`),
		URIPath: "http://127.0.0.1:22/",
	},
	{
		Name:    "SMTP",
		Regex:   regexp.MustCompile(`(?i)SMTP Postfix.*I can break rules, too\. Goodbye\.`),
		URIPath: "http://127.0.0.1:25/",
	},
}

// NewScanner provides a new scanner instance
func (module *Module) NewScanner() zgrab2.Scanner {
	return new(Scanner)
}

// Description returns the module description
func (module *Module) Description() string {
	return "Probe for open HTTP and SOCKS proxies"
}

// Validate checks that the flags are valid
func (flags *Flags) Validate(args []string) error {
	return nil
}

// Help returns help documentation
func (flags *Flags) Help() string {
	return ""
}

// InitPerSender initializes the scanner for each send
func (scanner *Scanner) InitPerSender(senderID int) error {
	return nil
}

// GetName returns the scanner name
func (scanner *Scanner) GetName() string {
	return scanner.config.Name
}

// GetTrigger returns the port trigger
func (scanner *Scanner) GetTrigger() string {
	return scanner.config.Trigger
}

// Protocol returns the protocol identifier
func (scanner *Scanner) Protocol() string {
	return "openproxy"
}

// Init initializes the scanner
func (scanner *Scanner) Init(flags zgrab2.ScanFlags) error {
	f, _ := flags.(*Flags)
	scanner.config = f
	return nil
}

// validateProxyHeaders checks if response headers match any known proxy types
// Returns a map of server names to whether they matched
func validateProxyHeaders(headers map[string][]string) map[string]bool {
	matches := make(map[string]bool)

	server := headers["Server"]
	if len(server) > 0 {
		if strings.HasPrefix(server[0], "Apache/") {
			matches["Apache HTTP"] = true
			matches["Apache HTTPS"] = true
		}
		if strings.HasPrefix(server[0], "nginx/") {
			matches["Nginx HTTP"] = true
			matches["Nginx HTTPS"] = true
		}
	}

	if etag := headers["Etag"]; len(etag) > 0 {
		etagValue := etag[0]
		if apacheEtagRegex.MatchString(etagValue) {
			matches["Apache HTTP"] = true
			matches["Apache HTTPS"] = true
			log.Debugf("matched apache etag")
		}
		if nginxEtagRegex.MatchString(etagValue) {
			matches["Nginx HTTP"] = true
			matches["Nginx HTTPS"] = true
			log.Debugf("matched nginx etag")
		}
		if iisEtagRegex.MatchString(etagValue) {
			matches["IIS"] = true
		}
	}

	via := headers["Via"]
	xcache := headers["X-Cache"]
	if len(via) > 0 && strings.Contains(via[0], "squid") {
		matches["Squid"] = true
	}
	if len(xcache) > 0 && strings.Contains(xcache[0], "squid") {
		matches["Squid"] = true
	}

	// TODO: could result in false positives
	// matches["HAProxy HTTP"] = true
	// matches["HAProxy HTTPS"] = true
	//
	// matches["Privoxy"] = true
	//
	// matches["Shadowsocks"] = true
	//
	return matches
}

// Scan performs the openproxy scan
func (scanner *Scanner) Scan(target zgrab2.ScanTarget) (zgrab2.ScanStatus, interface{}, error) {
	results := make(map[string]*Results)
	targetHost := target.String()

	// Group tests by port/protocol to avoid duplicate requests
	portTests := make(map[string]struct {
		port     int
		protocol string
		servers  []ProxyTest
	})

	// Group server types by port/protocol
	for port, tests := range serverTypes {
		for _, test := range tests {
			key := fmt.Sprintf("%d-%s", port, test.Protocol)
			if group, exists := portTests[key]; exists {
				group.servers = append(group.servers, test)
				portTests[key] = group
			} else {
				portTests[key] = struct {
					port     int
					protocol string
					servers  []ProxyTest
				}{
					port:     port,
					protocol: test.Protocol,
					servers:  []ProxyTest{test},
				}
			}
		}
	}

	resultsChan := make(chan struct {
		name   string
		result *Results
	}, len(serverTypes))

	// Test each unique port/protocol combination once
	for _, group := range portTests {
		go func(port int, protocol string, servers []ProxyTest) {
			var client *http.Client
			var err error

			// Create client for this port/protocol
			switch protocol {
			case "http", "https":
				client, err = getHTTPClient(targetHost, ProxyTest{Port: port, Protocol: protocol})
			case "socks5":
				client, err = getSOCKS5Client(targetHost, ProxyTest{Port: port, Protocol: protocol})
			}

			if err != nil {
				// Handle error for all servers in this group
				for _, server := range servers {
					result := &Results{
						Name:        server.Name,
						Protocol:    server.Protocol,
						IsOpen:      false,
						TestResults: make(map[string]*URLTestResult),
					}
					resultsChan <- struct {
						name   string
						result *Results
					}{server.Name, result}
				}
				return
			}

			// Make requests once for this port/protocol
			urlResults := make(map[string]*URLTestResult)
			for _, testURL := range scanner.config.TestURLs {
				urlResults[testURL] = testSingleURL(client, testURL, ProxyTest{Port: port, Protocol: protocol})
			}

			// Check results against each potential server type
			for _, server := range servers {
				result := &Results{
					Name:        server.Name,
					Protocol:    server.Protocol,
					IsOpen:      false,
					TestResults: make(map[string]*URLTestResult),
				}

				for url, urlResult := range urlResults {
					matches := validateProxyHeaders(urlResult.Headers)
					if matches[server.Name] {
						resultCopy := *urlResult
						resultCopy.Success = true
						result.IsOpen = true
						result.TestResults[url] = &resultCopy
					} else if urlResult.Error != "" {
						resultCopy := *urlResult
						resultCopy.Success = false
						result.TestResults[url] = &resultCopy
					}
					// Don't include non-matching successful responses
				}

				resultsChan <- struct {
					name   string
					result *Results
				}{server.Name, result}
			}
		}(group.port, group.protocol, group.servers)
	}

	// Collect results
	expectedResults := 0
	for _, tests := range serverTypes {
		expectedResults += len(tests)
	}

	for i := 0; i < expectedResults; i++ {
		res := <-resultsChan
		results[res.name] = res.result
	}

	return zgrab2.SCAN_SUCCESS, results, nil
}

// Helper function to test a single URL
func testSingleURL(client *http.Client, testURL string, test ProxyTest) *URLTestResult {
	log.Debugf("testing url: %s port %d protocol %s", testURL, test.Port, test.Protocol)
	urlResult := &URLTestResult{}

	req, err := http.NewRequest("GET", testURL, nil)
	if err != nil {
		urlResult.Success = false
		urlResult.Error = err.Error()
		return urlResult
	}

	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36")

	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		urlResult.Success = false
		urlResult.Error = err.Error()
		return urlResult
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		urlResult.Success = false
		urlResult.Error = err.Error()
		return urlResult
	}

	urlResult.Success = resp.StatusCode == 200
	urlResult.StatusCode = resp.StatusCode
	urlResult.ResponseTime = time.Since(start).String()
	urlResult.ResponseSize = int64(len(body))
	urlResult.Headers = resp.Header
	urlResult.Body = body

	return urlResult
}

func getHTTPClient(host string, test ProxyTest) (*http.Client, error) {
	proxyURL := fmt.Sprintf("%s://%s:%d", test.Protocol, host, test.Port)
	proxy, err := url.Parse(proxyURL)
	if err != nil {
		return nil, err
	}

	return &http.Client{
		Transport: &http.Transport{
			Proxy:           http.ProxyURL(proxy),
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		Timeout: time.Duration(5) * time.Second,
	}, nil
}

func getSOCKS5Client(host string, test ProxyTest) (*http.Client, error) {
	dialer, err := proxy.SOCKS5("tcp", fmt.Sprintf("%s:%d", host, test.Port), nil, proxy.Direct)
	if err != nil {
		return nil, err
	}

	return &http.Client{
		Transport: &http.Transport{
			Dial: dialer.Dial,
		},
		Timeout: time.Duration(5) * time.Second,
	}, nil
}
