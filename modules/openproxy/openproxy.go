package openproxy

import (
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/zmap/zgrab2"
	"golang.org/x/net/proxy"
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
	return &Flags{
		ProxyTests: []ProxyTest{
			{Port: 80, Protocol: "http"},
			{Port: 443, Protocol: "https"},
			{Port: 3128, Protocol: "http"},
			{Port: 8118, Protocol: "http"},
			{Port: 8388, Protocol: "socks5"},
		},
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

// validateProxyHeaders checks if response headers match expected proxy type
func validateProxyHeaders(test ProxyTest, headers map[string][]string) bool {
	server := headers["Server"]
	if len(server) == 0 {
		return false
	}

	switch test.Name {
	case "Apache HTTP", "Apache HTTPS":
		return strings.HasPrefix(server[0], "Apache/")

	case "Nginx HTTP", "Nginx HTTPS":
		return strings.HasPrefix(server[0], "nginx/")

	case "Squid":
		via := headers["Via"]
		xcache := headers["X-Cache"]
		if len(via) > 0 && strings.Contains(via[0], "squid") {
			return true
		}
		if len(xcache) > 0 && strings.Contains(xcache[0], "squid") {
			return true
		}
		return false

	case "HAProxy HTTP", "HAProxy HTTPS":
		// HAProxy typically forwards original server headers
		return true

	case "Privoxy":
		// Privoxy doesn't add distinctive headers by default
		return true

	case "Shadowsocks":
		// SOCKS proxies don't modify headers
		return true
	}
	return false
}

// Scan performs the openproxy scan
func (scanner *Scanner) Scan(target zgrab2.ScanTarget) (zgrab2.ScanStatus, interface{}, error) {
	results := make(map[string]*Results)
	targetHost := target.String()

	resultsChan := make(chan struct {
		name   string
		result *Results
	}, len(scanner.config.ProxyTests))

	for _, test := range scanner.config.ProxyTests {
		go func(test ProxyTest) {
			var client *http.Client
			var err error

			switch test.Protocol {
			case "http", "https":
				client, err = getHTTPClient(targetHost, test)
			case "socks5":
				client, err = getSOCKS5Client(targetHost, test)
			}

			if err != nil {
				for _, serverTest := range serverTypes[test.Port] {
					result := &Results{
						Name:        serverTest.Name,
						Protocol:    serverTest.Protocol,
						IsOpen:      false,
						TestResults: make(map[string]*URLTestResult),
					}
					resultsChan <- struct {
						name   string
						result *Results
					}{serverTest.Name, result}
				}
				return
			}

			urlResults := make(map[string]*URLTestResult)
			for _, testURL := range scanner.config.TestURLs {
				urlResults[testURL] = testSingleURL(client, testURL, test)
			}

			for _, serverTest := range serverTypes[test.Port] {
				result := &Results{
					Name:        serverTest.Name,
					Protocol:    serverTest.Protocol,
					IsOpen:      false,
					TestResults: make(map[string]*URLTestResult),
				}

				for url, urlResult := range urlResults {
					resultCopy := *urlResult // Create a copy of the result
					if urlResult.Success {
						resultCopy.Success = validateProxyHeaders(serverTest, urlResult.Headers)
						result.IsOpen = result.IsOpen || resultCopy.Success
					}
					result.TestResults[url] = &resultCopy
				}

				resultsChan <- struct {
					name   string
					result *Results
				}{serverTest.Name, result}
			}
		}(test)
	}

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

	urlResult.Success = false
	urlResult.StatusCode = resp.StatusCode
	urlResult.ResponseTime = time.Since(start).String()
	urlResult.ResponseSize = int64(len(body))
	urlResult.Headers = resp.Header
	urlResult.Body = body

	if validateProxyHeaders(test, resp.Header) && resp.StatusCode == 200 {
		urlResult.Success = true
	}

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
