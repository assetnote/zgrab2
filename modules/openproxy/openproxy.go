package openproxy

import (
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
			{"Nginx HTTP", 80, "http"},
			{"Nginx HTTPS", 443, "https"},
			{"Apache HTTP", 80, "http"},
			{"Apache HTTPS", 443, "https"},
			{"Squid", 3128, "http"},
			{"Privoxy", 8118, "http"},
			{"Shadowsocks", 8388, "socks5"},

			//{"HAProxy HTTP", 8083, "http"}, hard to fingerprint (no distinctive header)
			//{"HAProxy HTTPS", 443, "https"},
			//{"V2Ray HTTP", 10086, "http"}, TODO: need to configure local server
			//{"Dante SOCKS", 1080, "socks5"}, // TODO: need to configure local server
		},
		TestURLs: []string{
			"http://example.com",
			"https://example.com",
		},
	}
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
	switch test.Name {
	case "Apache HTTP", "Apache HTTPS":
		server := headers["Server"]
		if len(server) > 0 {
			return strings.HasPrefix(server[0], "Apache/")
		}

	case "Nginx HTTP", "Nginx HTTPS":
		server := headers["Server"]
		if len(server) > 0 {
			return strings.HasPrefix(server[0], "nginx/")
		}

	case "Squid":
		via := headers["Via"]
		xcache := headers["X-Cache"]
		if len(via) > 0 && strings.Contains(via[0], "squid") {
			return true
		}
		if len(xcache) > 0 && strings.Contains(xcache[0], "squid") {
			return true
		}

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

	// Create channel for results
	resultsChan := make(chan struct {
		name   string
		result *Results
	}, len(scanner.config.ProxyTests))

	// Launch goroutine for each test
	for _, test := range scanner.config.ProxyTests {
		go func(test ProxyTest) {
			result := &Results{
				Name:        test.Name,
				Protocol:    test.Protocol,
				TestResults: make(map[string]*URLTestResult),
			}

			var client *http.Client
			var err error

			switch test.Protocol {
			case "http", "https":
				client, err = getHTTPClient(targetHost, test)
			case "socks5":
				client, err = getSOCKS5Client(targetHost, test)
			default:
				resultsChan <- struct {
					name   string
					result *Results
				}{test.Name, result}
				return
			}

			if err != nil {
				result.IsOpen = false
				resultsChan <- struct {
					name   string
					result *Results
				}{test.Name, result}
				return
			}

			// Test URLs concurrently too
			urlChan := make(chan struct {
				url    string
				result *URLTestResult
			}, len(scanner.config.TestURLs))

			for _, testURL := range scanner.config.TestURLs {
				go func(url string) {
					urlResult := testSingleURL(client, url, test)
					urlChan <- struct {
						url    string
						result *URLTestResult
					}{url, urlResult}
				}(testURL)
			}

			// Collect URL results
			for i := 0; i < len(scanner.config.TestURLs); i++ {
				urlRes := <-urlChan
				result.TestResults[urlRes.url] = urlRes.result
				if urlRes.result.Success {
					result.IsOpen = true
				}
			}

			resultsChan <- struct {
				name   string
				result *Results
			}{test.Name, result}
		}(test)
	}

	// Collect all results
	for i := 0; i < len(scanner.config.ProxyTests); i++ {
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

	req.Header.Set("User-Agent", "zgrab2/openproxy")
	req.Header.Set("X-Test-Header", "true")

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

	urlResult.Success = true
	urlResult.StatusCode = resp.StatusCode
	urlResult.ResponseTime = time.Since(start).String()
	urlResult.ResponseSize = int64(len(body))
	urlResult.Headers = resp.Header
	urlResult.Body = body

	if !validateProxyHeaders(test, resp.Header) {
		urlResult.Success = true
		urlResult.Error = "could not gaurantee proxy type; headers did not match fingerprint but got body"
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
			Proxy: http.ProxyURL(proxy),
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
