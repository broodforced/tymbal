// pkg/probe/checks.go — basic security checks

package probe

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/zblauser/tymbal/pkg/config"
	"github.com/zblauser/tymbal/pkg/output"
)

func RunChecks(cfg *config.Config, result *output.ScanResult) {
	var wg sync.WaitGroup
	var mu sync.Mutex
	sem := make(chan struct{}, cfg.Threads)

	client := &http.Client{
		Timeout: cfg.Timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	for _, asset := range result.Recon.Assets {
		if asset.StatusCode == 0 || asset.CDN {
			continue
		}
		scheme := "https"
		if asset.StatusCode > 0 {
			for _, p := range asset.Ports {
				if p == 80 {
					scheme = "http"
					break
				}
			}
		}
		url := fmt.Sprintf("%s://%s", scheme, asset.Host)

		wg.Add(1)
		sem <- struct{}{}
		go func(u string) {
			defer wg.Done()
			defer func() { <-sem }()

			findings := checkTarget(client, u)
			mu.Lock()
			for _, f := range findings {
				result.AddFinding(f)
			}
			mu.Unlock()
		}(url)
	}
	wg.Wait()
}

func checkTarget(client *http.Client, target string) []output.Finding {
	var findings []output.Finding

	findings = append(findings, checkHeaders(client, target)...)
	findings = append(findings, checkCORS(client, target)...)

	return findings
}

func checkHeaders(client *http.Client, target string) []output.Finding {
	var findings []output.Finding

	req, err := http.NewRequest("GET", target, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("User-Agent", "Tymbal/0.1.0")

	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	io.ReadAll(io.LimitReader(resp.Body, 1024))
	resp.Body.Close()

	checks := map[string]struct {
		title    string
		severity string
	}{
		"Strict-Transport-Security": {"Missing HSTS Header", "medium"},
		"X-Content-Type-Options":    {"Missing X-Content-Type-Options", "low"},
		"X-Frame-Options":           {"Missing X-Frame-Options", "low"},
		"Content-Security-Policy":   {"Missing Content-Security-Policy", "low"},
	}

	for header, info := range checks {
		if resp.Header.Get(header) == "" {
			findings = append(findings, output.NewFinding(
				info.title,
				info.severity,
				"security-headers",
				target,
				fmt.Sprintf("%s header is not set", header),
				"tymbal-checks",
			))
		}
	}

	server := resp.Header.Get("Server")
	if server != "" {
		findings = append(findings, output.NewFinding(
			fmt.Sprintf("Server Disclosure: %s", server),
			"info",
			"information-disclosure",
			target,
			fmt.Sprintf("Server: %s", server),
			"tymbal-checks",
		))
	}

	powered := resp.Header.Get("X-Powered-By")
	if powered != "" {
		findings = append(findings, output.NewFinding(
			fmt.Sprintf("Tech Disclosure: %s", powered),
			"low",
			"information-disclosure",
			target,
			fmt.Sprintf("X-Powered-By: %s", powered),
			"tymbal-checks",
		))
	}

	return findings
}

func checkCORS(client *http.Client, target string) []output.Finding {
	var findings []output.Finding

	origins := []string{"https://evil.com", "null"}

	for _, origin := range origins {
		req, err := http.NewRequest("GET", target, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", "Tymbal/0.1.0")
		req.Header.Set("Origin", origin)

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		io.ReadAll(io.LimitReader(resp.Body, 1024))
		resp.Body.Close()

		acao := resp.Header.Get("Access-Control-Allow-Origin")
		acac := resp.Header.Get("Access-Control-Allow-Credentials")

		if acao == "*" {
			f := output.NewFinding(
				"CORS Wildcard Origin",
				"medium",
				"cors-misconfiguration",
				target,
				fmt.Sprintf("ACAO: * (tested with Origin: %s)", origin),
				"tymbal-checks",
			)
			f.Evidence = output.Evidence{
				Request:  fmt.Sprintf("Origin: %s", origin),
				Response: fmt.Sprintf("Access-Control-Allow-Origin: %s", acao),
			}
			findings = append(findings, f)
			break
		}

		if acao == origin && origin != "null" {
			sev := "medium"
			if strings.EqualFold(acac, "true") {
				sev = "high"
			}
			f := output.NewFinding(
				"CORS Origin Reflection",
				sev,
				"cors-misconfiguration",
				target,
				fmt.Sprintf("Origin %s reflected. Credentials: %s", origin, acac),
				"tymbal-checks",
			)
			f.Evidence = output.Evidence{
				Request:  fmt.Sprintf("Origin: %s", origin),
				Response: fmt.Sprintf("ACAO: %s\nACAC: %s", acao, acac),
			}
			findings = append(findings, f)
			break
		}

		if acao == "null" && origin == "null" {
			f := output.NewFinding(
				"CORS Null Origin Allowed",
				"medium",
				"cors-misconfiguration",
				target,
				"null origin reflected, exploitable via sandboxed iframe",
				"tymbal-checks",
			)
			findings = append(findings, f)
			break
		}
	}

	return findings
}

func fetch(client *http.Client, url string, headers map[string]string, timeout time.Duration) (*http.Response, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Tymbal/0.1.0")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	return client.Do(req)
}
