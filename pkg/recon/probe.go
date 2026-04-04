// pkg/recon/probe.go — live host detection via HTTP

package recon

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/zblauser/tymbal/pkg/config"
	"github.com/zblauser/tymbal/pkg/output"
)

var titleRe = regexp.MustCompile(`(?i)<title[^>]*>([^<]+)</title>`)

func ProbeHosts(cfg *config.Config, result *output.ScanResult) {
	subs := result.Recon.Subdomains
	if len(subs) == 0 {
		subs = []string{extractDomain(cfg.Target)}
	}

	sem := make(chan struct{}, cfg.Threads)
	var wg sync.WaitGroup
	var mu sync.Mutex

	client := &http.Client{
		Timeout: cfg.Timeout,
		Transport: &http.Transport{
			TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
			DisableKeepAlives:  true,
			MaxIdleConns:       cfg.Threads,
			IdleConnTimeout:    5 * time.Second,
			ForceAttemptHTTP2:  false,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

	for _, sub := range subs {
		wg.Add(1)
		sem <- struct{}{}
		go func(host string) {
			defer wg.Done()
			defer func() { <-sem }()

			asset := probeHost(client, host)
			if asset != nil {
				mu.Lock()
				result.AddAsset(*asset)
				mu.Unlock()
			}
		}(sub)
	}
	wg.Wait()
}

func probeHost(client *http.Client, host string) *output.Asset {
	for _, scheme := range []string{"https", "http"} {
		url := fmt.Sprintf("%s://%s", scheme, host)
		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", "Tymbal/0.1.0")

		resp, err := client.Do(req)
		if err != nil {
			continue
		}

		body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
		resp.Body.Close()

		title := ""
		if m := titleRe.FindSubmatch(body); len(m) > 1 {
			title = strings.TrimSpace(string(m[1]))
		}

		ip := resolveIP(host)
		ports := []int{}
		if scheme == "https" {
			ports = append(ports, 443)
		} else {
			ports = append(ports, 80)
		}

		server := resp.Header.Get("Server")
		powered := resp.Header.Get("X-Powered-By")
		techs := []string{}
		if server != "" {
			techs = append(techs, server)
		}
		if powered != "" {
			techs = append(techs, powered)
		}

		return &output.Asset{
			Host:          host,
			IP:            ip,
			Ports:         ports,
			Technologies:  techs,
			StatusCode:    resp.StatusCode,
			ContentLength: len(body),
			Title:         title,
			CDN:           isCDN(resp.Header, ip),
			Source:         "tymbal",
		}
	}
	return nil
}

func resolveIP(host string) string {
	ips, err := net.LookupHost(host)
	if err != nil || len(ips) == 0 {
		return ""
	}
	return ips[0]
}

func isCDN(headers http.Header, ip string) bool {
	cdnHeaders := []string{
		"cf-ray", "x-cdn", "x-cache", "x-amz-cf-id",
		"x-akamai-transformed", "x-fastly-request-id",
	}
	for _, h := range cdnHeaders {
		if headers.Get(h) != "" {
			return true
		}
	}
	server := strings.ToLower(headers.Get("Server"))
	cdnServers := []string{"cloudflare", "cloudfront", "akamai", "fastly", "varnish"}
	for _, cdn := range cdnServers {
		if strings.Contains(server, cdn) {
			return true
		}
	}
	return false
}
