// pkg/recon/subdomains.go — subdomain discovery without external tools

package recon

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/broodforced/tymbal/pkg/config"
	"github.com/broodforced/tymbal/pkg/output"
)

var miniWordlist = []string{
	"www", "mail", "ftp", "smtp", "pop", "ns1", "ns2",
	"webmail", "admin", "api", "dev", "staging", "test",
	"beta", "app", "m", "mobile", "cdn", "static",
	"assets", "img", "images", "media", "docs", "wiki",
	"blog", "shop", "store", "portal", "vpn", "remote",
	"git", "svn", "jenkins", "ci", "grafana", "monitor",
	"status", "auth", "sso", "login", "oauth", "id",
	"db", "mysql", "postgres", "redis", "elastic", "kibana",
	"internal", "intranet", "corp", "office", "jira",
	"confluence", "slack", "teams", "meet", "calendar",
	"sandbox", "demo", "preview", "stage", "uat", "qa",
	"prod", "production", "edge", "gateway", "proxy",
	"backup", "old", "new", "v2", "v3", "next",
}

type crtEntry struct {
	NameValue string `json:"name_value"`
}

func EnumSubdomains(cfg *config.Config, result *output.ScanResult) {
	domain := extractDomain(cfg.Target)
	found := &sync.Map{}

	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		crtSubs := queryCrtSh(domain, cfg.Timeout)
		for _, s := range crtSubs {
			found.Store(s, true)
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		dnsSubs := dnsWordlistBrute(domain, cfg.Threads)
		for _, s := range dnsSubs {
			found.Store(s, true)
		}
	}()

	wg.Wait()

	found.Range(func(key, _ any) bool {
		sub := key.(string)
		result.AddSubdomain(sub)
		return true
	})

	if len(result.Recon.Subdomains) == 0 {
		result.AddSubdomain(domain)
	}
}

func queryCrtSh(domain string, timeout time.Duration) []string {
	client := &http.Client{Timeout: timeout}
	url := fmt.Sprintf("https://crt.sh/?q=%%25.%s&output=json", domain)

	resp, err := client.Get(url)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 2*1024*1024))
	if err != nil {
		return nil
	}

	var entries []crtEntry
	if err := json.Unmarshal(body, &entries); err != nil {
		return nil
	}

	seen := make(map[string]bool)
	var subs []string
	for _, e := range entries {
		for _, name := range strings.Split(e.NameValue, "\n") {
			name = strings.TrimSpace(strings.ToLower(name))
			name = strings.TrimPrefix(name, "*.")
			if name == "" || seen[name] {
				continue
			}
			if strings.HasSuffix(name, "."+domain) || name == domain {
				seen[name] = true
				subs = append(subs, name)
			}
		}
	}
	return subs
}

func dnsWordlistBrute(domain string, threads int) []string {
	var mu sync.Mutex
	var results []string
	sem := make(chan struct{}, threads)
	var wg sync.WaitGroup

	for _, word := range miniWordlist {
		wg.Add(1)
		sem <- struct{}{}
		go func(w string) {
			defer wg.Done()
			defer func() { <-sem }()
			host := w + "." + domain
			if _, err := net.LookupHost(host); err == nil {
				mu.Lock()
				results = append(results, host)
				mu.Unlock()
			}
		}(word)
	}
	wg.Wait()
	return results
}

func extractDomain(target string) string {
	t := target
	for _, prefix := range []string{"https://", "http://"} {
		t = strings.TrimPrefix(t, prefix)
	}
	t = strings.Split(t, "/")[0]
	t = strings.Split(t, ":")[0]
	return strings.ToLower(t)
}
