// pkg/output/schema.go — data contract shared with cicada

package output

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"time"
)

type Evidence struct {
	Request    string `json:"request"`
	Response   string `json:"response"`
	Screenshot string `json:"screenshot"`
	Timestamp  string `json:"timestamp"`
}

type Finding struct {
	Title      string   `json:"title"`
	Severity   string   `json:"severity"`
	Category   string   `json:"category"`
	Target     string   `json:"target"`
	Detail     string   `json:"detail"`
	Evidence   Evidence `json:"evidence"`
	Tool       string   `json:"tool"`
	Confidence string   `json:"confidence"`
	Reference  string   `json:"reference"`
	FindingID  string   `json:"finding_id"`
}

func NewFinding(title, severity, category, target, detail, tool string) Finding {
	raw := title + target + detail
	hash := sha256.Sum256([]byte(raw))
	return Finding{
		Title:      title,
		Severity:   severity,
		Category:   category,
		Target:     target,
		Detail:     detail,
		Tool:       tool,
		Confidence: "medium",
		FindingID:  fmt.Sprintf("%x", hash[:6]),
		Evidence: Evidence{
			Timestamp: time.Now().UTC().Format(time.RFC3339),
		},
	}
}

type Asset struct {
	Host          string   `json:"host"`
	IP            string   `json:"ip"`
	Ports         []int    `json:"ports"`
	Technologies  []string `json:"technologies"`
	StatusCode    int      `json:"status_code"`
	ContentLength int      `json:"content_length"`
	Title         string   `json:"title"`
	CDN           bool     `json:"cdn"`
	Source        string   `json:"source"`
}

type ReconData struct {
	Target     string            `json:"target"`
	Subdomains []string          `json:"subdomains"`
	Assets     []Asset           `json:"assets"`
	Endpoints  []string          `json:"endpoints"`
	JSFiles    []string          `json:"js_files"`
	Parameters []string          `json:"parameters"`
	Secrets    []json.RawMessage `json:"secrets"`
	Timestamp  string            `json:"timestamp"`
}

type ScanResult struct {
	Target   string    `json:"target"`
	Tool     string    `json:"tool"`
	Version  string    `json:"version"`
	Recon    ReconData `json:"recon"`
	Findings []Finding `json:"findings"`
	Started  string    `json:"started"`
	Finished string    `json:"finished"`
	Mode     string    `json:"mode"`
	Scope    []string  `json:"scope"`
}

func NewScanResult(target, mode string) *ScanResult {
	now := time.Now().UTC().Format(time.RFC3339)
	return &ScanResult{
		Target:  target,
		Tool:    "tymbal",
		Version: "0.1.0",
		Mode:    mode,
		Started: now,
		Recon: ReconData{
			Target:     target,
			Subdomains: []string{},
			Assets:     []Asset{},
			Endpoints:  []string{},
			JSFiles:    []string{},
			Parameters: []string{},
			Secrets:    []json.RawMessage{},
			Timestamp:  now,
		},
		Findings: []Finding{},
		Scope:    []string{},
	}
}

func (s *ScanResult) Finish() {
	s.Finished = time.Now().UTC().Format(time.RFC3339)
}

func (s *ScanResult) AddFinding(f Finding) {
	for _, existing := range s.Findings {
		if existing.FindingID == f.FindingID {
			return
		}
	}
	s.Findings = append(s.Findings, f)
}

func (s *ScanResult) AddSubdomain(sub string) {
	for _, existing := range s.Recon.Subdomains {
		if existing == sub {
			return
		}
	}
	s.Recon.Subdomains = append(s.Recon.Subdomains, sub)
}

func (s *ScanResult) AddAsset(a Asset) {
	for _, existing := range s.Recon.Assets {
		if existing.Host == a.Host {
			return
		}
	}
	s.Recon.Assets = append(s.Recon.Assets, a)
}

func (s *ScanResult) AddEndpoint(ep string) {
	for _, existing := range s.Recon.Endpoints {
		if existing == ep {
			return
		}
	}
	s.Recon.Endpoints = append(s.Recon.Endpoints, ep)
}

func (s *ScanResult) WriteJSON(path string) error {
	data, err := json.MarshalIndent(s, "", "\t")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

func (s *ScanResult) Summary() string {
	sev := map[string]int{"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
	for _, f := range s.Findings {
		sev[f.Severity]++
	}
	parts := ""
	for _, k := range []string{"critical", "high", "medium", "low", "info"} {
		if sev[k] > 0 {
			if parts != "" {
				parts += ", "
			}
			parts += fmt.Sprintf("%d %s", sev[k], k)
		}
	}
	if parts == "" {
		parts = "none"
	}
	return fmt.Sprintf("%d subdomains | %d live | %d endpoints | findings: %s",
		len(s.Recon.Subdomains), len(s.Recon.Assets), len(s.Recon.Endpoints), parts)
}
