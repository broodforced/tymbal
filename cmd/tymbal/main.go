// cmd/tymbal/main.go — lightweight recon tool

package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/broodforced/tymbal/pkg/config"
	"github.com/broodforced/tymbal/pkg/output"
	"github.com/broodforced/tymbal/pkg/probe"
	"github.com/broodforced/tymbal/pkg/recon"
)

const version = "0.1.0"

const banner = `
  ▀▄▀▄▀▄ tymbal ▄▀▄▀▄▀
`

func main() {
	var (
		target    string
		mode      string
		threads   int
		timeout   int
		outputDir string
		verbose   bool
		showVer   bool
	)

	flag.StringVar(&mode, "m", "normal", "scan mode: fast|normal|deep")
	flag.IntVar(&threads, "t", 10, "thread count")
	flag.IntVar(&timeout, "T", 10, "timeout per request (seconds)")
	flag.StringVar(&outputDir, "o", ".", "output directory")
	flag.BoolVar(&verbose, "v", false, "verbose output")
	flag.BoolVar(&showVer, "V", false, "show version")
	flag.Parse()

	if showVer {
		fmt.Printf("tymbal v%s %s/%s\n", version, runtime.GOOS, runtime.GOARCH)
		return
	}

	args := flag.Args()
	if len(args) < 1 {
		fmt.Print(banner)
		fmt.Printf("  tymbal v%s — lightweight recon for cicada\n\n", version)
		fmt.Println("  usage: tymbal [options] <target>")
		fmt.Println()
		fmt.Println("  options:")
		fmt.Println("    -m string   mode: fast|normal|deep (default normal)")
		fmt.Println("    -t int      threads (default 10)")
		fmt.Println("    -T int      timeout seconds (default 10)")
		fmt.Println("    -o string   output directory (default .)")
		fmt.Println("    -v          verbose")
		fmt.Println("    -V          version")
		fmt.Println()
		fmt.Println("  examples:")
		fmt.Println("    tymbal example.com")
		fmt.Println("    tymbal -m deep example.com")
		fmt.Println("    tymbal -m fast -t 5 example.com")
		fmt.Println()
		fmt.Println("  feed results to cicada:")
		fmt.Println("    cicada scan example.com --tymbal tymbal_example_*.json")
		fmt.Println()
		os.Exit(0)
	}

	target = args[0]

	fmt.Print(banner)
	fmt.Printf("  target: %s\n", target)
	fmt.Printf("  mode:   %s\n", mode)
	fmt.Printf("  arch:   %s/%s\n\n", runtime.GOOS, runtime.GOARCH)

	cfg := config.Default(target, mode)
	cfg.Threads = threads
	cfg.Timeout = time.Duration(timeout) * time.Second
	cfg.OutputDir = outputDir
	cfg.Verbose = verbose

	result := output.NewScanResult(target, mode)

	phase("1", "subdomain enumeration")
	recon.EnumSubdomains(cfg, result)
	status(fmt.Sprintf("found %d subdomains", len(result.Recon.Subdomains)))

	phase("2", "http probing")
	recon.ProbeHosts(cfg, result)
	live := 0
	for _, a := range result.Recon.Assets {
		if a.StatusCode > 0 {
			live++
		}
	}
	status(fmt.Sprintf("%d live hosts", live))

	if mode == "normal" || mode == "deep" {
		phase("3", "port scanning")
		recon.ScanPorts(cfg, result)
		totalPorts := 0
		for _, a := range result.Recon.Assets {
			totalPorts += len(a.Ports)
		}
		status(fmt.Sprintf("%d open ports", totalPorts))
	}

	if mode == "deep" {
		phase("4", "security checks")
		probe.RunChecks(cfg, result)
		status(fmt.Sprintf("%d findings", len(result.Findings)))
	}

	result.Finish()

	domain := strings.ReplaceAll(target, "https://", "")
	domain = strings.ReplaceAll(domain, "http://", "")
	domain = strings.ReplaceAll(domain, "/", "_")
	domain = strings.Split(domain, ":")[0]
	ts := time.Now().Format("20060102_150405")
	filename := fmt.Sprintf("tymbal_%s_%s.json", domain, ts)
	outPath := filepath.Join(cfg.OutputDir, filename)

	if err := result.WriteJSON(outPath); err != nil {
		fmt.Fprintf(os.Stderr, "  [!] error writing output: %s\n", err)
		os.Exit(1)
	}

	fmt.Printf("\n  %s\n", strings.Repeat("─", 40))
	fmt.Printf("  %s\n", result.Summary())
	fmt.Printf("  output → %s\n", outPath)
	fmt.Printf("  %s\n\n", strings.Repeat("─", 40))
	fmt.Println("  feed to cicada:")
	fmt.Printf("    cicada scan %s --tymbal %s\n\n", target, outPath)
}

func phase(n, name string) {
	fmt.Printf("  [%s] %s\n", n, strings.ToUpper(name))
}

func status(msg string) {
	fmt.Printf("    → %s\n", msg)
}
