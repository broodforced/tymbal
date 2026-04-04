// pkg/config/config.go — runtime configuration

package config

import (
	"net"
	"os"
	"runtime"
	"time"
)

type Config struct {
	Target    string
	Mode      string
	Threads   int
	Timeout   time.Duration
	OutputDir string
	Verbose   bool
	Scope     []string
}

func Default(target, mode string) *Config {
	threads := 10
	if runtime.NumCPU() < 2 {
		threads = 5
	}

	out := "."
	if dir, err := os.Getwd(); err == nil {
		out = dir
	}

	return &Config{
		Target:    target,
		Mode:      mode,
		Threads:   threads,
		Timeout:   10 * time.Second,
		OutputDir: out,
		Verbose:   false,
	}
}

func (c *Config) IsConstrained() bool {
	mem := runtime.GOMAXPROCS(0)
	return mem <= 2
}

func CanResolve(host string) bool {
	_, err := net.LookupHost(host)
	return err == nil
}
