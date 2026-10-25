// pkg/recon/ports.go — lightweight port scanning

package recon

import (
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/broodforced/tymbal/pkg/config"
	"github.com/broodforced/tymbal/pkg/output"
)

var commonPorts = []int{
	21, 22, 23, 25, 53, 80, 110, 143, 443, 445,
	993, 995, 1433, 1521, 2082, 2083, 2086, 2087,
	3000, 3306, 3389, 4443, 5432, 5900, 6379,
	8000, 8008, 8080, 8443, 8888, 9090, 9200, 9443,
	27017,
}

func ScanPorts(cfg *config.Config, result *output.ScanResult) {
	sem := make(chan struct{}, cfg.Threads)
	var wg sync.WaitGroup

	for i := range result.Recon.Assets {
		asset := &result.Recon.Assets[i]
		ip := asset.IP
		if ip == "" {
			ip = asset.Host
		}

		var mu sync.Mutex
		var openPorts []int

		for _, port := range commonPorts {
			wg.Add(1)
			sem <- struct{}{}
			go func(p int) {
				defer wg.Done()
				defer func() { <-sem }()
				addr := net.JoinHostPort(ip, strconv.Itoa(p))
				conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
				if err == nil {
					conn.Close()
					mu.Lock()
					openPorts = append(openPorts, p)
					mu.Unlock()
				}
			}(port)
		}

		wg.Wait()

		existing := make(map[int]bool)
		for _, p := range asset.Ports {
			existing[p] = true
		}
		for _, p := range openPorts {
			if !existing[p] {
				asset.Ports = append(asset.Ports, p)
			}
		}
	}
}
