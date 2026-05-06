// dns_init.go overrides net.DefaultResolver for Android gomobile builds.
// The original dns_android.go uses //go:build android && !cgo which is excluded
// by gomobile (which forces cgo). This file replicates the DNS override without
// the !cgo constraint so it is included in the .aar build.
package mobile

import (
	"context"
	"net"
	"sync"
	"time"
)

func init() {
	var dialer net.Dialer
	dnsServers := []string{
		"[2606:4700:4700::1111]:53",
		"[2606:4700:4700::1001]:53",
		"1.1.1.1:53",
		"1.0.0.1:53",
	}

	net.DefaultResolver = &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			ctx, cancel := context.WithCancel(ctx)
			defer cancel()

			var wg sync.WaitGroup
			result := make(chan net.Conn, 1)
			errChan := make(chan error, len(dnsServers))

			for _, ip := range dnsServers {
				wg.Add(1)
				go func(ip string) {
					defer wg.Done()
					conn, err := dialer.DialContext(ctx, "udp", ip)
					if err == nil {
						select {
						case result <- conn:
							cancel()
						default:
							_ = conn.Close()
						}
					} else {
						errChan <- err
					}
				}(ip)
			}

			go func() {
				wg.Wait()
				close(result)
			}()

			select {
			case conn, ok := <-result:
				if ok && conn != nil {
					return conn, nil
				}
				return nil, net.ErrClosed
			case <-time.After(2 * time.Second):
				return nil, net.ErrClosed
			}
		},
	}
}
