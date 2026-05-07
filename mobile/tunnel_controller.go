package mobile

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/Diniboy1123/usque/api"
	"github.com/Diniboy1123/usque/internal"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

const (
	statusIdle         = "idle"
	statusConnecting   = "connecting"
	statusConnected    = "connected"
	statusReconnecting = "reconnecting"
)

// TunnelController manages the lifecycle of a MASQUE tunnel (SOCKS5 or VPN mode).
type TunnelController struct {
	mu          sync.Mutex
	ctx         context.Context
	cancel      context.CancelFunc
	status      string
	done        chan struct{}
	started     bool
	socksServer socksShutdowner
	tunDevice   *fdTunDevice // non-nil while VPN mode is running; closed by Stop() to unblock ReadPacket
}

type socksShutdowner interface {
	Shutdown()
}

// NewTunnelController creates a new idle TunnelController.
func NewTunnelController() *TunnelController {
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	close(done) // pre-closed so Stop() on an unstarted controller returns immediately
	return &TunnelController{
		ctx:    ctx,
		cancel: cancel,
		status: statusIdle,
		done:   done,
	}
}

// GetStatus returns the current tunnel status string.
// Possible values: idle | connecting | connected | reconnecting | error:<msg>
func (c *TunnelController) GetStatus() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.status
}

func (c *TunnelController) setStatus(s string) {
	c.mu.Lock()
	c.status = s
	c.mu.Unlock()
	logf("TunnelController status: %s", s)
}

// Stop cancels the tunnel context and waits for goroutines to exit.
func (c *TunnelController) Stop() {
	c.mu.Lock()
	cancel := c.cancel
	socks := c.socksServer
	tun := c.tunDevice
	c.mu.Unlock()

	cancel()

	if socks != nil {
		socks.Shutdown()
	}
	// Close the tun fd to unblock any ReadPacket call that is parked in a blocking read.
	if tun != nil {
		_ = tun.Close()
	}

	// Re-read done after cancel so we always wait on the channel that the
	// running goroutine will close (resetCtx may have replaced it).
	c.mu.Lock()
	done := c.done
	c.mu.Unlock()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		logf("TunnelController.Stop: timed out waiting for goroutines")
	}
	c.setStatus(statusIdle)
}

// WaitUntilStopped blocks until the tunnel goroutines have exited.
// Returns immediately if the tunnel was never started.
// Use this after StartVpn (which is non-blocking) to keep the calling thread alive.
func (c *TunnelController) WaitUntilStopped() {
	c.mu.Lock()
	done := c.done
	c.mu.Unlock()
	<-done
}

// NotifyNetworkChanged triggers a reconnect cycle by cancelling the current context.
// The supervisor goroutine will restart automatically.
func (c *TunnelController) NotifyNetworkChanged() {
	logf("TunnelController.NotifyNetworkChanged: triggering reconnect")
	c.mu.Lock()
	cancel := c.cancel
	c.mu.Unlock()
	cancel()
}

// resetCtx replaces the controller's context with a fresh cancellable one.
func (c *TunnelController) resetCtx() (context.Context, context.CancelFunc, chan struct{}) {
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	c.mu.Lock()
	c.ctx = ctx
	c.cancel = cancel
	c.done = done
	c.mu.Unlock()
	return ctx, cancel, done
}

// StartSocks starts a SOCKS5 proxy tunnel. This call blocks until Stop() is called.
//   - configJson: JSON-encoded config.Config
//   - listenAddr:  "host:port" for SOCKS5 listener (empty → "127.0.0.1:1080")
//   - dnsAddrs:    comma-separated DNS IPs (empty → Cloudflare defaults)
//   - sni:         SNI override (empty → use default)
//   - mtu:         MTU (typically 1280)
//   - useIPv6:     use IPv6 MASQUE endpoint
//   - useHTTP2:    use HTTP/2 over TCP instead of HTTP/3 over QUIC
func (c *TunnelController) StartSocks(configJson, listenAddr, dnsAddrs, sni string,
	mtu int, useIPv6, useHTTP2 bool) error {

	cfg, err := parseConfig(configJson)
	if err != nil {
		return err
	}
	tlsCfg, err := buildTLSConfig(cfg, sni)
	if err != nil {
		return err
	}
	dnsAddrList, err := parseDNSAddrs(dnsAddrs)
	if err != nil {
		return fmt.Errorf("USQUE_ERR_CONFIG: %w", err)
	}
	endpoint, err := selectEndpoint(cfg, useHTTP2, useIPv6, 443)
	if err != nil {
		return err
	}

	var localAddresses []netip.Addr
	if v4, e := netip.ParseAddr(cfg.IPv4); e == nil {
		localAddresses = append(localAddresses, v4)
	}
	if v6, e := netip.ParseAddr(cfg.IPv6); e == nil {
		localAddresses = append(localAddresses, v6)
	}

	tunDev, tunNet, err := netstack.CreateNetTUN(localAddresses, dnsAddrList, mtu)
	if err != nil {
		return fmt.Errorf("USQUE_ERR_NETWORK: failed to create virtual TUN: %w", err)
	}

	ctx, _, done := c.resetCtx()
	c.setStatus(statusConnecting)

	go func() {
		defer func() {
			_ = tunDev.Close()
			close(done)
			c.setStatus(statusIdle)
		}()

		maintainCfg := api.MaintainTunnelConfig{
			TLSConfig:       tlsCfg,
			KeepalivePeriod: 30 * time.Second,
			Endpoint:        endpoint,
			Device:          api.NewNetstackAdapter(tunDev),
			MTU:             mtu,
			ReconnectDelay:  1 * time.Second,
			AlwaysReconnect: true,
			UseHTTP2:        useHTTP2,
		}
		c.setStatus(statusConnected)
		api.MaintainTunnel(ctx, maintainCfg)
	}()

	resolver := &internal.TunnelDNSResolver{
		DNSAddrs: dnsAddrList,
		Timeout:  2 * time.Second,
		TunNet:   tunNet,
	}
	if listenAddr == "" {
		listenAddr = "127.0.0.1:1080"
	}
	server, err := internal.NewSOCKS5Server(internal.SOCKS5Config{
		Addr:       listenAddr,
		Resolver:   resolver,
		TunNet:     tunNet,
		UDPTimeout: 60 * time.Second,
	})
	if err != nil {
		c.cancel()
		return fmt.Errorf("USQUE_ERR_NETWORK: failed to create SOCKS5 server: %w", err)
	}

	c.mu.Lock()
	c.socksServer = server
	c.mu.Unlock()

	logf("SOCKS5 proxy listening on %s", listenAddr)
	err = server.Start()
	c.mu.Lock()
	c.socksServer = nil
	c.mu.Unlock()
	if err != nil {
		c.cancel()
		return fmt.Errorf("USQUE_ERR_NETWORK: SOCKS5 server error: %w", err)
	}
	return nil
}

// StartVpn starts a VPN tunnel using a pre-established TUN file descriptor.
// tunFd must be the result of VpnService.Builder.establish().detachFd().
// Non-blocking; the tunnel runs in background goroutines.
func (c *TunnelController) StartVpn(configJson string, tunFd int, dnsAddrs, sni string,
	mtu int, useIPv6, useHTTP2 bool) error {

	cfg, err := parseConfig(configJson)
	if err != nil {
		return err
	}
	tlsCfg, err := buildTLSConfig(cfg, sni)
	if err != nil {
		return err
	}
	endpoint, err := selectEndpoint(cfg, useHTTP2, useIPv6, 443)
	if err != nil {
		return err
	}
	tunDevice, err := newFdTunDevice(tunFd, mtu)
	if err != nil {
		return fmt.Errorf("USQUE_ERR_CONFIG: failed to wrap tun fd: %w", err)
	}

	ctx, _, done := c.resetCtx()
	c.mu.Lock()
	c.tunDevice = tunDevice
	c.mu.Unlock()
	c.setStatus(statusConnecting)

	go c.runVpnSupervisor(ctx, done, tlsCfg, endpoint, tunDevice, mtu, useHTTP2)
	return nil
}

// runVpnSupervisor runs MaintainTunnel in a restart loop until ctx is done.
func (c *TunnelController) runVpnSupervisor(
	outerCtx context.Context,
	done chan struct{},
	tlsCfg *tls.Config,
	endpoint net.Addr,
	tunDevice *fdTunDevice,
	mtu int,
	useHTTP2 bool,
) {
	defer func() {
		_ = tunDevice.Close()
		c.mu.Lock()
		c.tunDevice = nil
		c.mu.Unlock()
		close(done)
		c.setStatus(statusIdle)
	}()

	for {
		if outerCtx.Err() != nil {
			return
		}

		innerCtx, innerCancel := context.WithCancel(outerCtx)

		maintainCfg := api.MaintainTunnelConfig{
			TLSConfig:       tlsCfg,
			KeepalivePeriod: 30 * time.Second,
			Endpoint:        endpoint,
			Device:          tunDevice,
			MTU:             mtu,
			ReconnectDelay:  1 * time.Second,
			AlwaysReconnect: true,
			UseHTTP2:        useHTTP2,
		}

		c.setStatus(statusConnected)
		api.MaintainTunnel(innerCtx, maintainCfg)
		innerCancel()

		if outerCtx.Err() != nil {
			return
		}

		c.setStatus(statusReconnecting)
		logf("VPN supervisor: reconnecting")
		time.Sleep(500 * time.Millisecond)
	}
}
