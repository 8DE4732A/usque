package mobile

// Tun2Socks bridges an Android VpnService TUN fd to an upstream SOCKS5 proxy.
//
// Two modes:
//
//  1. Direct (upstreamSocks5 == ""):
//     Android traffic → tun2socks → usque SOCKS5 (127.0.0.1:1080) → WARP → Internet
//
//  2. Two-hop (upstreamSocks5 != ""):
//     Android traffic → tun2socks → usque SOCKS5 (127.0.0.1:1080) → WARP → upstream SOCKS5 → Internet
//     Each flow: CONNECT to usque, then CONNECT-through to upstream, then CONNECT to final dst.
//
// In both cases tun2socks dials 127.0.0.1 (loopback) first, which never enters
// the VPN TUN device, so no protect() call is required.

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"sync"
	"time"

	gvbuffer "gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

// Tun2SocksController manages the lifecycle of a tun-to-socks5 tunnel.
type Tun2SocksController struct {
	mu     sync.Mutex
	cancel context.CancelFunc
	done   chan struct{}
}

// NewTun2SocksController returns an idle controller.
func NewTun2SocksController() *Tun2SocksController {
	_, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	close(done)
	return &Tun2SocksController{cancel: cancel, done: done}
}

// StartFull wires the Android TUN fd to an upstream SOCKS5 proxy.
//
//   - tunFd:           detached fd from VpnService.Builder.establish().detachFd()
//   - localIPv4:       device's VPN IPv4 (e.g. "100.96.0.6")
//   - localIPv6:       device's VPN IPv6 (may be empty)
//   - dnsAddrs:        comma-separated DNS servers (e.g. "1.1.1.1,1.0.0.1")
//   - firstHop:        local SOCKS5 proxy address (usque, e.g. "127.0.0.1:1080")
//   - upstreamSocks5:  remote upstream SOCKS5 address reachable via firstHop
//     (e.g. "100.96.0.1:1080"); empty means firstHop is the exit proxy
//   - mtu:             TUN MTU
//
// Non-blocking.  Call WaitUntilStopped to block until the tunnel exits.
func (c *Tun2SocksController) StartFull(tunFd int, localIPv4, localIPv6, dnsAddrs, firstHop, upstreamSocks5 string, mtu int) error {
	var localAddrs []netip.Addr
	if localIPv4 != "" {
		a, err := netip.ParseAddr(localIPv4)
		if err != nil {
			return fmt.Errorf("tun2socks: invalid localIPv4 %q: %w", localIPv4, err)
		}
		localAddrs = append(localAddrs, a)
	}
	if localIPv6 != "" {
		a, err := netip.ParseAddr(localIPv6)
		if err != nil {
			return fmt.Errorf("tun2socks: invalid localIPv6 %q: %w", localIPv6, err)
		}
		localAddrs = append(localAddrs, a)
	}
	if len(localAddrs) == 0 {
		return fmt.Errorf("tun2socks: at least one local address required")
	}
	if _, err := net.ResolveTCPAddr("tcp", firstHop); err != nil {
		return fmt.Errorf("tun2socks: invalid firstHop %q: %w", firstHop, err)
	}
	if upstreamSocks5 != "" {
		if _, err := net.ResolveTCPAddr("tcp", upstreamSocks5); err != nil {
			return fmt.Errorf("tun2socks: invalid upstreamSocks5 %q: %w", upstreamSocks5, err)
		}
	}

	fdDev, err := newFdTunDevice(tunFd, mtu)
	if err != nil {
		return fmt.Errorf("tun2socks: wrap fd: %w", err)
	}

	gStack, ep, err := newGvisorStack(localAddrs, mtu)
	if err != nil {
		_ = fdDev.Close()
		return fmt.Errorf("tun2socks: gvisor stack: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})

	c.mu.Lock()
	c.cancel = cancel
	c.done = done
	c.mu.Unlock()

	go func() {
		defer func() {
			ep.close()
			_ = fdDev.Close()
			gStack.Destroy()
			cancel()
			close(done)
		}()
		pumpTunFull(ctx, fdDev, ep, gStack, firstHop, upstreamSocks5, mtu)
	}()

	return nil
}

// Stop cancels the tunnel and waits up to 5 s for goroutines to exit.
func (c *Tun2SocksController) Stop() {
	c.mu.Lock()
	cancel := c.cancel
	done := c.done
	c.mu.Unlock()

	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		log.Println("Tun2SocksController.Stop: timed out")
	}
}

// WaitUntilStopped blocks until the tunnel goroutines exit.
func (c *Tun2SocksController) WaitUntilStopped() {
	c.mu.Lock()
	done := c.done
	c.mu.Unlock()
	<-done
}

// ────────────────────────────────────────────────────────────────────────────
// Core pump
// ────────────────────────────────────────────────────────────────────────────

func pumpTunFull(ctx context.Context, fdDev *fdTunDevice, ep *channelEndpoint, gStack *stack.Stack, firstHop, upstreamSocks5 string, mtu int) {
	logf("tun2socks: pump started, firstHop=%s upstream=%q", firstHop, upstreamSocks5)
	tcpFwd := tcp.NewForwarder(gStack, 0, 1024, func(r *tcp.ForwarderRequest) {
		go handleTCPRequest(ctx, r, firstHop, upstreamSocks5)
	})
	gStack.SetTransportProtocolHandler(tcp.ProtocolNumber, tcpFwd.HandlePacket)

	udpFwd := udp.NewForwarder(gStack, func(r *udp.ForwarderRequest) bool {
		go handleUDPRequest(ctx, r, firstHop, upstreamSocks5)
		return true
	})
	gStack.SetTransportProtocolHandler(udp.ProtocolNumber, udpFwd.HandlePacket)

	// fd → gvisor
	go func() {
		buf := make([]byte, mtu+4)
		pktCount := 0
		for {
			if ctx.Err() != nil {
				return
			}
			n, err := fdDev.ReadPacket(buf)
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				logf("tun2socks: fd read error: %v", err)
				return
			}
			pktCount++
			if pktCount <= 5 || pktCount%100 == 0 {
				logf("tun2socks: fd→gvisor pkt #%d len=%d", pktCount, n)
			}
			ep.InjectInbound(buf[:n])
		}
	}()

	// gvisor → fd
	for {
		if ctx.Err() != nil {
			return
		}
		pkt := ep.ReadOutbound()
		if pkt == nil {
			time.Sleep(100 * time.Microsecond)
			continue
		}
		if err := fdDev.WritePacket(pkt); err != nil {
			if ctx.Err() != nil {
				return
			}
			log.Printf("tun2socks: fd write: %v", err)
		}
	}
}

// ────────────────────────────────────────────────────────────────────────────
// TCP / UDP handlers
// ────────────────────────────────────────────────────────────────────────────

func handleTCPRequest(ctx context.Context, r *tcp.ForwarderRequest, firstHop, upstreamSocks5 string) {
	dst := forwarderReqDst(r)
	logf("tun2socks: TCP %s", dst)

	var wq waiter.Queue
	ep, tcpErr := r.CreateEndpoint(&wq)
	if tcpErr != nil {
		r.Complete(true)
		return
	}
	r.Complete(false)
	defer ep.Close()

	inConn := gonet.NewTCPConn(&wq, ep)
	defer func() { _ = inConn.Close() }()

	upConn, err := dialTCP(ctx, firstHop, upstreamSocks5, dst)
	if err != nil {
		logf("tun2socks: dial %s: %v", dst, err)
		return
	}
	logf("tun2socks: TCP %s connected", dst)
	defer func() { _ = upConn.Close() }()

	relayTCP(inConn, upConn)
}

func handleUDPRequest(ctx context.Context, r *udp.ForwarderRequest, firstHop, upstreamSocks5 string) {
	dst := forwarderReqDstUDP(r)
	logf("tun2socks: UDP %s", dst)

	var wq waiter.Queue
	ep, tcpErr := r.CreateEndpoint(&wq)
	if tcpErr != nil {
		return
	}
	defer ep.Close()

	udpConn := gonet.NewUDPConn(&wq, ep)
	defer func() { _ = udpConn.Close() }()

	buf := make([]byte, 65535)
	n, _, err := udpConn.ReadFrom(buf)
	if err != nil {
		return
	}
	payload := buf[:n]

	// When an upstream proxy is configured, UDP ASSOCIATE relay addresses returned
	// by the upstream are unreachable from here (they point to the upstream's
	// loopback). Use DNS-over-TCP through the SOCKS5 CONNECT chain instead.
	if upstreamSocks5 != "" {
		reply, err := sendUDPviaTCP(ctx, firstHop, upstreamSocks5, dst, payload)
		if err != nil {
			log.Printf("tun2socks: UDP(tcp) %s: %v", dst, err)
			return
		}
		if _, err := udpConn.Write(reply); err != nil {
			log.Printf("tun2socks: UDP reply write: %v", err)
		}
		return
	}

	reply, err := sendUDP(ctx, firstHop, upstreamSocks5, dst, payload)
	if err != nil {
		log.Printf("tun2socks: UDP %s: %v", dst, err)
		return
	}
	if _, err := udpConn.Write(reply); err != nil {
		log.Printf("tun2socks: UDP reply write: %v", err)
	}
}

// ────────────────────────────────────────────────────────────────────────────
// Dial helpers: single-hop and two-hop SOCKS5
// ────────────────────────────────────────────────────────────────────────────

// dialTCP opens a TCP connection to dst through the proxy chain.
//
//   - No upstream: dial firstHop, SOCKS5 CONNECT to dst.
//   - With upstream: dial firstHop, SOCKS5 CONNECT to upstreamSocks5,
//     then SOCKS5 CONNECT again to dst over that tunnel connection.
func dialTCP(ctx context.Context, firstHop, upstreamSocks5 string, dst netip.AddrPort) (net.Conn, error) {
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", firstHop)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", firstHop, err)
	}

	if upstreamSocks5 != "" {
		// First hop: CONNECT to the upstream proxy address.
		upAddr, err := netip.ParseAddrPort(upstreamSocks5)
		if err != nil {
			// Fall back to host:port parsing.
			host, port, e := net.SplitHostPort(upstreamSocks5)
			if e != nil {
				_ = conn.Close()
				return nil, fmt.Errorf("parse upstreamSocks5: %w", err)
			}
			ips, e := net.LookupHost(host)
			if e != nil || len(ips) == 0 {
				_ = conn.Close()
				return nil, fmt.Errorf("resolve %s: %w", host, e)
			}
			var p uint16
			fmt.Sscanf(port, "%d", &p)
			ip, _ := netip.ParseAddr(ips[0])
			upAddr = netip.AddrPortFrom(ip, p)
		}
		if err := socks5Connect(conn, upAddr); err != nil {
			_ = conn.Close()
			return nil, fmt.Errorf("CONNECT to upstream %s: %w", upstreamSocks5, err)
		}
	}

	// Final hop: CONNECT to the actual destination.
	if err := socks5Connect(conn, dst); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("CONNECT to %s: %w", dst, err)
	}
	return conn, nil
}

// sendUDP sends a single UDP datagram through the proxy chain and returns the reply.
// UDP relay always goes through the exit proxy's UDP ASSOCIATE.
// With two hops, the UDP ASSOCIATE control connection is tunnelled through firstHop→upstreamSocks5.
func sendUDP(ctx context.Context, firstHop, upstreamSocks5 string, dst netip.AddrPort, payload []byte) ([]byte, error) {
	exitProxy := firstHop
	if upstreamSocks5 != "" {
		exitProxy = upstreamSocks5
	}

	// Open control connection to exit proxy (possibly via firstHop tunnel).
	ctrl, err := dialTCPRaw(ctx, firstHop, upstreamSocks5)
	if err != nil {
		return nil, err
	}
	defer func() { _ = ctrl.Close() }()
	_ = ctrl.SetDeadline(time.Now().Add(10 * time.Second))

	// Greeting on exit proxy.
	if _, err := ctrl.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		return nil, err
	}
	resp := make([]byte, 2)
	if _, err := io.ReadFull(ctrl, resp); err != nil {
		return nil, err
	}
	if resp[1] != 0x00 {
		return nil, fmt.Errorf("socks5 udp: auth %d", resp[1])
	}

	// UDP ASSOCIATE
	if _, err := ctrl.Write([]byte{0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
		return nil, err
	}
	hdr := make([]byte, 4)
	if _, err := io.ReadFull(ctrl, hdr); err != nil {
		return nil, err
	}
	if hdr[1] != 0x00 {
		return nil, fmt.Errorf("socks5 udp: ASSOCIATE rejected REP=%d", hdr[1])
	}
	relayAddr, err := readSocks5AddrPort(ctrl, hdr[3])
	if err != nil {
		return nil, err
	}
	_ = exitProxy // used only for documentation; relayAddr comes from the proxy response

	uc, err := net.Dial("udp", relayAddr)
	if err != nil {
		return nil, err
	}
	defer func() { _ = uc.Close() }()
	_ = uc.SetDeadline(time.Now().Add(5 * time.Second))

	if _, err := uc.Write(buildUDPFrame(dst, payload)); err != nil {
		return nil, err
	}
	buf := make([]byte, 65535)
	n, err := uc.Read(buf)
	if err != nil {
		return nil, err
	}
	return stripUDPFrame(buf[:n])
}

// sendUDPviaTCP sends a UDP payload over a TCP SOCKS5 CONNECT tunnel.
// Used in two-hop mode where the upstream's UDP ASSOCIATE relay address is
// unreachable from the client side. The payload is framed as DNS-over-TCP
// (2-byte length prefix) when dst port is 53; otherwise it is forwarded raw
// over the TCP stream and the first response chunk is returned.
func sendUDPviaTCP(ctx context.Context, firstHop, upstreamSocks5 string, dst netip.AddrPort, payload []byte) ([]byte, error) {
	conn, err := dialTCP(ctx, firstHop, upstreamSocks5, dst)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

	// DNS-over-TCP: prefix with 2-byte big-endian length.
	if dst.Port() == 53 {
		lenBuf := [2]byte{byte(len(payload) >> 8), byte(len(payload))}
		if _, err := conn.Write(lenBuf[:]); err != nil {
			return nil, err
		}
		if _, err := conn.Write(payload); err != nil {
			return nil, err
		}
		// Read 2-byte length prefix of the response.
		var respLen [2]byte
		if _, err := io.ReadFull(conn, respLen[:]); err != nil {
			return nil, err
		}
		n := int(respLen[0])<<8 | int(respLen[1])
		resp := make([]byte, n)
		if _, err := io.ReadFull(conn, resp); err != nil {
			return nil, err
		}
		return resp, nil
	}

	// Non-DNS UDP over TCP: send raw, read one chunk back.
	if _, err := conn.Write(payload); err != nil {
		return nil, err
	}
	buf := make([]byte, 65535)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}

// dialTCPRaw opens a raw TCP connection to the exit proxy (no final CONNECT).
// If upstreamSocks5 is empty, connects directly to firstHop.
// Otherwise connects to firstHop and tunnels through to upstreamSocks5.
func dialTCPRaw(ctx context.Context, firstHop, upstreamSocks5 string) (net.Conn, error) {
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", firstHop)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", firstHop, err)
	}
	if upstreamSocks5 == "" {
		return conn, nil
	}
	upAddr, err := parseAddrPort(upstreamSocks5)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	if err := socks5Connect(conn, upAddr); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("tunnel to %s: %w", upstreamSocks5, err)
	}
	return conn, nil
}

func parseAddrPort(hostport string) (netip.AddrPort, error) {
	ap, err := netip.ParseAddrPort(hostport)
	if err == nil {
		return ap, nil
	}
	host, portStr, e := net.SplitHostPort(hostport)
	if e != nil {
		return netip.AddrPort{}, fmt.Errorf("parse %q: %w", hostport, e)
	}
	ips, e := net.LookupHost(host)
	if e != nil || len(ips) == 0 {
		return netip.AddrPort{}, fmt.Errorf("resolve %q: %w", host, e)
	}
	ip, _ := netip.ParseAddr(ips[0])
	var port uint16
	fmt.Sscanf(portStr, "%d", &port)
	return netip.AddrPortFrom(ip, port), nil
}

// ────────────────────────────────────────────────────────────────────────────
// gvisor stack + channel endpoint
// ────────────────────────────────────────────────────────────────────────────

type channelEndpoint struct {
	mu            sync.Mutex
	mtu           uint32
	linkAddr      tcpip.LinkAddress
	inbound       chan []byte
	outbox        chan []byte
	onCloseAction func()
}

func newGvisorStack(localAddrs []netip.Addr, mtu int) (*stack.Stack, *channelEndpoint, error) {
	ep := &channelEndpoint{
		mtu:     uint32(mtu),
		inbound: make(chan []byte, 256),
		outbox:  make(chan []byte, 256),
	}

	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
	})

	const nicID = tcpip.NICID(1)
	if err := s.CreateNIC(nicID, ep); err != nil {
		return nil, nil, fmt.Errorf("CreateNIC: %v", err)
	}

	for _, addr := range localAddrs {
		var proto tcpip.NetworkProtocolNumber
		var tcpipAddr tcpip.Address
		if addr.Is4() {
			proto = ipv4.ProtocolNumber
			a4 := addr.As4()
			tcpipAddr = tcpip.AddrFrom4(a4)
		} else {
			proto = ipv6.ProtocolNumber
			a16 := addr.As16()
			tcpipAddr = tcpip.AddrFrom16(a16)
		}
		if err := s.AddProtocolAddress(nicID, tcpip.ProtocolAddress{
			Protocol:          proto,
			AddressWithPrefix: tcpipAddr.WithPrefix(),
		}, stack.AddressProperties{}); err != nil {
			return nil, nil, fmt.Errorf("AddProtocolAddress %s: %v", addr, err)
		}
	}

	s.AddRoute(tcpip.Route{Destination: header.IPv4EmptySubnet, NIC: nicID})
	s.AddRoute(tcpip.Route{Destination: header.IPv6EmptySubnet, NIC: nicID})

	// Accept packets destined for any IP (not just our assigned addresses),
	// and allow sending from any source IP (needed for TCP SYN-ACK spoofing).
	if err := s.SetPromiscuousMode(nicID, true); err != nil {
		return nil, nil, fmt.Errorf("SetPromiscuousMode: %v", err)
	}
	if err := s.SetSpoofing(nicID, true); err != nil {
		return nil, nil, fmt.Errorf("SetSpoofing: %v", err)
	}

	return s, ep, nil
}

func (e *channelEndpoint) InjectInbound(pkt []byte) {
	cp := make([]byte, len(pkt))
	copy(cp, pkt)
	select {
	case e.inbound <- cp:
	default:
	}
}

func (e *channelEndpoint) ReadOutbound() []byte {
	select {
	case p := <-e.outbox:
		return p
	default:
		return nil
	}
}

func (e *channelEndpoint) close() { close(e.inbound) }

// stack.NetworkLinkEndpoint
func (e *channelEndpoint) MTU() uint32 { return e.mtu }
func (e *channelEndpoint) SetMTU(mtu uint32) {
	e.mu.Lock()
	e.mtu = mtu
	e.mu.Unlock()
}
func (e *channelEndpoint) Capabilities() stack.LinkEndpointCapabilities { return 0 }
func (e *channelEndpoint) MaxHeaderLength() uint16                       { return 0 }
func (e *channelEndpoint) LinkAddress() tcpip.LinkAddress                { return e.linkAddr }
func (e *channelEndpoint) SetLinkAddress(addr tcpip.LinkAddress) {
	e.mu.Lock()
	e.linkAddr = addr
	e.mu.Unlock()
}
func (e *channelEndpoint) ARPHardwareType() header.ARPHardwareType { return header.ARPHardwareNone }
func (e *channelEndpoint) AddHeader(*stack.PacketBuffer)           {}
func (e *channelEndpoint) ParseHeader(*stack.PacketBuffer) bool    { return true }
func (e *channelEndpoint) Close() {
	e.mu.Lock()
	fn := e.onCloseAction
	e.mu.Unlock()
	if fn != nil {
		fn()
	}
}
func (e *channelEndpoint) SetOnCloseAction(fn func()) {
	e.mu.Lock()
	e.onCloseAction = fn
	e.mu.Unlock()
}
func (e *channelEndpoint) Attach(dispatcher stack.NetworkDispatcher) {
	go func() {
		for pkt := range e.inbound {
			if dispatcher == nil {
				continue
			}
			var proto tcpip.NetworkProtocolNumber
			if len(pkt) > 0 {
				switch pkt[0] >> 4 {
				case 4:
					proto = header.IPv4ProtocolNumber
				case 6:
					proto = header.IPv6ProtocolNumber
				}
			}
			buf := gvbuffer.MakeWithData(pkt)
			pb := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buf})
			dispatcher.DeliverNetworkPacket(proto, pb)
			pb.DecRef()
		}
	}()
}
func (e *channelEndpoint) IsAttached() bool { return true }
func (e *channelEndpoint) Wait()            {}

// stack.LinkWriter
func (e *channelEndpoint) WritePackets(pkts stack.PacketBufferList) (int, tcpip.Error) {
	n := 0
	for _, pb := range pkts.AsSlice() {
		buf := pb.ToBuffer()
		data := buf.Flatten()
		cp := make([]byte, len(data))
		copy(cp, data)
		buf.Release()
		select {
		case e.outbox <- cp:
			n++
		default:
		}
	}
	return n, nil
}

// ────────────────────────────────────────────────────────────────────────────
// Address helpers
// ────────────────────────────────────────────────────────────────────────────

func forwarderReqDst(r *tcp.ForwarderRequest) netip.AddrPort {
	id := r.ID()
	return netip.AddrPortFrom(tcpipAddrToNetip(id.LocalAddress), id.LocalPort)
}

func forwarderReqDstUDP(r *udp.ForwarderRequest) netip.AddrPort {
	id := r.ID()
	return netip.AddrPortFrom(tcpipAddrToNetip(id.LocalAddress), id.LocalPort)
}

func tcpipAddrToNetip(addr tcpip.Address) netip.Addr {
	if addr.Len() == 4 {
		return netip.AddrFrom4(addr.As4())
	}
	return netip.AddrFrom16(addr.As16())
}

// ────────────────────────────────────────────────────────────────────────────
// SOCKS5 protocol helpers
// ────────────────────────────────────────────────────────────────────────────

func socks5Connect(conn net.Conn, dst netip.AddrPort) error {
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	defer func() { _ = conn.SetDeadline(time.Time{}) }()

	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		return err
	}
	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return err
	}
	if resp[1] != 0x00 {
		return fmt.Errorf("socks5: server chose auth %d", resp[1])
	}
	if _, err := conn.Write(buildConnectReq(dst)); err != nil {
		return err
	}
	hdr := make([]byte, 4)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		return err
	}
	if hdr[1] != 0x00 {
		return fmt.Errorf("socks5: CONNECT rejected REP=%d", hdr[1])
	}
	return drainAddrPort(conn, hdr[3])
}

func buildConnectReq(dst netip.AddrPort) []byte {
	buf := []byte{0x05, 0x01, 0x00}
	if dst.Addr().Is4() {
		ip := dst.Addr().As4()
		buf = append(buf, 0x01)
		buf = append(buf, ip[:]...)
	} else {
		ip := dst.Addr().As16()
		buf = append(buf, 0x04)
		buf = append(buf, ip[:]...)
	}
	p := dst.Port()
	return append(buf, byte(p>>8), byte(p))
}

func drainAddrPort(conn net.Conn, atyp byte) error {
	switch atyp {
	case 0x01:
		_, err := io.ReadFull(conn, make([]byte, 4+2))
		return err
	case 0x04:
		_, err := io.ReadFull(conn, make([]byte, 16+2))
		return err
	case 0x03:
		lb := make([]byte, 1)
		if _, err := io.ReadFull(conn, lb); err != nil {
			return err
		}
		_, err := io.ReadFull(conn, make([]byte, int(lb[0])+2))
		return err
	default:
		return fmt.Errorf("socks5: unexpected ATYP %d", atyp)
	}
}

func readSocks5AddrPort(r io.Reader, atyp byte) (string, error) {
	switch atyp {
	case 0x01:
		b := make([]byte, 6)
		if _, err := io.ReadFull(r, b); err != nil {
			return "", err
		}
		return fmt.Sprintf("%d.%d.%d.%d:%d", b[0], b[1], b[2], b[3],
			binary.BigEndian.Uint16(b[4:6])), nil
	case 0x04:
		b := make([]byte, 18)
		if _, err := io.ReadFull(r, b); err != nil {
			return "", err
		}
		ip := net.IP(b[:16])
		port := binary.BigEndian.Uint16(b[16:18])
		return fmt.Sprintf("[%s]:%d", ip, port), nil
	default:
		return "", fmt.Errorf("socks5: unexpected ATYP %d in ASSOCIATE reply", atyp)
	}
}

func buildUDPFrame(dst netip.AddrPort, payload []byte) []byte {
	buf := []byte{0x00, 0x00, 0x00}
	if dst.Addr().Is4() {
		ip := dst.Addr().As4()
		buf = append(buf, 0x01)
		buf = append(buf, ip[:]...)
	} else {
		ip := dst.Addr().As16()
		buf = append(buf, 0x04)
		buf = append(buf, ip[:]...)
	}
	p := dst.Port()
	buf = append(buf, byte(p>>8), byte(p))
	return append(buf, payload...)
}

func stripUDPFrame(b []byte) ([]byte, error) {
	if len(b) < 4 {
		return nil, fmt.Errorf("socks5 udp reply too short")
	}
	switch b[3] {
	case 0x01:
		if len(b) < 10 {
			return nil, fmt.Errorf("socks5 udp reply truncated (ipv4)")
		}
		return b[10:], nil
	case 0x04:
		if len(b) < 22 {
			return nil, fmt.Errorf("socks5 udp reply truncated (ipv6)")
		}
		return b[22:], nil
	case 0x03:
		if len(b) < 5 {
			return nil, fmt.Errorf("socks5 udp reply truncated (domain)")
		}
		l := int(b[4])
		if len(b) < 5+l+2 {
			return nil, fmt.Errorf("socks5 udp reply truncated (domain data)")
		}
		return b[5+l+2:], nil
	default:
		return nil, fmt.Errorf("socks5 udp unknown ATYP %d", b[3])
	}
}

func relayTCP(a, b net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)
	half := func(dst, src net.Conn) {
		defer wg.Done()
		_, _ = io.Copy(dst, src)
		type halfCloser interface{ CloseWrite() error }
		if hc, ok := dst.(halfCloser); ok {
			_ = hc.CloseWrite()
		}
	}
	go half(b, a)
	half(a, b)
	wg.Wait()
}
