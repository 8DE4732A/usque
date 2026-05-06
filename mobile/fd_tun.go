package mobile

import (
	"fmt"
	"os"
)

// fdTunDevice implements api.TunnelDevice over a raw file descriptor (for Android VpnService).
// The fd is owned by this struct after construction; Close() releases it.
type fdTunDevice struct {
	file *os.File
	mtu  int
}

// newFdTunDevice wraps an already-detached file descriptor into a TunnelDevice.
// The caller must NOT close fd after this call; fdTunDevice.Close() owns it.
func newFdTunDevice(fd int, mtu int) (*fdTunDevice, error) {
	if fd < 0 {
		return nil, fmt.Errorf("invalid fd: %d", fd)
	}
	f := os.NewFile(uintptr(fd), "vpn-tun")
	if f == nil {
		return nil, fmt.Errorf("os.NewFile returned nil for fd %d", fd)
	}
	return &fdTunDevice{file: f, mtu: mtu}, nil
}

// ReadPacket reads one IP packet from the TUN fd into buf.
func (f *fdTunDevice) ReadPacket(buf []byte) (int, error) {
	n, err := f.file.Read(buf)
	if err != nil {
		return 0, fmt.Errorf("tun read: %w", err)
	}
	return n, nil
}

// WritePacket writes one IP packet to the TUN fd.
func (f *fdTunDevice) WritePacket(pkt []byte) error {
	_, err := f.file.Write(pkt)
	if err != nil {
		return fmt.Errorf("tun write: %w", err)
	}
	return nil
}

// Close releases the underlying file descriptor.
func (f *fdTunDevice) Close() error {
	return f.file.Close()
}
