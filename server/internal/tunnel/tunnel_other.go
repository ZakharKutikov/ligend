//go:build !linux
// +build !linux

package tunnel

import (
	"log/slog"
)

// TUNDevice mock for non-Linux platforms (Windows/macOS development).
type TUNDevice struct {
	name   string
	addr   string
	mtu    int
	logger *slog.Logger
}

// NewTUNDevice mock constructor for non-Linux OS.
func NewTUNDevice(name, addr string, mtu int, logger *slog.Logger) (*TUNDevice, error) {
	logger.Warn("TUN device running in stub mode (non-Linux platform)", "os", "non-linux")
	return &TUNDevice{
		name:   name,
		addr:   addr,
		mtu:    mtu,
		logger: logger,
	}, nil
}

func (t *TUNDevice) Read(buf []byte) (int, error) {
	// Block or sleep to simulate read loop on non-Linux
	select {}
}

func (t *TUNDevice) Write(buf []byte) (int, error) {
	return len(buf), nil
}

func (t *TUNDevice) Close() error {
	return nil
}

func (t *TUNDevice) Name() string {
	return t.name
}

func SetupNAT(subnet string, logger *slog.Logger) error {
	logger.Info("NAT setup skipped (non-Linux platform)", "subnet", subnet)
	return nil
}

func CleanupNAT(subnet string, logger *slog.Logger) {
	logger.Info("NAT cleanup skipped (non-Linux platform)", "subnet", subnet)
}
