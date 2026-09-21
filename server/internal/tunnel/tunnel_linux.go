//go:build linux
// +build linux

package tunnel

import (
	"fmt"
	"log/slog"
	"net"
	"os/exec"

	"github.com/songgao/water"
)

// TUNDevice wraps a TUN network interface for reading/writing IP packets.
type TUNDevice struct {
	iface  *water.Interface
	name   string
	addr   string
	mtu    int
	logger *slog.Logger
}

// NewTUNDevice creates and configures a new TUN interface on Linux.
func NewTUNDevice(name, addr string, mtu int, logger *slog.Logger) (*TUNDevice, error) {
	config := water.Config{
		DeviceType: water.TUN,
	}
	config.Name = name

	iface, err := water.New(config)
	if err != nil {
		return nil, fmt.Errorf("create TUN interface %s: %w", name, err)
	}

	dev := &TUNDevice{
		iface:  iface,
		name:   iface.Name(),
		addr:   addr,
		mtu:    mtu,
		logger: logger,
	}

	if err := dev.configure(); err != nil {
		iface.Close()
		return nil, fmt.Errorf("configure TUN: %w", err)
	}

	logger.Info("TUN device created",
		"name", dev.name,
		"addr", addr,
		"mtu", mtu,
	)

	return dev, nil
}

// configure sets up the TUN interface with IP address, MTU, and brings it up.
func (t *TUNDevice) configure() error {
	// Parse IP and CIDR mask
	ip, ipNet, err := net.ParseCIDR(t.addr)
	if err != nil {
		return fmt.Errorf("invalid CIDR address %s: %w", t.addr, err)
	}
	maskLen, _ := ipNet.Mask.Size()

	// 1. Assign IP address: ip addr add <ip>/<mask> dev <name>
	cidrAddr := fmt.Sprintf("%s/%d", ip.String(), maskLen)
	if err := runCmd("ip", "addr", "add", cidrAddr, "dev", t.name); err != nil {
		t.logger.Warn("ip addr add warning (may already exist)", "error", err)
	}

	// 2. Set MTU: ip link set dev <name> mtu <mtu>
	if err := runCmd("ip", "link", "set", "dev", t.name, "mtu", fmt.Sprintf("%d", t.mtu)); err != nil {
		return fmt.Errorf("set MTU: %w", err)
	}

	// 3. Bring interface up: ip link set dev <name> up
	if err := runCmd("ip", "link", "set", "dev", t.name, "up"); err != nil {
		return fmt.Errorf("bring up interface: %w", err)
	}

	t.logger.Info("TUN configured",
		"ip", ip.String(),
		"network", ipNet.String(),
	)

	return nil
}

// Read reads a single IP packet from the TUN interface.
func (t *TUNDevice) Read(buf []byte) (int, error) {
	return t.iface.Read(buf)
}

// Write writes a single IP packet to the TUN interface.
func (t *TUNDevice) Write(buf []byte) (int, error) {
	return t.iface.Write(buf)
}

// Close shuts down the TUN device.
func (t *TUNDevice) Close() error {
	t.logger.Info("closing TUN device", "name", t.name)
	return t.iface.Close()
}

// Name returns the interface name.
func (t *TUNDevice) Name() string {
	return t.name
}

// SetupNAT configures iptables MASQUERADE for VPN subnet traffic.
func SetupNAT(subnet string, logger *slog.Logger) error {
	// Enable IP forwarding
	if err := runCmd("sysctl", "-w", "net.ipv4.ip_forward=1"); err != nil {
		logger.Warn("enable ip_forward failed", "error", err)
	}

	// Add POSTROUTING MASQUERADE rule
	if err := runCmd("iptables", "-t", "nat", "-C", "POSTROUTING", "-s", subnet, "-j", "MASQUERADE"); err != nil {
		// Rule doesn't exist, add it
		if err := runCmd("iptables", "-t", "nat", "-A", "POSTROUTING", "-s", subnet, "-j", "MASQUERADE"); err != nil {
			return fmt.Errorf("iptables NAT rule: %w", err)
		}
		logger.Info("NAT configured", "subnet", subnet)
	}

	// Accept forward traffic
	_ = runCmd("iptables", "-C", "FORWARD", "-s", subnet, "-j", "ACCEPT")
	_ = runCmd("iptables", "-A", "FORWARD", "-s", subnet, "-j", "ACCEPT")
	_ = runCmd("iptables", "-C", "FORWARD", "-d", subnet, "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT")
	_ = runCmd("iptables", "-A", "FORWARD", "-d", subnet, "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT")

	return nil
}

// CleanupNAT removes iptables rules on shutdown.
func CleanupNAT(subnet string, logger *slog.Logger) {
	_ = runCmd("iptables", "-t", "nat", "-D", "POSTROUTING", "-s", subnet, "-j", "MASQUERADE")
	_ = runCmd("iptables", "-D", "FORWARD", "-s", subnet, "-j", "ACCEPT")
	_ = runCmd("iptables", "-D", "FORWARD", "-d", subnet, "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT")
	logger.Info("NAT cleaned up", "subnet", subnet)
}

func runCmd(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %v failed (%s): %w", name, args, string(output), err)
	}
	return nil
}
