package scanner

import (
	"bufio"
	"context"
	"encoding/hex"
	"net"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
)

// Device represents a discovered network device
type Device struct {
	IP        string `json:"ip"`
	MAC       string `json:"mac"`
	Hostname  string `json:"hostname"`
	IsGateway bool   `json:"is_gateway"`
	OpenPorts []int  `json:"open_ports"`
}

// SubnetInfo contains subnet and interface info
type SubnetInfo struct {
	IPNet         *net.IPNet
	InterfaceName string
}

// CommonPorts maps port numbers to standard network services
var CommonPorts = map[int]string{
	22:   "SSH",
	80:   "HTTP",
	443:  "HTTPS",
	139:  "NetBIOS",
	445:  "SMB",
	3000: "React/Node Dev",
	5000: "Flask/ASP.NET Dev",
	8000: "HTTP Dev",
	8080: "HTTP Alt",
	9000: "Portainer/PHP",
}

// GetActiveSubnets returns all active IPv4 non-loopback subnets
func GetActiveSubnets() ([]SubnetInfo, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	var subnets []SubnetInfo
	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}

			ipv4 := ipNet.IP.To4()
			if ipv4 == nil {
				continue
			}

			subnets = append(subnets, SubnetInfo{
				IPNet:         ipNet,
				InterfaceName: iface.Name,
			})
		}
	}
	return subnets, nil
}

// GetDefaultGateway finds the default gateway on Linux using the routing table or ip command
func GetDefaultGateway() string {
	if runtime.GOOS != "linux" {
		return ""
	}

	file, err := os.Open("/proc/net/route")
	if err == nil {
		defer file.Close()
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			fields := strings.Fields(scanner.Text())
			if len(fields) >= 3 {
				if fields[1] == "00000000" {
					gwHex := fields[2]
					d, err := hex.DecodeString(gwHex)
					if err == nil && len(d) == 4 {
						ip := net.IPv4(d[3], d[2], d[1], d[0])
						return ip.String()
					}
				}
			}
		}
	}

	cmd := exec.Command("ip", "route")
	output, err := cmd.Output()
	if err == nil {
		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			if strings.HasPrefix(line, "default via") {
				fields := strings.Fields(line)
				if len(fields) >= 3 {
					return fields[2]
				}
			}
		}
	}

	return ""
}

// parseARPCache reads /proc/net/arp to get MAC addresses of devices
func parseARPCache() map[string]string {
	arpMap := make(map[string]string)
	file, err := os.Open("/proc/net/arp")
	if err != nil {
		return arpMap
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	if scanner.Scan() {
		for scanner.Scan() {
			fields := strings.Fields(scanner.Text())
			if len(fields) >= 4 {
				ip := fields[0]
				mac := fields[3]
				if mac != "00:00:00:00:00:00" && regexp.MustCompile(`^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$`).MatchString(mac) {
					arpMap[ip] = mac
				}
			}
		}
	}
	return arpMap
}

// ScanSubnet discovers active devices in a subnet and is context-cancellation aware
func ScanSubnet(ctx context.Context, ipNet *net.IPNet, gatewayIP string) []Device {
	ips := generateIPs(ipNet)
	if len(ips) == 0 {
		return nil
	}

	activeIPChan := make(chan string, len(ips))
	var wg sync.WaitGroup

	workerCount := 64
	ipChan := make(chan string, len(ips))

	// Start workers
	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ip := range ipChan {
				select {
				case <-ctx.Done():
					return
				default:
					if pingHost(ip) {
						activeIPChan <- ip
					}
				}
			}
		}()
	}

	// Send IPs to workers
	for _, ip := range ips {
		ipChan <- ip
	}
	close(ipChan)
	wg.Wait()
	close(activeIPChan)

	// Check cancellation
	select {
	case <-ctx.Done():
		return nil
	default:
	}

	// Collect active IPs
	activeIPs := make(map[string]bool)
	for ip := range activeIPChan {
		activeIPs[ip] = true
	}

	// Read ARP cache to catch devices bypassing ICMP pings
	arpMap := parseARPCache()
	for ip := range arpMap {
		parsedIP := net.ParseIP(ip)
		if ipNet.Contains(parsedIP) {
			activeIPs[ip] = true
		}
	}

	localIPMap := getLocalIPToMACMap()

	// Scan ports on all active devices concurrently
	var devices []Device
	var devWg sync.WaitGroup
	var devMutex sync.Mutex

	for ipStr := range activeIPs {
		devWg.Add(1)
		go func(ip string) {
			defer devWg.Done()
			select {
			case <-ctx.Done():
				return
			default:
			}

			mac := arpMap[ip]
			if mac == "" {
				if localMac, ok := localIPMap[ip]; ok && localMac != "" {
					mac = localMac
				} else {
					mac = "Unknown"
				}
			}

			hostname := getHostname(ip)
			openPorts := scanPorts(ctx, ip)

			devMutex.Lock()
			devices = append(devices, Device{
				IP:        ip,
				MAC:       mac,
				Hostname:  hostname,
				IsGateway: ip == gatewayIP,
				OpenPorts: openPorts,
			})
			devMutex.Unlock()
		}(ipStr)
	}

	devWg.Wait()
	return devices
}

// PerformSubnetScans runs scans across all active subnets concurrently
func PerformSubnetScans(ctx context.Context, subnets []SubnetInfo) []Device {
	var allDevices []Device
	seenIPs := make(map[string]bool)
	gatewayIP := GetDefaultGateway()

	for _, sub := range subnets {
		select {
		case <-ctx.Done():
			return nil
		default:
			scanned := ScanSubnet(ctx, sub.IPNet, gatewayIP)
			for _, dev := range scanned {
				if !seenIPs[dev.IP] {
					seenIPs[dev.IP] = true
					allDevices = append(allDevices, dev)
				}
			}
		}
	}
	return allDevices
}

// generateIPs returns all host IPs in the given subnet
func generateIPs(ipNet *net.IPNet) []string {
	var ips []string
	ip := ipNet.IP.Mask(ipNet.Mask)

	for {
		inc(ip)
		if !ipNet.Contains(ip) {
			break
		}
		ips = append(ips, ip.String())
	}

	if len(ips) > 1 {
		ips = ips[:len(ips)-1]
	}
	return ips
}

func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

// pingHost sends a single ping packet to verify if the host is alive
func pingHost(ip string) bool {
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command("ping", "-n", "1", "-w", "800", ip)
	} else {
		cmd = exec.Command("ping", "-c", "1", "-W", "1", ip)
	}

	err := cmd.Run()
	return err == nil
}

// scanPorts checks which common ports are open on a target IP
func scanPorts(ctx context.Context, ip string) []int {
	var openPorts []int
	var wg sync.WaitGroup
	var mutex sync.Mutex

	for port := range CommonPorts {
		wg.Add(1)
		go func(p int) {
			defer wg.Done()
			select {
			case <-ctx.Done():
				return
			default:
			}

			address := net.JoinHostPort(ip, strconv.Itoa(p))
			var dialer net.Dialer
			conn, err := dialer.DialContext(ctx, "tcp", address)
			if err == nil {
				conn.Close()
				mutex.Lock()
				openPorts = append(openPorts, p)
				mutex.Unlock()
			}
		}(port)
	}

	wg.Wait()
	return openPorts
}

// getHostname performs a reverse DNS lookup to find device name
func getHostname(ip string) string {
	names, err := net.LookupAddr(ip)
	if err == nil && len(names) > 0 {
		return strings.TrimSuffix(names[0], ".")
	}
	return "Unknown"
}

// getLocalIPToMACMap returns a map of all local IPv4 interface addresses to their hardware MACs
func getLocalIPToMACMap() map[string]string {
	m := make(map[string]string)
	interfaces, err := net.Interfaces()
	if err != nil {
		return m
	}
	for _, iface := range interfaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}
			ipv4 := ipNet.IP.To4()
			if ipv4 != nil {
				m[ipv4.String()] = iface.HardwareAddr.String()
			}
		}
	}
	return m
}

// Truncate helper
func Truncate(str string, max int) string {
	if len(str) > max {
		return str[:max-3] + "..."
	}
	return str
}
