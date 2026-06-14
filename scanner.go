package main

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Device represents a discovered network device
type Device struct {
	IP        string
	MAC       string
	Hostname  string
	Vendor    string
	IsGateway bool
	OpenPorts []int
}

// SubnetInfo contains subnet and interface info
type SubnetInfo struct {
	IPNet         *net.IPNet
	InterfaceName string
}

var commonPorts = map[int]string{
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

// getActiveSubnets returns all active IPv4 non-loopback subnets
func getActiveSubnets() ([]SubnetInfo, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	var subnets []SubnetInfo
	for _, iface := range interfaces {
		// Skip interface if it's down or a loopback
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

			// We are only interested in IPv4 addresses
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

// getDefaultGateway finds the default gateway on Linux using the routing table or ip command
func getDefaultGateway() string {
	if runtime.GOOS != "linux" {
		return ""
	}

	// Try reading /proc/net/route first (fastest and native)
	file, err := os.Open("/proc/net/route")
	if err == nil {
		defer file.Close()
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			fields := strings.Fields(scanner.Text())
			if len(fields) >= 3 {
				// Destination "00000000" represents the default route
				if fields[1] == "00000000" {
					gwHex := fields[2]
					d, err := hex.DecodeString(gwHex)
					if err == nil && len(d) == 4 {
						// Little-endian IPv4 representation
						ip := net.IPv4(d[3], d[2], d[1], d[0])
						return ip.String()
					}
				}
			}
		}
	}

	// Fallback: run 'ip route' command
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
	// Skip header line
	if scanner.Scan() {
		for scanner.Scan() {
			fields := strings.Fields(scanner.Text())
			if len(fields) >= 4 {
				ip := fields[0]
				mac := fields[3]
				// Filter out incomplete/invalid MAC addresses
				if mac != "00:00:00:00:00:00" && regexp.MustCompile(`^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$`).MatchString(mac) {
					arpMap[ip] = mac
				}
			}
		}
	}
	return arpMap
}

// scanSubnet discovers active devices in a subnet
func scanSubnet(ipNet *net.IPNet, gatewayIP string) []Device {
	ips := generateIPs(ipNet)
	if len(ips) == 0 {
		return nil
	}

	activeIPChan := make(chan string, len(ips))
	var wg sync.WaitGroup

	// Worker pool for ping sweeping
	workerCount := 64
	ipChan := make(chan string, len(ips))

	// Start workers
	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ip := range ipChan {
				if pingHost(ip) {
					activeIPChan <- ip
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

	// Collect active IPs
	activeIPs := make(map[string]bool)
	for ip := range activeIPChan {
		activeIPs[ip] = true
	}

	// Read ARP cache to catch firewalled devices that replied to ARP but blocked ICMP
	arpMap := parseARPCache()
	for ip := range arpMap {
		// Only add it if it belongs to this subnet
		parsedIP := net.ParseIP(ip)
		if ipNet.Contains(parsedIP) {
			activeIPs[ip] = true
		}
	}

	// Get mapping of local interface IPs to their hardware MAC addresses
	localIPMap := getLocalIPToMACMap()

	// Scan ports on all active devices
	var devices []Device
	var devWg sync.WaitGroup
	var devMutex sync.Mutex

	for ipStr := range activeIPs {
		devWg.Add(1)
		go func(ip string) {
			defer devWg.Done()
			mac := arpMap[ip]
			if mac == "" {
				if localMac, ok := localIPMap[ip]; ok && localMac != "" {
					mac = localMac
				} else {
					mac = "Unknown"
				}
			}

			// Check hostname
			hostname := getHostname(ip)

			// Scan common ports
			openPorts := scanPorts(ip)

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

	// Remove broadcast address if length is typical
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
func scanPorts(ip string) []int {
	var openPorts []int
	var wg sync.WaitGroup
	var mutex sync.Mutex

	for port := range commonPorts {
		wg.Add(1)
		go func(p int) {
			defer wg.Done()
			address := net.JoinHostPort(ip, strconv.Itoa(p))
			conn, err := net.DialTimeout("tcp", address, 600*time.Millisecond)
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

// printDeviceTable prints a styled table of discovered devices
func printDeviceTable(devices []Device) {
	fmt.Printf("%-18s %-20s %-20s %-10s %s\n", "IP Address", "Hostname", "MAC Address", "Type", "Open Servers / Services")
	fmt.Println(strings.Repeat("-", 100))

	for _, dev := range devices {
		devType := "Client"
		if dev.IsGateway {
			devType = "Gateway"
		} else if len(dev.OpenPorts) > 0 {
			devType = "Server"
		}

		var services []string
		for _, port := range dev.OpenPorts {
			services = append(services, fmt.Sprintf("%d (%s)", port, commonPorts[port]))
		}

		serviceStr := "None"
		if len(services) > 0 {
			serviceStr = strings.Join(services, ", ")
		}

		fmt.Printf("%-18s %-20s %-20s %-10s %s\n",
			dev.IP,
			truncate(dev.Hostname, 18),
			dev.MAC,
			devType,
			serviceStr,
		)
	}
}

func truncate(str string, max int) string {
	if len(str) > max {
		return str[:max-3] + "..."
	}
	return str
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
