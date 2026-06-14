package main

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		return
	}

	command := strings.ToLower(os.Args[1])

	switch command {
	case "scan":
		runSingleScan()

	case "monitor":
		StartMonitor()

	case "list":
		runListCommand()

	case "authorize":
		if len(os.Args) < 4 {
			fmt.Println(colorRed + "❌ Error: Please specify a MAC address and an alias." + colorReset)
			fmt.Println("Usage: netscan authorize <MAC_ADDRESS> <ALIAS>")
			return
		}
		runAuthorizeCommand(os.Args[2], strings.Join(os.Args[3:], " "))

	case "deauthorize":
		if len(os.Args) < 3 {
			fmt.Println(colorRed + "❌ Error: Please specify a MAC address." + colorReset)
			fmt.Println("Usage: netscan deauthorize <MAC_ADDRESS>")
			return
		}
		runDeauthorizeCommand(os.Args[2])

	case "settings":
		if len(os.Args) < 4 {
			fmt.Println(colorRed + "❌ Error: Please specify setting key and value." + colorReset)
			fmt.Println("Usage:")
			fmt.Println("  netscan settings interval <SECONDS>")
			fmt.Println("  netscan settings notify <true/false>")
			return
		}
		runSettingsCommand(os.Args[2], os.Args[3])

	case "help", "-h", "--help":
		printUsage()

	default:
		fmt.Printf("❌ Unknown command: %s\n", os.Args[1])
		printUsage()
	}
}

func printUsage() {
	fmt.Println("==================================================")
	fmt.Println("        🛡️  LAN Sentinel CLI Tool Commands       ")
	fmt.Println("==================================================")
	fmt.Println("Usage: netscan <command> [arguments]")
	fmt.Println()
	fmt.Println("Available Commands:")
	fmt.Println("  scan                       Perform a fast one-time scan of the subnets")
	fmt.Println("  monitor                    Start background security monitor & intruder alert loop")
	fmt.Println("  list                       List authorized devices and active devices on the network")
	fmt.Println("  authorize <MAC> <alias>    Authorize a device's MAC address with a friendly name")
	fmt.Println("  deauthorize <MAC>          Deauthorize a device's MAC address")
	fmt.Println("  settings interval <sec>    Change monitor scanning frequency (default: 30s)")
	fmt.Println("  settings notify <t/f>      Enable or disable OS desktop notifications")
	fmt.Println()
	fmt.Println("Examples:")
	fmt.Println("  go run . authorize 4A:6C:34:73:21:F9 \"Home Router\"")
	fmt.Println("  go run . monitor")
}

func runSingleScan() {
	fmt.Println("==================================================")
	fmt.Println("            ⚡ Wi-Fi Subnet Scanner ⚡           ")
	fmt.Println("==================================================")

	gatewayIP := getDefaultGateway()
	if gatewayIP != "" {
		fmt.Printf("🌐 Default Gateway (Router IP): %s\n", gatewayIP)
	}

	subnets, err := getActiveSubnets()
	if err != nil || len(subnets) == 0 {
		fmt.Printf("❌ Failed to detect active interfaces: %v\n", err)
		return
	}

	for _, sub := range subnets {
		fmt.Printf("\n🚀 Scanning subnet %s...\n", sub.IPNet.String())
		devices := scanSubnet(sub.IPNet, gatewayIP)
		printDeviceTable(devices)
	}
}

func runListCommand() {
	config, err := LoadConfig()
	if err != nil {
		fmt.Printf("❌ Failed to load config: %v\n", err)
		return
	}

	fmt.Println(colorCyan + "--- Authorized Devices List ---" + colorReset)
	if len(config.AuthorizedDevices) == 0 {
		fmt.Println("No devices authorized yet. Run 'netscan authorize <MAC> <alias>' to add one.")
	} else {
		for mac, alias := range config.AuthorizedDevices {
			fmt.Printf("   %-20s -> %s\n", mac, alias)
		}
	}
	fmt.Println()

	// Check who is active now
	fmt.Println(colorCyan + "--- Current Online Devices ---" + colorReset)
	subnets, err := getActiveSubnets()
	if err == nil {
		devices := performSubnetScans(subnets)
		printStateSummary(devicesToMap(devices), config)
	}
}

func runAuthorizeCommand(macStr, alias string) {
	mac, err := net.ParseMAC(macStr)
	if err != nil {
		fmt.Printf("❌ Invalid MAC address format: %s\n", macStr)
		return
	}
	normalizedMac := strings.ToLower(mac.String())

	config, err := LoadConfig()
	if err != nil {
		fmt.Printf("❌ Failed to load config: %v\n", err)
		return
	}

	config.AuthorizedDevices[normalizedMac] = alias
	err = SaveConfig(config)
	if err != nil {
		fmt.Printf("❌ Failed to save config: %v\n", err)
		return
	}

	fmt.Printf("✅ Device Authorized: %s -> %s\n", normalizedMac, alias)
}

func runDeauthorizeCommand(macStr string) {
	mac, err := net.ParseMAC(macStr)
	if err != nil {
		fmt.Printf("❌ Invalid MAC address format: %s\n", macStr)
		return
	}
	normalizedMac := strings.ToLower(mac.String())

	config, err := LoadConfig()
	if err != nil {
		fmt.Printf("❌ Failed to load config: %v\n", err)
		return
	}

	if _, exists := config.AuthorizedDevices[normalizedMac]; !exists {
		fmt.Printf("⚠️  Device %s is not in the authorized list.\n", normalizedMac)
		return
	}

	delete(config.AuthorizedDevices, normalizedMac)
	err = SaveConfig(config)
	if err != nil {
		fmt.Printf("❌ Failed to save config: %v\n", err)
		return
	}

	fmt.Printf("✅ Device Deauthorized: %s\n", normalizedMac)
}

func runSettingsCommand(key, value string) {
	config, err := LoadConfig()
	if err != nil {
		fmt.Printf("❌ Failed to load config: %v\n", err)
		return
	}

	switch strings.ToLower(key) {
	case "interval":
		sec, err := strconv.Atoi(value)
		if err != nil || sec < 5 {
			fmt.Println("❌ Error: Interval must be an integer greater than or equal to 5 seconds.")
			return
		}
		config.ScanIntervalSeconds = sec
		fmt.Printf("✅ Scan interval updated to %d seconds.\n", sec)

	case "notify":
		val := strings.ToLower(value)
		if val == "true" || val == "t" || val == "1" {
			config.EnableNotifications = true
		} else if val == "false" || val == "f" || val == "0" {
			config.EnableNotifications = false
		} else {
			fmt.Println("❌ Error: Notification setting must be 'true' or 'false'.")
			return
		}
		fmt.Printf("✅ Desktop notifications set to %t.\n", config.EnableNotifications)

	default:
		fmt.Printf("❌ Unknown setting: %s. Use 'interval' or 'notify'.\n", key)
		return
	}

	err = SaveConfig(config)
	if err != nil {
		fmt.Printf("❌ Failed to save config: %v\n", err)
	}
}

func devicesToMap(devices []Device) map[string]Device {
	m := make(map[string]Device)
	for _, d := range devices {
		if d.MAC != "" && d.MAC != "Unknown" {
			m[strings.ToLower(d.MAC)] = d
		}
	}
	return m
}
