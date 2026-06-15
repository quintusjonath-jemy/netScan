package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"netscan/internal/config"
	"netscan/internal/db"
	"netscan/internal/monitor"
	"netscan/internal/scanner"
	"netscan/internal/web"
)

// ANSI Color Codes
const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorBlue   = "\033[34m"
	colorCyan   = "\033[36m"
	colorGray   = "\033[90m"
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
		runMonitorService()

	case "list":
		runListCommand()

	case "authorize":
		if len(os.Args) < 4 {
			fmt.Println(colorRed + "❌ Error: Please specify a MAC address and an alias." + colorReset)
			fmt.Println("Usage: netsentinel authorize <MAC_ADDRESS> <ALIAS>")
			return
		}
		runAuthorizeCommand(os.Args[2], strings.Join(os.Args[3:], " "))

	case "deauthorize":
		if len(os.Args) < 3 {
			fmt.Println(colorRed + "❌ Error: Please specify a MAC address." + colorReset)
			fmt.Println("Usage: netsentinel deauthorize <MAC_ADDRESS>")
			return
		}
		runDeauthorizeCommand(os.Args[2])

	case "settings":
		if len(os.Args) < 4 {
			fmt.Println(colorRed + "❌ Error: Please specify setting key and value." + colorReset)
			fmt.Println("Usage:")
			fmt.Println("  netsentinel settings interval <SECONDS>")
			fmt.Println("  netsentinel settings notify <true/false>")
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
	fmt.Println("        🛡️  LAN Sentinel Production CLI           ")
	fmt.Println("==================================================")
	fmt.Println("Usage: netsentinel <command> [arguments]")
	fmt.Println()
	fmt.Println("Available Commands:")
	fmt.Println("  scan                       Perform a fast one-time scan of local subnets")
	fmt.Println("  monitor                    Start background security monitor & web server dashboard")
	fmt.Println("  list                       List authorized devices and active devices on the network")
	fmt.Println("  authorize <MAC> <alias>    Authorize a device's MAC address with a friendly name")
	fmt.Println("  deauthorize <MAC>          Deauthorize a device's MAC address")
	fmt.Println("  settings interval <sec>    Change monitor scanning frequency (default: 30s)")
	fmt.Println("  settings notify <t/f>      Enable or disable OS desktop notifications")
	fmt.Println()
	fmt.Println("Examples:")
	fmt.Println("  go run ./cmd/netsentinel authorize 4A:6C:34:73:21:F9 \"Home Router\"")
	fmt.Println("  go run ./cmd/netsentinel monitor")
}

func runSingleScan() {
	fmt.Println("==================================================")
	fmt.Println("            ⚡ Wi-Fi Subnet Scanner ⚡           ")
	fmt.Println("==================================================")

	gatewayIP := scanner.GetDefaultGateway()
	if gatewayIP != "" {
		fmt.Printf("🌐 Default Gateway (Router IP): %s\n", gatewayIP)
	}

	subnets, err := scanner.GetActiveSubnets()
	if err != nil || len(subnets) == 0 {
		fmt.Printf("❌ Failed to detect active interfaces: %v\n", err)
		return
	}

	ctx := context.Background()
	for _, sub := range subnets {
		fmt.Printf("\n🚀 Scanning subnet %s...\n", sub.IPNet.String())
		devices := scanner.ScanSubnet(ctx, sub.IPNet, gatewayIP)
		printDeviceTable(devices)
	}
}

func runMonitorService() {
	// Initialize database
	dbConn, err := db.InitDB("sentinel.db")
	if err != nil {
		log.Fatalf("❌ Failed to initialize SQLite database: %v", err)
	}
	defer dbConn.Close()

	// Handle graceful shutdown context
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		fmt.Println("\n⚠️  Termination signal received. Shutting down gracefully...")
		cancel()
	}()

	// Start Background Monitor loop
	go monitor.StartMonitor(ctx, dbConn)

	// Start Web Server dashboard (blocking)
	err = web.StartWebServer(ctx, dbConn, 8080)
	if err != nil && err != http.ErrServerClosed {
		log.Fatalf("❌ Server error: %v", err)
	}

	fmt.Println("👋 LAN Sentinel stopped. Goodbye!")
}

func runListCommand() {
	dbConn, err := db.InitDB("sentinel.db")
	if err != nil {
		log.Fatalf("❌ Database connection failed: %v", err)
	}
	defer dbConn.Close()

	configObj, err := config.LoadConfig()
	if err != nil {
		fmt.Printf("❌ Failed to load config: %v\n", err)
		return
	}

	fmt.Println(colorCyan + "--- Authorized Devices List ---" + colorReset)
	if len(configObj.AuthorizedDevices) == 0 {
		fmt.Println("No devices authorized yet. Run 'netsentinel authorize <MAC> <alias>' to add one.")
	} else {
		for mac, alias := range configObj.AuthorizedDevices {
			fmt.Printf("   %-20s -> %s\n", mac, alias)
		}
	}
	fmt.Println()

	// Check who is active now
	fmt.Println(colorCyan + "--- Current Online Devices ---" + colorReset)
	devices, err := db.GetDevices(dbConn)
	if err == nil {
		fmt.Printf("%-18s %-20s %-20s %-12s\n", "IP Address", "Hostname", "MAC Address", "Status")
		fmt.Println(strings.Repeat("-", 75))

		gatewayIP := scanner.GetDefaultGateway()
		activeThreshold := time.Duration(configObj.ScanIntervalSeconds*2+5) * time.Second

		for _, d := range devices {
			if time.Since(d.LastSeen) < activeThreshold {
				status := colorRed + "Unauthorized" + colorReset
				if d.LastIP == gatewayIP {
					status = colorBlue + "Gateway" + colorReset
				} else if alias, authorized := configObj.AuthorizedDevices[strings.ToLower(d.MAC)]; authorized {
					status = colorGreen + "Authorized (" + alias + ")" + colorReset
				}

				fmt.Printf("%-18s %-20s %-20s %-12s\n",
					d.LastIP,
					scanner.Truncate(d.Hostname, 18),
					d.MAC,
					status,
				)
			}
		}
	}
}

func runAuthorizeCommand(macStr, alias string) {
	mac, err := net.ParseMAC(macStr)
	if err != nil {
		fmt.Printf("❌ Invalid MAC address format: %s\n", macStr)
		return
	}
	normalizedMac := strings.ToLower(mac.String())

	configObj, err := config.LoadConfig()
	if err != nil {
		fmt.Printf("❌ Failed to load config: %v\n", err)
		return
	}

	configObj.AuthorizedDevices[normalizedMac] = alias
	err = config.SaveConfig(configObj)
	if err != nil {
		fmt.Printf("❌ Failed to save config: %v\n", err)
		return
	}

	// Update in DB if database exists
	dbConn, err := db.InitDB("sentinel.db")
	if err == nil {
		defer dbConn.Close()
		_ = db.UpdateDeviceOrCreate(dbConn, normalizedMac, "Unknown", "Unknown", true, alias)
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

	configObj, err := config.LoadConfig()
	if err != nil {
		fmt.Printf("❌ Failed to load config: %v\n", err)
		return
	}

	if _, exists := configObj.AuthorizedDevices[normalizedMac]; !exists {
		fmt.Printf("⚠️  Device %s is not in the authorized list.\n", normalizedMac)
		return
	}

	delete(configObj.AuthorizedDevices, normalizedMac)
	err = config.SaveConfig(configObj)
	if err != nil {
		fmt.Printf("❌ Failed to save config: %v\n", err)
		return
	}

	// Update in DB
	dbConn, err := db.InitDB("sentinel.db")
	if err == nil {
		defer dbConn.Close()
		_ = db.UpdateDeviceOrCreate(dbConn, normalizedMac, "Unknown", "Unknown", false, "")
	}

	fmt.Printf("✅ Device Deauthorized: %s\n", normalizedMac)
}

func runSettingsCommand(key, value string) {
	configObj, err := config.LoadConfig()
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
		configObj.ScanIntervalSeconds = sec
		fmt.Printf("✅ Scan interval updated to %d seconds.\n", sec)

	case "notify":
		val := strings.ToLower(value)
		if val == "true" || val == "t" || val == "1" {
			configObj.EnableNotifications = true
		} else if val == "false" || val == "f" || val == "0" {
			configObj.EnableNotifications = false
		} else {
			fmt.Println("❌ Error: Notification setting must be 'true' or 'false'.")
			return
		}
		fmt.Printf("✅ Desktop notifications set to %t.\n", configObj.EnableNotifications)

	default:
		fmt.Printf("❌ Unknown setting: %s. Use 'interval' or 'notify'.\n", key)
		return
	}

	err = config.SaveConfig(configObj)
	if err != nil {
		fmt.Printf("❌ Failed to save config: %v\n", err)
	}
}

func printDeviceTable(devices []scanner.Device) {
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
			services = append(services, fmt.Sprintf("%d (%s)", port, scanner.CommonPorts[port]))
		}

		serviceStr := "None"
		if len(services) > 0 {
			serviceStr = strings.Join(services, ", ")
		}

		fmt.Printf("%-18s %-20s %-20s %-10s %s\n",
			dev.IP,
			scanner.Truncate(dev.Hostname, 18),
			dev.MAC,
			devType,
			serviceStr,
		)
	}
}
