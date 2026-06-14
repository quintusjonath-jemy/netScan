package main

import (
	"fmt"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

// ANSI Color Codes
const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorBlue   = "\033[34m"
	colorPurple = "\033[35m"
	colorCyan   = "\033[36m"
	colorGray   = "\033[90m"
)

// StartMonitor runs the stateful Wi-Fi scanner loop
func StartMonitor() {
	config, err := LoadConfig()
	if err != nil {
		fmt.Printf("❌ Failed to load config: %v\n", err)
		return
	}

	fmt.Println(colorCyan + "==================================================" + colorReset)
	fmt.Println(colorCyan + "   🛡️  LAN Sentinel: Background Monitor Mode      " + colorReset)
	fmt.Println(colorCyan + "==================================================" + colorReset)
	fmt.Printf("⏱️  Scan Interval: %d seconds\n", config.ScanIntervalSeconds)
	fmt.Printf("🔔 Desktop Alerts: %t\n", config.EnableNotifications)
	fmt.Println("Press Ctrl+C to terminate.")
	fmt.Println(colorGray + "Monitoring started... Performing initial baseline scan..." + colorReset)

	// In-memory state tracking (Key: MAC address in lowercase)
	previousDevices := make(map[string]Device)

	// Baseline Scan
	activeSubnets, err := getActiveSubnets()
	if err != nil || len(activeSubnets) == 0 {
		fmt.Printf("❌ Error: No active subnets detected.\n")
		return
	}

	// Fetch current devices for baseline
	baselineDevices := performSubnetScans(activeSubnets)
	for _, dev := range baselineDevices {
		if dev.MAC != "" && dev.MAC != "Unknown" {
			previousDevices[strings.ToLower(dev.MAC)] = dev
		}
	}

	fmt.Printf(colorGreen+"Baseline scan finished. Found %d active devices.\n\n"+colorReset, len(previousDevices))
	printStateSummary(previousDevices, config)

	// Ticker for subsequent scans
	ticker := time.NewTicker(time.Duration(config.ScanIntervalSeconds) * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		fmt.Printf("\n[%s] 🔍 Performing periodic scan...\n", time.Now().Format("15:04:05"))

		// Reload configuration to pick up any changes to authorized devices
		config, err = LoadConfig()
		if err != nil {
			fmt.Printf("⚠️  Warning: Failed to reload config: %v\n", err)
		}

		currentDevices := make(map[string]Device)
		scannedList := performSubnetScans(activeSubnets)

		for _, dev := range scannedList {
			if dev.MAC != "" && dev.MAC != "Unknown" {
				currentDevices[strings.ToLower(dev.MAC)] = dev
			}
		}

		// Detect changes
		detectStateChanges(previousDevices, currentDevices, config)

		// Update previous state
		previousDevices = currentDevices
	}
}

// performSubnetScans runs scans across all active subnets and aggregates them
func performSubnetScans(subnets []SubnetInfo) []Device {
	var allDevices []Device
	seenIPs := make(map[string]bool)
	gatewayIP := getDefaultGateway()

	for _, sub := range subnets {
		scanned := scanSubnet(sub.IPNet, gatewayIP)
		for _, dev := range scanned {
			if !seenIPs[dev.IP] {
				seenIPs[dev.IP] = true
				allDevices = append(allDevices, dev)
			}
		}
	}
	return allDevices
}

// detectStateChanges compares previous scan to current scan and logs/alerts changes
func detectStateChanges(previous map[string]Device, current map[string]Device, config *Config) {
	// 1. Detect Joins (In current, not in previous)
	for mac, curDev := range current {
		if _, exists := previous[mac]; !exists {
			// A device connected
			alias, authorized := config.AuthorizedDevices[mac]
			if authorized {
				fmt.Printf(colorGreen+"[+] JOINED (Authorized): %s (%s) | IP: %s\n"+colorReset, alias, curDev.MAC, curDev.IP)
				if config.EnableNotifications {
					triggerDesktopAlert("Device Connected (Known)", fmt.Sprintf("%s joined the network.\nIP: %s\nMAC: %s", alias, curDev.IP, curDev.MAC), false)
				}
			} else {
				// INTRUDER ALERT!
				fmt.Printf(colorRed+"[⚠️ ALERT] JOINED (UNAUTHORIZED): IP: %s | MAC: %s | Hostname: %s\n"+colorReset, curDev.IP, curDev.MAC, curDev.Hostname)
				if config.EnableNotifications {
					triggerDesktopAlert("🚨 INTRUDER ALERT!", fmt.Sprintf("Unknown device connected to Wi-Fi!\nIP: %s\nMAC: %s\nName: %s", curDev.IP, curDev.MAC, curDev.Hostname), true)
				}
			}
		} else {
			// Device existed in previous, check if IP changed
			prevDev := previous[mac]
			if prevDev.IP != curDev.IP {
				fmt.Printf(colorYellow+"[*] IP CHANGED: MAC %s shifted from %s to %s\n"+colorReset, curDev.MAC, prevDev.IP, curDev.IP)
			}
		}
	}

	// 2. Detect Leaves (In previous, not in current)
	for mac, prevDev := range previous {
		if _, exists := current[mac]; !exists {
			alias, authorized := config.AuthorizedDevices[mac]
			name := "Unknown Device"
			if authorized {
				name = alias
			}
			fmt.Printf(colorGray+"[-] LEFT: %s (%s) | Last IP: %s\n"+colorReset, name, prevDev.MAC, prevDev.IP)
			if config.EnableNotifications {
				triggerDesktopAlert("Device Disconnected", fmt.Sprintf("%s left the network.\nIP: %s", name, prevDev.IP), false)
			}
		}
	}
}

// triggerDesktopAlert runs notify-send on Linux or equivalent
func triggerDesktopAlert(title, message string, critical bool) {
	if runtime.GOOS != "linux" {
		return
	}

	urgency := "normal"
	icon := "network-wireless"
	if critical {
		urgency = "critical"
		icon = "dialog-warning"
	}

	// Execute notify-send command
	cmd := exec.Command("notify-send", "-u", urgency, "-i", icon, title, message)
	_ = cmd.Run()
}

// printStateSummary displays a summary of current active devices
func printStateSummary(devices map[string]Device, config *Config) {
	fmt.Println("Current Network Device List:")
	fmt.Printf("%-18s %-20s %-20s %-12s\n", "IP Address", "Hostname", "MAC Address", "Status")
	fmt.Println(strings.Repeat("-", 75))

	for mac, dev := range devices {
		status := colorRed + "Unauthorized" + colorReset
		if dev.IsGateway {
			status = colorBlue + "Gateway" + colorReset
		} else if alias, authorized := config.AuthorizedDevices[mac]; authorized {
			status = colorGreen + "Authorized (" + alias + ")" + colorReset
		}

		fmt.Printf("%-18s %-20s %-20s %-12s\n",
			dev.IP,
			truncate(dev.Hostname, 18),
			dev.MAC,
			status,
		)
	}
	fmt.Println()
}
