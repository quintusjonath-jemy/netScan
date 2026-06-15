package monitor

import (
	"context"
	"database/sql"
	"fmt"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"netscan/internal/config"
	"netscan/internal/db"
	"netscan/internal/scanner"
)

// NetworkEvent represents a real-time event broadcasted to the Web UI
type NetworkEvent struct {
	Type      string      `json:"type"` // "join", "leave", "ip_change", "scan_complete"
	Timestamp time.Time   `json:"timestamp"`
	Data      interface{} `json:"data"`
}

// Global Event Channel for Web Server broadcasting
var EventBus = make(chan NetworkEvent, 100)

// StartMonitor launches the stateful network monitor loop
func StartMonitor(ctx context.Context, dbConn *sql.DB) {
	conf, err := config.LoadConfig()
	if err != nil {
		fmt.Printf("❌ Failed to load config: %v\n", err)
		return
	}

	fmt.Println("🛡️  LAN Sentinel monitor started...")

	// In-memory state tracking
	previousDevices := make(map[string]scanner.Device)

	// Baseline Scan
	activeSubnets, err := scanner.GetActiveSubnets()
	if err != nil || len(activeSubnets) == 0 {
		fmt.Printf("❌ Error: No active subnets detected.\n")
		return
	}

	// Initialize baseline devices
	baselineDevices := performSubnetScans(ctx, activeSubnets)
	for _, dev := range baselineDevices {
		if dev.MAC != "" && dev.MAC != "Unknown" {
			macKey := strings.ToLower(dev.MAC)
			previousDevices[macKey] = dev

			// Update SQLite database with baseline active status
			alias, authorized := conf.AuthorizedDevices[macKey]
			_ = db.UpdateDeviceOrCreate(dbConn, dev.MAC, dev.IP, dev.Hostname, authorized, alias)
		}
	}

	// Broadcast baseline complete
	broadcast(NetworkEvent{
		Type:      "scan_complete",
		Timestamp: time.Now(),
		Data:      "Initial baseline scan completed",
	})

	ticker := time.NewTicker(time.Duration(conf.ScanIntervalSeconds) * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			fmt.Println("🛑 Monitoring loop terminated gracefully.")
			return
		case <-ticker.C:
			// Reload config for live updates
			conf, err = config.LoadConfig()
			if err != nil {
				fmt.Printf("⚠️  Failed to reload config: %v\n", err)
			}

			currentDevices := make(map[string]scanner.Device)
			scannedList := performSubnetScans(ctx, activeSubnets)

			// Check cancellation
			select {
			case <-ctx.Done():
				return
			default:
			}

			for _, dev := range scannedList {
				if dev.MAC != "" && dev.MAC != "Unknown" {
					currentDevices[strings.ToLower(dev.MAC)] = dev
				}
			}

			// Detect state changes and log them to DB/channel
			detectStateChanges(ctx, dbConn, previousDevices, currentDevices, conf)

			previousDevices = currentDevices

			broadcast(NetworkEvent{
				Type:      "scan_complete",
				Timestamp: time.Now(),
				Data:      fmt.Sprintf("Periodic scan finished. %d devices online.", len(currentDevices)),
			})
		}
	}
}

// performSubnetScans runs scans across all active subnets and aggregates them
func performSubnetScans(ctx context.Context, subnets []scanner.SubnetInfo) []scanner.Device {
	var allDevices []scanner.Device
	seenIPs := make(map[string]bool)
	gatewayIP := scanner.GetDefaultGateway()

	for _, sub := range subnets {
		select {
		case <-ctx.Done():
			return nil
		default:
			scanned := scanner.ScanSubnet(ctx, sub.IPNet, gatewayIP)
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

// detectStateChanges checks for joined, left, or altered devices
func detectStateChanges(ctx context.Context, dbConn *sql.DB, previous map[string]scanner.Device, current map[string]scanner.Device, conf *config.Config) {
	// 1. Detect Joins
	for mac, curDev := range current {
		prevDev, existed := previous[mac]
		alias, authorized := conf.AuthorizedDevices[mac]

		if !existed {
			// Device newly joined
			_ = db.UpdateDeviceOrCreate(dbConn, curDev.MAC, curDev.IP, curDev.Hostname, authorized, alias)
			_ = db.LogEvent(dbConn, curDev.MAC, curDev.IP, curDev.Hostname, "join")

			if authorized {
				fmt.Printf("💡 Device Connected: %s (%s) | IP: %s\n", alias, curDev.MAC, curDev.IP)
				broadcast(NetworkEvent{
					Type:      "join",
					Timestamp: time.Now(),
					Data:      curDev,
				})
				if conf.EnableNotifications {
					triggerDesktopAlert("Device Connected", fmt.Sprintf("%s joined the network.\nIP: %s", alias, curDev.IP), false)
				}
			} else {
				// Intruder Alert!
				alertMsg := fmt.Sprintf("Intruder connected! IP: %s, MAC: %s, Name: %s", curDev.IP, curDev.MAC, curDev.Hostname)
				fmt.Println("🚨 " + alertMsg)
				_ = db.LogAlert(dbConn, curDev.MAC, curDev.IP, curDev.Hostname, "Unauthorized intruder connection detected")
				broadcast(NetworkEvent{
					Type:      "alert",
					Timestamp: time.Now(),
					Data:      curDev,
				})
				if conf.EnableNotifications {
					triggerDesktopAlert("🚨 INTRUDER ALERT!", fmt.Sprintf("Unknown device connected!\nIP: %s\nMAC: %s", curDev.IP, curDev.MAC), true)
				}
			}
		} else if prevDev.IP != curDev.IP {
			// IP Changed
			_ = db.UpdateDeviceOrCreate(dbConn, curDev.MAC, curDev.IP, curDev.Hostname, authorized, alias)
			_ = db.LogEvent(dbConn, curDev.MAC, curDev.IP, curDev.Hostname, "ip_change")
			fmt.Printf("🔄 IP Shift: MAC %s shifted from %s to %s\n", curDev.MAC, prevDev.IP, curDev.IP)

			broadcast(NetworkEvent{
				Type:      "ip_change",
				Timestamp: time.Now(),
				Data:      curDev,
			})
		}
	}

	// 2. Detect Leaves
	for mac, prevDev := range previous {
		if _, exists := current[mac]; !exists {
			alias, authorized := conf.AuthorizedDevices[mac]
			name := "Unknown Device"
			if authorized {
				name = alias
			}

			_ = db.LogEvent(dbConn, prevDev.MAC, prevDev.IP, prevDev.Hostname, "leave")
			fmt.Printf("🔌 Device Left: %s (%s) | Last IP: %s\n", name, prevDev.MAC, prevDev.IP)

			broadcast(NetworkEvent{
				Type:      "leave",
				Timestamp: time.Now(),
				Data:      prevDev,
			})

			if conf.EnableNotifications {
				triggerDesktopAlert("Device Disconnected", fmt.Sprintf("%s left the network.\nIP: %s", name, prevDev.IP), false)
			}
		}
	}
}

// triggerDesktopAlert executes notify-send on Linux desktop
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

	cmd := exec.Command("notify-send", "-u", urgency, "-i", icon, title, message)
	_ = cmd.Run()
}

// broadcast sends a network event to the EventBus in a non-blocking manner
func broadcast(event NetworkEvent) {
	select {
	case EventBus <- event:
	default:
		// Drop event if bus channel is full to avoid blocking monitoring loops
	}
}
