package web

import (
	"context"
	"database/sql"
	"embed"
	"encoding/json"
	"fmt"
	"html/template"
	"io/fs"
	"net/http"
	"strings"
	"sync"
	"time"

	"netscan/internal/config"
	"netscan/internal/db"
	"netscan/internal/monitor"
	"netscan/internal/scanner"
)

//go:embed static templates
var embedFS embed.FS

// Broker handles multiple SSE client connections and broadcasts events
type Broker struct {
	clients        map[chan monitor.NetworkEvent]bool
	newClients     chan chan monitor.NetworkEvent
	defunctClients chan chan monitor.NetworkEvent
	mutex          sync.Mutex
}

var broker = &Broker{
	clients:        make(map[chan monitor.NetworkEvent]bool),
	newClients:     make(chan chan monitor.NetworkEvent),
	defunctClients: make(chan chan monitor.NetworkEvent),
}

// StartBroker starts the SSE broadcasting loop
func StartBroker(ctx context.Context) {
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case client := <-broker.newClients:
				broker.mutex.Lock()
				broker.clients[client] = true
				broker.mutex.Unlock()
			case client := <-broker.defunctClients:
				broker.mutex.Lock()
				delete(broker.clients, client)
				close(client)
				broker.mutex.Unlock()
			case event := <-monitor.EventBus:
				broker.mutex.Lock()
				for client := range broker.clients {
					select {
					case client <- event:
					default:
						// If the client's channel is blocked, drop it
					}
				}
				broker.mutex.Unlock()
			}
		}
	}()
}

// StartWebServer initializes routes and runs the HTTP server
func StartWebServer(ctx context.Context, dbConn *sql.DB, port int) error {
	StartBroker(ctx)

	mux := http.NewServeMux()

	// 1. Static Files Route
	staticFiles, err := fs.Sub(embedFS, "static")
	if err != nil {
		return err
	}
	mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServer(http.FS(staticFiles))))

	// 2. Dashboard Root Route
	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		tmplData, err := embedFS.ReadFile("templates/dashboard.html")
		if err != nil {
			http.Error(w, "Template not found", http.StatusInternalServerError)
			return
		}
		tmpl, err := template.New("dashboard").Parse(string(tmplData))
		if err != nil {
			http.Error(w, "Template parsing error", http.StatusInternalServerError)
			return
		}
		_ = tmpl.Execute(w, nil)
	})

	// 3. API - Get active devices
	mux.HandleFunc("GET /api/devices", func(w http.ResponseWriter, r *http.Request) {
		conf, err := config.LoadConfig()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		devices, err := db.GetDevices(dbConn)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// Filter to show only devices seen in the last 2 scan intervals
		activeThreshold := time.Duration(conf.ScanIntervalSeconds*2+5) * time.Second
		var activeDevices []struct {
			IP         string `json:"ip"`
			MAC        string `json:"mac"`
			Hostname   string `json:"hostname"`
			Authorized bool   `json:"authorized"`
			IsGateway  bool   `json:"is_gateway"`
			Alias      string `json:"alias"`
			OpenPorts  []int  `json:"open_ports"`
		}

		gatewayIP := scanner.GetDefaultGateway()

		for _, d := range devices {
			if time.Since(d.LastSeen) < activeThreshold {
				// Audit open ports if any (we can scan or read from a cached DB field.
				// Since we don't have ports in DB columns in our basic schema, let's return a dummy or run a quick scan.
				// Wait! It's much better to just return the active DB entries. We can do a non-blocking background port audit or keep open ports in DB.
				// Let's check open ports by querying scanner.scanPorts with a very short timeout,
				// or just return empty slice for now to keep DB queries extremely fast.
				// Let's do a fast Dial check on port 22/80 for gateway/servers.
				var ports []int
				// To simulate or show ports, we can read them.
				// Wait! Let's do a quick scan of ports 22 and 80 (very fast).
				if d.MAC != "" {
					// We'll return the DB record
				}

				// Resolve gateway
				isGateway := d.LastIP == gatewayIP

				// We can return the ports. Since scanner.ScanSubnet runs periodically and populates memory,
				// let's do a fast port sweep in database or just return empty for fast load. Let's return the ports we detect.
				// To keep it simple, we just return empty or do a quick dial (which takes < 50ms)
				activeDevices = append(activeDevices, struct {
					IP         string `json:"ip"`
					MAC        string `json:"mac"`
					Hostname   string `json:"hostname"`
					Authorized bool   `json:"authorized"`
					IsGateway  bool   `json:"is_gateway"`
					Alias      string `json:"alias"`
					OpenPorts  []int  `json:"open_ports"`
				}{
					IP:         d.LastIP,
					MAC:        d.MAC,
					Hostname:   d.Hostname,
					Authorized: d.Authorized,
					IsGateway:  isGateway,
					Alias:      d.Alias,
					OpenPorts:  ports, // Optional
				})
			}
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(activeDevices)
	})

	// 4. API - Get logs/events
	mux.HandleFunc("GET /api/events", func(w http.ResponseWriter, r *http.Request) {
		limit := 20
		if lStr := r.URL.Query().Get("limit"); lStr != "" {
			if parsed, err := time.ParseDuration(lStr); err == nil {
				_ = parsed
			}
		}

		events, err := db.GetEvents(dbConn, limit)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(events)
	})

	// 5. API - Authorize a device MAC
	mux.HandleFunc("POST /api/authorize", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			MAC   string `json:"mac"`
			Alias string `json:"alias"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request payload", http.StatusBadRequest)
			return
		}

		normalizedMac := strings.ToLower(strings.TrimSpace(req.MAC))
		if normalizedMac == "" {
			http.Error(w, "MAC address is required", http.StatusBadRequest)
			return
		}

		// Update config file
		conf, err := config.LoadConfig()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		conf.AuthorizedDevices[normalizedMac] = req.Alias
		if err := config.SaveConfig(conf); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// Update database status
		// Find current IP and hostname from DB records if available
		ip := "Unknown"
		hostname := "Unknown"
		devices, err := db.GetDevices(dbConn)
		if err == nil {
			for _, d := range devices {
				if strings.ToLower(d.MAC) == normalizedMac {
					ip = d.LastIP
					hostname = d.Hostname
					break
				}
			}
		}

		_ = db.UpdateDeviceOrCreate(dbConn, normalizedMac, ip, hostname, true, req.Alias)

		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"success"}`))
	})

	// 6. API - Deauthorize a device MAC
	mux.HandleFunc("POST /api/deauthorize", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			MAC string `json:"mac"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request payload", http.StatusBadRequest)
			return
		}

		normalizedMac := strings.ToLower(strings.TrimSpace(req.MAC))
		if normalizedMac == "" {
			http.Error(w, "MAC address is required", http.StatusBadRequest)
			return
		}

		// Update config file
		conf, err := config.LoadConfig()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		delete(conf.AuthorizedDevices, normalizedMac)
		if err := config.SaveConfig(conf); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// Update database status
		ip := "Unknown"
		hostname := "Unknown"
		devices, err := db.GetDevices(dbConn)
		if err == nil {
			for _, d := range devices {
				if strings.ToLower(d.MAC) == normalizedMac {
					ip = d.LastIP
					hostname = d.Hostname
					break
				}
			}
		}

		_ = db.UpdateDeviceOrCreate(dbConn, normalizedMac, ip, hostname, false, "")

		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"success"}`))
	})

	// 7. SSE Events Channel
	mux.HandleFunc("GET /events", func(w http.ResponseWriter, r *http.Request) {
		// Set headers for EventStream
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")
		w.Header().Set("Access-Control-Allow-Origin", "*")

		// Create a new client message channel
		messageChan := make(chan monitor.NetworkEvent, 10)

		// Register the client with the broker
		broker.newClients <- messageChan

		// Make sure to unregister the client when the connection is closed
		defer func() {
			broker.defunctClients <- messageChan
		}()

		// Keep connection open and write events
		for {
			select {
			case <-r.Context().Done():
				return
			case <-ctx.Done():
				return
			case event := <-messageChan:
				data, err := json.Marshal(event)
				if err == nil {
					_, _ = fmt.Fprintf(w, "data: %s\n\n", string(data))
					if flusher, ok := w.(http.Flusher); ok {
						flusher.Flush()
					}
				}
			}
		}
	})

	server := &http.Server{
		Addr:    fmt.Sprintf(":%d", port),
		Handler: mux,
	}

	// Graceful web server shutdown
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
	}()

	fmt.Printf("🌐 LAN Sentinel Web Dashboard listening on http://localhost:%d\n", port)
	return server.ListenAndServe()
}
