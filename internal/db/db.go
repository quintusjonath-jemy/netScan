package db

import (
	"database/sql"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

// DeviceRecord represents a saved device in the database
type DeviceRecord struct {
	MAC        string    `json:"mac"`
	LastIP     string    `json:"last_ip"`
	Hostname   string    `json:"hostname"`
	Alias      string    `json:"alias"`
	Authorized bool      `json:"authorized"`
	LastSeen   time.Time `json:"last_seen"`
}

// EventRecord represents a log of a join/leave/IP change event
type EventRecord struct {
	ID        int       `json:"id"`
	MAC       string    `json:"mac"`
	IP        string    `json:"ip"`
	Hostname  string    `json:"hostname"`
	EventType string    `json:"event_type"` // "join", "leave", "ip_change"
	Timestamp time.Time `json:"timestamp"`
}

// AlertRecord represents an intrusion log
type AlertRecord struct {
	ID        int       `json:"id"`
	MAC       string    `json:"mac"`
	IP        string    `json:"ip"`
	Hostname  string    `json:"hostname"`
	Message   string    `json:"message"`
	Timestamp time.Time `json:"timestamp"`
}

// InitDB initializes the SQLite database and creates tables if they do not exist
func InitDB(dbPath string) (*sql.DB, error) {
	database, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, err
	}

	// Create tables
	queries := []string{
		`CREATE TABLE IF NOT EXISTS devices (
			mac TEXT PRIMARY KEY,
			last_ip TEXT,
			hostname TEXT,
			alias TEXT,
			authorized INTEGER,
			last_seen DATETIME
		);`,
		`CREATE TABLE IF NOT EXISTS events (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			mac TEXT,
			ip TEXT,
			hostname TEXT,
			event_type TEXT,
			timestamp DATETIME
		);`,
		`CREATE TABLE IF NOT EXISTS alerts (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			mac TEXT,
			ip TEXT,
			hostname TEXT,
			message TEXT,
			timestamp DATETIME
		);`,
	}

	for _, query := range queries {
		if _, err := database.Exec(query); err != nil {
			database.Close()
			return nil, err
		}
	}

	return database, nil
}

// LogEvent registers a network join/leave/change event
func LogEvent(dbConn *sql.DB, mac, ip, hostname, eventType string) error {
	_, err := dbConn.Exec(
		"INSERT INTO events (mac, ip, hostname, event_type, timestamp) VALUES (?, ?, ?, ?, ?)",
		strings.ToLower(mac), ip, hostname, eventType, time.Now(),
	)
	return err
}

// LogAlert registers an unauthorized device intrusion alert
func LogAlert(dbConn *sql.DB, mac, ip, hostname, message string) error {
	_, err := dbConn.Exec(
		"INSERT INTO alerts (mac, ip, hostname, message, timestamp) VALUES (?, ?, ?, ?, ?)",
		strings.ToLower(mac), ip, hostname, message, time.Now(),
	)
	return err
}

// UpdateDeviceOrCreate updates device status or creates a new device entry
func UpdateDeviceOrCreate(dbConn *sql.DB, mac, ip, hostname string, authorized bool, alias string) error {
	mac = strings.ToLower(mac)
	var count int
	err := dbConn.QueryRow("SELECT COUNT(*) FROM devices WHERE mac = ?", mac).Scan(&count)
	if err != nil {
		return err
	}

	authVal := 0
	if authorized {
		authVal = 1
	}

	if count > 0 {
		// Update
		// If alias is empty, keep the existing alias
		if alias == "" {
			_, err = dbConn.Exec(
				"UPDATE devices SET last_ip = ?, hostname = ?, authorized = ?, last_seen = ? WHERE mac = ?",
				ip, hostname, authVal, time.Now(), mac,
			)
		} else {
			_, err = dbConn.Exec(
				"UPDATE devices SET last_ip = ?, hostname = ?, authorized = ?, alias = ?, last_seen = ? WHERE mac = ?",
				ip, hostname, authVal, alias, time.Now(), mac,
			)
		}
	} else {
		// Create
		_, err = dbConn.Exec(
			"INSERT INTO devices (mac, last_ip, hostname, alias, authorized, last_seen) VALUES (?, ?, ?, ?, ?, ?)",
			mac, ip, hostname, alias, authVal, time.Now(),
		)
	}
	return err
}

// GetDevices returns all saved devices
func GetDevices(dbConn *sql.DB) ([]DeviceRecord, error) {
	rows, err := dbConn.Query("SELECT mac, last_ip, hostname, alias, authorized, last_seen FROM devices ORDER BY last_seen DESC")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var records []DeviceRecord
	for rows.Next() {
		var rec DeviceRecord
		var authInt int
		err := rows.Scan(&rec.MAC, &rec.LastIP, &rec.Hostname, &rec.Alias, &authInt, &rec.LastSeen)
		if err != nil {
			return nil, err
		}
		rec.Authorized = authInt == 1
		records = append(records, rec)
	}
	return records, nil
}

// GetEvents returns the last N logged events
func GetEvents(dbConn *sql.DB, limit int) ([]EventRecord, error) {
	rows, err := dbConn.Query("SELECT id, mac, ip, hostname, event_type, timestamp FROM events ORDER BY timestamp DESC LIMIT ?", limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var records []EventRecord
	for rows.Next() {
		var rec EventRecord
		err := rows.Scan(&rec.ID, &rec.MAC, &rec.IP, &rec.Hostname, &rec.EventType, &rec.Timestamp)
		if err != nil {
			return nil, err
		}
		records = append(records, rec)
	}
	return records, nil
}

// GetAlerts returns the last N logged alerts
func GetAlerts(dbConn *sql.DB, limit int) ([]AlertRecord, error) {
	rows, err := dbConn.Query("SELECT id, mac, ip, hostname, message, timestamp FROM alerts ORDER BY timestamp DESC LIMIT ?", limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var records []AlertRecord
	for rows.Next() {
		var rec AlertRecord
		err := rows.Scan(&rec.ID, &rec.MAC, &rec.IP, &rec.Hostname, &rec.Message, &rec.Timestamp)
		if err != nil {
			return nil, err
		}
		records = append(records, rec)
	}
	return records, nil
}
