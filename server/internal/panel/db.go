package panel

import (
	"database/sql"
	"fmt"
	"time"

	"golang.org/x/crypto/bcrypt"
	_ "modernc.org/sqlite"
)

type DB struct {
	*sql.DB
}

func NewDB(dsn string) (*DB, error) {
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}

	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("ping db: %w", err)
	}

	if err := initSchema(db); err != nil {
		return nil, fmt.Errorf("init schema: %w", err)
	}

	return &DB{db}, nil
}

func initSchema(db *sql.DB) error {
	queries := []string{
		`CREATE TABLE IF NOT EXISTS admin_users (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			username TEXT UNIQUE NOT NULL,
			password_hash TEXT NOT NULL,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS client_keys (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT NOT NULL,
			secret_key TEXT NOT NULL,
			traffic_limit_bytes INTEGER DEFAULT 0,
			traffic_used_up INTEGER DEFAULT 0,
			traffic_used_down INTEGER DEFAULT 0,
			enabled BOOLEAN DEFAULT 1,
			expires_at DATETIME,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS traffic_stats (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			client_key_id INTEGER NOT NULL,
			timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
			bytes_up INTEGER DEFAULT 0,
			bytes_down INTEGER DEFAULT 0,
			FOREIGN KEY(client_key_id) REFERENCES client_keys(id) ON DELETE CASCADE
		)`,
		`CREATE TABLE IF NOT EXISTS panel_config (
			key TEXT PRIMARY KEY,
			value TEXT NOT NULL
		)`,
	}

	for _, q := range queries {
		if _, err := db.Exec(q); err != nil {
			return err
		}
	}

	var count int
	err := db.QueryRow(`SELECT count(*) FROM admin_users WHERE username = 'admin'`).Scan(&count)
	if err != nil {
		return err
	}
	if count == 0 {
		hash, _ := bcrypt.GenerateFromPassword([]byte("admin"), bcrypt.DefaultCost)
		_, err = db.Exec(`INSERT INTO admin_users (username, password_hash) VALUES (?, ?)`, "admin", string(hash))
		if err != nil {
			return err
		}
	}
	return nil
}

func (db *DB) CreateUser(username, password string) error {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	_, err = db.Exec(`INSERT INTO admin_users (username, password_hash) VALUES (?, ?)`, username, string(hash))
	return err
}

func (db *DB) ValidateUser(username, password string) bool {
	var hash string
	err := db.QueryRow(`SELECT password_hash FROM admin_users WHERE username = ?`, username).Scan(&hash)
	if err != nil {
		return false
	}
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
}

type ClientKey struct {
	ID                int        `json:"id"`
	Name              string     `json:"name"`
	SecretKey         string     `json:"secret_key"`
	TrafficLimitBytes int64      `json:"traffic_limit_bytes"`
	TrafficUsedUp     int64      `json:"traffic_used_up"`
	TrafficUsedDown   int64      `json:"traffic_used_down"`
	Enabled           bool       `json:"enabled"`
	ExpiresAt         *time.Time `json:"expires_at"`
	CreatedAt         time.Time  `json:"created_at"`
}

func (db *DB) ListClientKeys() ([]ClientKey, error) {
	rows, err := db.Query(`SELECT id, name, secret_key, traffic_limit_bytes, traffic_used_up, traffic_used_down, enabled, expires_at, created_at FROM client_keys`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var keys []ClientKey
	for rows.Next() {
		var k ClientKey
		var expiresAt sql.NullTime
		if err := rows.Scan(&k.ID, &k.Name, &k.SecretKey, &k.TrafficLimitBytes, &k.TrafficUsedUp, &k.TrafficUsedDown, &k.Enabled, &expiresAt, &k.CreatedAt); err != nil {
			return nil, err
		}
		if expiresAt.Valid {
			k.ExpiresAt = &expiresAt.Time
		}
		keys = append(keys, k)
	}
	return keys, nil
}

func (db *DB) CreateClientKey(name, secretKey string, limit int64, expiresAt *time.Time) error {
	if expiresAt != nil {
		_, err := db.Exec(`INSERT INTO client_keys (name, secret_key, traffic_limit_bytes, expires_at) VALUES (?, ?, ?, ?)`, name, secretKey, limit, *expiresAt)
		return err
	}
	_, err := db.Exec(`INSERT INTO client_keys (name, secret_key, traffic_limit_bytes) VALUES (?, ?, ?)`, name, secretKey, limit)
	return err
}

func (db *DB) DeleteClientKey(id int) error {
	_, err := db.Exec(`DELETE FROM client_keys WHERE id = ?`, id)
	return err
}

func (db *DB) UpdateTraffic(clientKeyID int, up, down int64) error {
	_, err := db.Exec(`UPDATE client_keys SET traffic_used_up = traffic_used_up + ?, traffic_used_down = traffic_used_down + ? WHERE id = ?`, up, down, clientKeyID)
	if err != nil {
		return err
	}
	_, err = db.Exec(`INSERT INTO traffic_stats (client_key_id, bytes_up, bytes_down) VALUES (?, ?, ?)`, clientKeyID, up, down)
	return err
}

func (db *DB) GetTrafficStats(period string) ([]map[string]interface{}, error) {
	// Simple implementation
	return nil, nil
}

func (db *DB) GetPanelConfig(key string) (string, error) {
	var val string
	err := db.QueryRow(`SELECT value FROM panel_config WHERE key = ?`, key).Scan(&val)
	if err != nil {
		if err == sql.ErrNoRows {
			return "", nil
		}
		return "", err
	}
	return val, nil
}

func (db *DB) SetPanelConfig(key, value string) error {
	_, err := db.Exec(`INSERT INTO panel_config (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = ?`, key, value, value)
	return err
}
