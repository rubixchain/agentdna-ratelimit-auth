// main.go
package main

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	_ "github.com/joho/godotenv/autoload"
	_ "github.com/mattn/go-sqlite3"
)

const (
	maxRequests  = 100
	apiKeyHeader = "X-API-Key"
)

type User struct {
	Email       string    `json:"email"`
	APIKey      string    `json:"api_key"`
	RequestCount int      `json:"request_count"`
	CreatedAt   time.Time `json:"created_at"`
}

type RateLimiter struct {
	db      *sql.DB
	proxy   *httputil.ReverseProxy
	mu      sync.RWMutex
	baseURL *url.URL
}

// billablePaths contains endpoints that should consume from the quota.
var billablePaths = map[string]bool{
	"/api/execute-nft":            true,
	"/api/deploy-nft":             true,
}

func isBillable(path string) bool {
	return billablePaths[path]
}

func initConfig() (string, *url.URL) {
	dbFile := os.Getenv("API_USAGE_DB")
	backendURLStr := os.Getenv("RUBIX_NODE_URL")

	if dbFile == "" {
		log.Fatal("API_USAGE_DB environment variable is required")
	}
	if backendURLStr == "" {
		log.Fatal("RUBIX_NODE_URL environment variable is required")
	}

	u, err := url.Parse(backendURLStr)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		log.Fatalf("RUBIX_NODE_URL invalid format (must be http(s)://host:port): %s", backendURLStr)
	}

	if strings.Contains(dbFile, "\x00") {
		log.Fatal("API_USAGE_DB contains invalid characters")
	}

	log.Printf("DB file: %s", dbFile)
	log.Printf("Backend: %s", backendURLStr)

	return dbFile, u
}

func NewRateLimiter(dbFile string, backendURL *url.URL) *RateLimiter {
	db, err := sql.Open("sqlite3", dbFile)
	if err != nil {
		log.Fatalf("Failed to open DB %s: %v", dbFile, err)
	}

	_, err = db.Exec("PRAGMA journal_mode=WAL;")
	if err != nil {
		log.Printf("Warning: WAL mode not enabled: %v", err)
	}

	// Users table with email as PRIMARY KEY
	// NFTs table with email as FOREIGN KEY to users.email
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS users (
			email TEXT PRIMARY KEY,
			api_key TEXT UNIQUE NOT NULL,
			request_count INTEGER DEFAULT 0,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		);
		CREATE INDEX IF NOT EXISTS idx_api_key ON users(api_key);

		CREATE TABLE IF NOT EXISTS nfts (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			nft_id TEXT NOT NULL,
			nft_name TEXT,
			email TEXT NOT NULL,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		);
		CREATE INDEX IF NOT EXISTS idx_nft_id ON nfts(nft_id);
		CREATE INDEX IF NOT EXISTS idx_nft_email ON nfts(email);
	`)
	if err != nil {
		log.Fatalf("Failed to create tables: %v", err)
	}

	proxy := httputil.NewSingleHostReverseProxy(backendURL)

	return &RateLimiter{
		db:      db,
		proxy:   proxy,
		baseURL: backendURL,
	}
}

// lookupUserByAPIKey returns User by API key.
func (rl *RateLimiter) lookupUserByAPIKey(key string) (*User, error) {
	var user User
	err := rl.db.QueryRow(`
		SELECT email, api_key, request_count, created_at
		FROM users WHERE api_key = ?`, key).Scan(
		&user.Email,
		&user.APIKey,
		&user.RequestCount,
		&user.CreatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("invalid API key")
	}
	if err != nil {
		return nil, fmt.Errorf("database error: %v", err)
	}
	return &user, nil
}


// validateAndIncrement: checks key + count and increments atomically.
func (rl *RateLimiter) validateAndIncrement(key string) (*User, error) {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	// Start transaction
	tx, err := rl.db.Begin()
	if err != nil {
		return nil, fmt.Errorf("failed to start transaction: %v", err)
	}
	defer tx.Rollback()

	var user User
	err = tx.QueryRow(`
		SELECT email, api_key, request_count, created_at
		FROM users WHERE api_key = ?`, key).Scan(
		&user.Email,
		&user.APIKey,
		&user.RequestCount,
		&user.CreatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("invalid API key")
	}
	if err != nil {
		return nil, fmt.Errorf("database error: %v", err)
	}

	if user.RequestCount >= maxRequests {
		return nil, fmt.Errorf("rate limit exceeded")
	}

	// Increment request count
	_, err = tx.Exec(
		"UPDATE users SET request_count = request_count + 1 WHERE api_key = ?",
		key,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to increment: %v", err)
	}

	// Reload user with new count
	err = tx.QueryRow(`
		SELECT email, api_key, request_count, created_at
		FROM users WHERE api_key = ?`, key).Scan(
		&user.Email,
		&user.APIKey,
		&user.RequestCount,
		&user.CreatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to get final count: %v", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("failed to commit transaction: %v", err)
	}

	return &user, nil
}

// nftPayload models the deploy-nft request body.
type nftPayload struct {
	NFT        string  `json:"nft"`
	DID        string  `json:"did"`
	QuorumType int     `json:"quorum_type"`
	NFTValue   float64 `json:"nft_value"`
	NFTData    string  `json:"nft_data"`
	NFTMetadata string `json:"nft_metadata"`
	NFTFileName string `json:"nft_file_name"`
}

// extractAgentName parses nftData string like "{'agent_name': 'mike'}" to extract agent_name.
func extractAgentName(nftData string) string {
	// Convert Python-style single quotes to JSON double quotes
	normalized := strings.ReplaceAll(nftData, "'", "\"")
	
	var obj map[string]interface{}
	if err := json.Unmarshal([]byte(normalized), &obj); err != nil {
		return ""
	}

	agentName, ok := obj["agent_name"].(string)
	if !ok {
		return ""
	}
	return agentName
}

func (rl *RateLimiter) storeNFT(email, nftID, nftName string) error {
	_, err := rl.db.Exec(
		`INSERT INTO nfts (nft_id, nft_name, email) VALUES (?, ?, ?)`,
		nftID,
		nftName,
		email,
	)
	return err
}

// proxyHandler: main entry point for ALL blockchain traffic.
func (rl *RateLimiter) proxyHandler(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	billable := isBillable(path)

	var (
		user *User
		err  error
	)

	if billable {
		apiKey := r.Header.Get(apiKeyHeader)
		if apiKey == "" {
			http.Error(w, `{"error":"API key required in `+apiKeyHeader+` header"}`, http.StatusUnauthorized)
			return
		}

		user, err = rl.validateAndIncrement(apiKey)
	}

	if err != nil {
		status := http.StatusUnauthorized
		if err.Error() == "rate limit exceeded" {
			status = http.StatusTooManyRequests
		}
		http.Error(w, `{"error":"`+err.Error()+`"}`, status)
		return
	}

	// SPECIAL HANDLING: For /api/deploy-nft, extract and store NFT info
	if strings.Contains(path, "/api/deploy-nft") && r.Method == http.MethodPost {
		// Read and buffer the body
		bodyBytes, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, `{"error":"failed to read request body"}`, http.StatusBadRequest)
			return
		}
		r.Body.Close()

		// Reconstruct body for proxying downstream
		r.Body = io.NopCloser(bytes.NewReader(bodyBytes))

		// Parse NFT payload
		var payload nftPayload
		if err := json.Unmarshal(bodyBytes, &payload); err == nil {
			// Extract agent_name from nftData
			agentName := extractAgentName(payload.NFTData)
			// Store in nfts table with email foreign key
			if err := rl.storeNFT(user.Email, payload.NFT, agentName); err != nil {
				log.Printf("Failed to store NFT for %s: %v", user.Email, err)
			} else {
				log.Printf("✅ Stored NFT: id=%s, name=%s, email=%s", payload.NFT, agentName, user.Email)
			}
		}
	}

	// Pass user metadata to blockchain node
	r.Header.Set("X-User-Email", user.Email)
	r.Header.Set("X-Request-Count", fmt.Sprintf("%d/%d", user.RequestCount, maxRequests))
	r.Header.Set("X-Billable", fmt.Sprintf("%t", isBillable(path)))

	// Proxy to blockchain node
	rl.proxy.ServeHTTP(w, r)
}

func (rl *RateLimiter) healthz(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func (rl *RateLimiter) adminAddUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Email string `json:"email"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	if req.Email == "" {
		http.Error(w, "Email required", http.StatusBadRequest)
		return
	}

	// Check if email already exists (email is PRIMARY KEY)
	var existingEmail string
	err := rl.db.QueryRow("SELECT email FROM users WHERE email = ?", req.Email).Scan(&existingEmail)
	if err == nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusConflict)
		json.NewEncoder(w).Encode(map[string]string{
			"error":   "email_already_exists",
			"message": fmt.Sprintf("Email %s already registered", req.Email),
		})
		return
	}
	if err != sql.ErrNoRows {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	// Create new user
	apiKey := uuid.New().String()
	_, err = rl.db.Exec(
		`INSERT INTO users (email, api_key) VALUES (?, ?)`,
		req.Email, apiKey,
	)
	if err != nil {
		http.Error(w, "Failed to create user", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"api_key": apiKey,
		"message": "API key created successfully",
	})
}

func (rl *RateLimiter) getNFTByEmail(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "GET only", http.StatusMethodNotAllowed)
		return
	}

	email := r.URL.Query().Get("email")
	if email == "" {
		http.Error(w, "Email query parameter required", http.StatusBadRequest)
		return
	}

	rows, err := rl.db.Query(
		`SELECT nft_id, nft_name FROM nfts WHERE email = ?`,
		email,
	)
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var nfts []map[string]string
	for rows.Next() {
		var nftID, nftName string
		if err := rows.Scan(&nftID, &nftName); err != nil {
			http.Error(w, "Database error", http.StatusInternalServerError)
			return
		}

		nfts = append(nfts, map[string]string{
			"nft_id":   nftID,
			"nft_name": nftName,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"email": email,
		"nfts":  nfts,
	})
}

func main() {
    dbFile, backendURL := initConfig()
    rl := NewRateLimiter(dbFile, backendURL)
    defer rl.db.Close()

    // Management endpoints FIRST (specific routes)
    http.HandleFunc("/healthz", rl.healthz)
    http.HandleFunc("/admin/add-user", rl.adminAddUser)
    http.HandleFunc("/get-nft-by-email", rl.getNFTByEmail)  // ← Now works!

    // Catch ALL OTHER blockchain traffic LAST (catch-all)
    http.HandleFunc("/", rl.proxyHandler)  // ← Only non-management paths
    
    log.Printf("Rate limiter + NFT proxy starting on :8080 -> %s", backendURL.String())
    log.Fatal(http.ListenAndServe(":8080", nil))
}