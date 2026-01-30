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

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	_ "github.com/joho/godotenv/autoload"
	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/bcrypt"
)

const (
	maxRequests            = 100
	apiKeyHeader           = "X-API-Key"
	agentDescriptionHeader = "X-Agent-Description"
	agentRepoHeader        = "X-Agent-Repo"
)

type User struct {
	Email        string    `json:"email"`
	APIKey       string    `json:"api_key"`
	RequestCount int       `json:"request_count"`
	CreatedAt    time.Time `json:"created_at"`
}

type RateLimiter struct {
	db      *sql.DB
	proxy   *httputil.ReverseProxy
	mu      sync.RWMutex
	baseURL *url.URL
}

var billablePaths = map[string]bool{
	"/api/execute-nft": true,
	"/api/deploy-nft":  true,
}

func isBillable(path string) bool {
	return billablePaths[path]
}

func enableCors(w *http.ResponseWriter) {
	(*w).Header().Set("Access-Control-Allow-Origin", "*")
	(*w).Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
	(*w).Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Content-Length, Accept-Encoding, Authorization")
}

// initConfig returns the database file path, rubix Node URL and server port from environment variables.
func initConfig() (string, *url.URL, string) {
	dbFile := os.Getenv("API_USAGE_DB")
	backendURLStr := os.Getenv("RUBIX_NODE_URL")
	serverPort := os.Getenv("SERVER_PORT")

	if dbFile == "" {
		log.Fatal("API_USAGE_DB environment variable is required")
	}
	if backendURLStr == "" {
		log.Fatal("RUBIX_NODE_URL environment variable is required")
	}
	if serverPort == "" {
		log.Fatal("SERVER_PORT environment variable is required")
	}

	parsedRubixNodeURL, err := url.Parse(backendURLStr)
	if err != nil || (parsedRubixNodeURL.Scheme != "http" && parsedRubixNodeURL.Scheme != "https") || parsedRubixNodeURL.Host == "" {
		log.Fatalf("RUBIX_NODE_URL invalid format: %s", backendURLStr)
	}

	return dbFile, parsedRubixNodeURL, serverPort
}

func NewRateLimiter(dbFile string, backendURL *url.URL) *RateLimiter {
	db, err := sql.Open("sqlite3", dbFile)
	if err != nil {
		log.Fatalf("Failed to open DB: %v", err)
	}

	db.Exec("PRAGMA journal_mode=WAL;")

	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS users (
			email TEXT PRIMARY KEY,
			api_key TEXT UNIQUE NOT NULL,
			request_count INTEGER DEFAULT 0,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		);
		CREATE TABLE IF NOT EXISTS nfts (
			nft_id TEXT PRIMARY KEY,
			nft_name TEXT,
			email TEXT,
			agent_description TEXT,
			agent_repo TEXT,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			nft_did TEXT
		);
		CREATE TABLE IF NOT EXISTS admin (
			username TEXT UNIQUE,
			password_hash TEXT
		);
		CREATE TABLE IF NOT EXISTS interaction (
            host_id TEXT,
            host_did TEXT,
            host_name TEXT,
            remote_did TEXT,
            remote_name TEXT,
            intrusion_cause TEXT,
            epoch INTEGER
        );
		CREATE TABLE IF NOT EXISTS remote (
            did TEXT PRIMARY KEY,
            name TEXT
        );
	`)
	if err != nil {
		log.Fatal(err)
	}

	proxy := httputil.NewSingleHostReverseProxy(backendURL)

	return &RateLimiter{db: db, proxy: proxy, baseURL: backendURL}
}

func (rl *RateLimiter) healthz(c *gin.Context) {
	w := http.ResponseWriter(c.Writer)
	enableCors(&w)
	c.JSON(200, gin.H{"status": "ok"})
}

func (rl *RateLimiter) adminAddUser(c *gin.Context) {
	w := http.ResponseWriter(c.Writer)
	enableCors(&w)

	if c.Request.Method != http.MethodPost {
		c.AbortWithStatus(http.StatusMethodNotAllowed)
		return
	}

	user, pass, ok := c.Request.BasicAuth()
	if !ok || !rl.checkAdminCredentials(user, pass) {
		c.Header("WWW-Authenticate", `Basic realm="admin"`)
		c.AbortWithStatus(http.StatusUnauthorized)
		return
	}

	var req struct {
		Email string `json:"email"`
	}
	if err := c.BindJSON(&req); err != nil || req.Email == "" {
		c.AbortWithStatus(http.StatusBadRequest)
		return
	}

	apiKey := uuid.New().String()
	_, err := rl.db.Exec(`INSERT INTO users (email, api_key) VALUES (?, ?)`, req.Email, apiKey)
	if err != nil {
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}

	c.JSON(200, gin.H{"api_key": apiKey})
}

func (rl *RateLimiter) proxyHandler(c *gin.Context) {
	r := c.Request
	w := c.Writer

	path := r.URL.Path
	billable := isBillable(path)

	var (
		user *User
		err  error = nil
	)

	apiKey := r.Header.Get(apiKeyHeader)
	if billable {
		if apiKey == "" {
			c.JSON(http.StatusUnauthorized, Response{
				Status:  false,
				Message: "missing API key",
			})
			return
		}

		user, err = rl.validateAndIncrement(apiKey)
		if err != nil {
			status := http.StatusUnauthorized
			if err.Error() == "rate limit exceeded" {
				status = http.StatusTooManyRequests
			}
			c.JSON(status, Response{
				Status:  false,
				Message: err.Error(),
			})
			return
		}
	}

	agentDescription := r.Header.Get(agentDescriptionHeader)
	agentRepo := r.Header.Get(agentRepoHeader)

	// SPECIAL HANDLING: For /api/deploy-nft, extract and store NFT info
	if strings.Contains(path, "/api/deploy-nft") && r.Method == http.MethodPost {
		// Read and buffer the body
		bodyBytes, err := io.ReadAll(r.Body)
		if err != nil {
			c.JSON(http.StatusBadRequest, Response{
				Status:  false,
				Message: "failed to read request body",
			})
			return
		}
		r.Body.Close()

		// Reconstruct body for proxying downstream
		r.Body = io.NopCloser(bytes.NewReader(bodyBytes))

		// Parse NFT payload
		var payload nftPayload
		if err := json.Unmarshal(bodyBytes, &payload); err == nil {
			// Extract agent_name from nftData
			agentName := extractHostAgentName(payload.NFTData)
			// Store in nfts table with email foreign key
			if err := rl.storeNFT(user.Email, payload.NFT, agentName, payload.DID, agentDescription, agentRepo); err != nil {
				log.Printf("Failed to store NFT for %s: %v", user.Email, err)
				c.JSON(http.StatusInternalServerError, Response{
					Status:  false,
					Message: fmt.Sprintf("failed to store NFT: %v", err),
				})
				return
			}
		}
	}

	if strings.Contains(path, "/api/execute-nft") && r.Method == http.MethodPost {
		// Extract Remote name and info
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
		if err := json.Unmarshal(bodyBytes, &payload); err != nil {
			c.JSON(http.StatusInternalServerError, Response{
				Status:  false,
				Message: "failed to unmarshal payload for Execute NFT API",
			})
			return
		}

		// Store remote info
		remoteInfoList, err := extractRemoteInfo(payload)
		if err != nil {
			c.JSON(http.StatusInternalServerError, Response{
				Status:  false,
				Message: fmt.Sprintf("failed to fetch remote info, err: %v", err),
			})
			return
		}

		for _, remoteInfo := range remoteInfoList {
			err := rl.storeRemote(remoteInfo.Did, remoteInfo.Name)
			if err != nil {
				errMsg := fmt.Sprintf(
					"failed to store remote details, remote_name: %v, remote_did: %v",
					remoteInfo.Name,
					remoteInfo.Did,
				)
				c.JSON(http.StatusInternalServerError, Response{
					Status:  false,
					Message: errMsg,
				})
				return
			}
		}

		// Store interactions
		interactionList, err := extractAgentInteractions(payload, rl.db)
		if err != nil {
			c.JSON(http.StatusInternalServerError, Response{
				Status:  false,
				Message: fmt.Sprintf("failed to fetch agent interactions, err: %v", err),
			})
			return
		}

		 if err := rl.storeInteractions(interactionList); err != nil {
			c.JSON(http.StatusInternalServerError, Response{
				Status:  false,
				Message: fmt.Sprintf("failed to store agent interactions, err: %v", err),
			})
			return
		}
	}

	// Proxy to blockchain node
	rl.proxy.ServeHTTP(w, r)
}

func (rl *RateLimiter) getNFTs(c *gin.Context) {
	rows, err := rl.db.Query(`SELECT nft_id, nft_name FROM nfts`)
	if err != nil {
		c.AbortWithStatus(500)
		return
	}
	defer rows.Close()

	var out []gin.H
	for rows.Next() {
		var id, name string
		rows.Scan(&id, &name)
		out = append(out, gin.H{"nft_id": id, "nft_name": name})
	}

	c.JSON(200, gin.H{"nfts": out})
}

func (rl *RateLimiter) getNFTByEmail(c *gin.Context) {
	email := c.Query("email")
	if email == "" {
		c.AbortWithStatus(400)
		return
	}

	rows, err := rl.db.Query(`SELECT nft_id, nft_name FROM nfts WHERE email = ?`, email)
	if err != nil {
		c.AbortWithStatus(500)
		return
	}
	defer rows.Close()

	var out []gin.H
	for rows.Next() {
		var id, name string
		rows.Scan(&id, &name)
		out = append(out, gin.H{"nft_id": id, "nft_name": name})
	}

	c.JSON(200, gin.H{"email": email, "nfts": out})
}

func (rl *RateLimiter) getBalanceCredits(c *gin.Context) {
	w := http.ResponseWriter(c.Writer)
	enableCors(&w)

	email := c.Query("email")
	if email == "" {
		c.JSON(400, Response{
			Status: false,
			Message: "email is required",
		})
		return
	}

	var count int
	err := rl.db.QueryRow(`SELECT request_count FROM users WHERE email = ?`, email).Scan(&count)
	if err != nil {
		c.JSON(500, Response{
			Status:  false,
			Message: fmt.Sprintf("failed to fetch credit balance for email: %v", email),
		})
		return
	}

	c.JSON(200, gin.H{
		"email":          email,
		"credit_balance": maxRequests - count,
	})
}

func (rl *RateLimiter) checkAdminCredentials(username, password string) bool {
	var hash string
	err := rl.db.QueryRow(`SELECT password_hash FROM admin WHERE username = ?`, username).Scan(&hash)
	if err != nil {
		return false
	}
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
}

func (rl *RateLimiter) validateAndIncrement(key string) (*User, error) {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	tx, err := rl.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	var u User
	err = tx.QueryRow(`SELECT email, api_key, request_count, created_at FROM users WHERE api_key = ?`, key).
		Scan(&u.Email, &u.APIKey, &u.RequestCount, &u.CreatedAt)
	if err != nil {
		return nil, err
	}

	if u.RequestCount >= maxRequests {
		return nil, fmt.Errorf("rate limit exceeded")
	}

	tx.Exec(`UPDATE users SET request_count = request_count + 1 WHERE api_key = ?`, key)
	tx.Commit()

	return &u, nil
}

func (rl *RateLimiter) storeNFT(email, nftID, nftName, nftDID, agentDescription, agentRepo string) error {
	_, err := rl.db.Exec(
		`INSERT OR IGNORE INTO nfts (nft_id, nft_name, nft_did, email, agent_description, agent_repo) VALUES (?, ?, ?, ?, ?, ?)`,
		nftID,
		nftName,
		nftDID,
		email,
		agentDescription,
		agentRepo,
	)
	return err
}

// nftPayload models the deploy-nft request body.
type nftPayload struct {
	NFT         string  `json:"nft"`
	DID         string  `json:"did"`
	QuorumType  int     `json:"quorum_type"`
	NFTValue    float64 `json:"nft_value"`
	NFTData     string  `json:"nft_data"`
	NFTMetadata string  `json:"nft_metadata"`
	NFTFileName string  `json:"nft_file_name"`
}

// agentInteraction stores the interaction information between agent
// and other agents, tools, etc
type agentInteraction struct {
	HostID         string `json:"host_id"`
	HostDID        string `json:"host_did"`
	HostName       string `json:"host_name"`
	RemoteDID      string `json:"remote_did"`
	RemoteName     string `json:"remote_name"`
	IntrusionCause string `json:"intrusion_cause"`
	Epoch          int64  `json:"epoch"`
}

func (rl *RateLimiter) storeRemote(remoteDid, remoteName string) error {
	_, err := rl.db.Exec(`
		INSERT OR IGNORE INTO remote(did, name)
		VALUES (?, ?)
	`, remoteDid, remoteName)
	if err != nil {
		return fmt.Errorf("storeRemote: failed to execute query, err: %v", err)
	}

	return nil
}

func (rl *RateLimiter) storeInteractions(interactionList []*agentInteraction) error {
	tx, err := rl.db.Begin()
	if err != nil {
		return fmt.Errorf("storeInteractions: failed to begin transaction, err: %v", err)
	}
	defer tx.Rollback()
	
	for _, interaction := range interactionList {
		_, err := tx.Exec(`
			INSERT INTO interaction(host_id, host_did, host_name, remote_did, remote_name, intrusion_cause, epoch)
			VALUES(?, ?, ?, ?, ?, ?, ?)
		`, interaction.HostID, interaction.HostDID, interaction.HostName, interaction.RemoteDID,
			interaction.RemoteName, interaction.IntrusionCause, interaction.Epoch)
		
		if err != nil {
			return fmt.Errorf("storeInteractions: failed to execute query, err: %v", err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("storeInteractions: failed to commit transaction, err: %v", err)
	}

	return nil
}


func (rl *RateLimiter) getInteractions(c *gin.Context) {
	w := http.ResponseWriter(c.Writer)
	enableCors(&w)

	rows, err := rl.db.Query("SELECT * FROM interaction ORDER BY epoch DESC")
	if err != nil {
		c.JSON(500, Response{
			Status:  false,
			Message: fmt.Sprintf("failed to fetch interactions, err: %v", err),
		})
		return
	}
	defer rows.Close()

	var agentInteractions []*agentInteraction = make([]*agentInteraction, 0)

	for rows.Next() {
		var hostId, hostDid, hostName, remoteDid, remoteName, intrusionCause string
		var epoch int
		if err := rows.Scan(&hostId, &hostDid, &hostName, &remoteDid, &remoteName, &intrusionCause, &epoch); err != nil {
			c.JSON(500, Response{
				Status:  false,
				Message: fmt.Sprintf("failed to capture info for interactions, err: %v", err),
			})
			return
		}

		agentInteractions = append(agentInteractions, &agentInteraction{
			HostID:         hostId,
			HostDID:        hostDid,
			HostName:       hostName,
			RemoteDID:      remoteDid,
			RemoteName:     remoteName,
			IntrusionCause: intrusionCause,
			Epoch:          int64(epoch),
		})
	}

	c.JSON(200, Response{
		Status: true,
		Data: agentInteractions,
	})
}

func (rl *RateLimiter) getToolInteractionsByDID(c *gin.Context) {
	w := http.ResponseWriter(c.Writer)
	enableCors(&w)

	toolDID := c.Param("did")
	if toolDID == "" {
		c.JSON(400, Response{
			Status: false,
			Message: "did is required",
		})
		return
	}

	rows, err := rl.db.Query("SELECT * from interaction WHERE remote_did = ? ORDER BY epoch DESC", toolDID)
	if err != nil {
		c.JSON(500, Response{
			Status:  false,
			Message: fmt.Sprintf("failed to fetch interactions, err: %v", err),
		})
		return
	}
	defer rows.Close()

	var agentInteractions []*agentInteraction = make([]*agentInteraction, 0)

	for rows.Next() {
		var hostId, hostDid, hostName, remoteDid, remoteName, intrusionCause string
		var epoch int
		if err := rows.Scan(&hostId, &hostDid, &hostName, &remoteDid, &remoteName, &intrusionCause, &epoch); err != nil {
			c.JSON(500, Response{
				Status:  false,
				Message: fmt.Sprintf("failed to capture info for interactions, err: %v", err),
			})
			return
		}

		agentInteractions = append(agentInteractions, &agentInteraction{
			HostID:         hostId,
			HostDID:        hostDid,
			HostName:       hostName,
			RemoteDID:      remoteDid,
			RemoteName:     remoteName,
			IntrusionCause: intrusionCause,
			Epoch:          int64(epoch),
		})
	}

	c.JSON(200, Response{
		Status: true,
		Data: agentInteractions,
	})
}

func (rl *RateLimiter) getEcosystemMetrics(c *gin.Context) {
	w := http.ResponseWriter(c.Writer)
	enableCors(&w)

	// total_interactions
	totalInteractionsRows, err := rl.db.Query("SELECT COUNT() from interaction")
	if err != nil {
		c.JSON(500, Response{
			Status:  false,
			Message: fmt.Sprintf("failed to fetch total interactions, err: %v", err),
		})
		return
	}
	defer totalInteractionsRows.Close()

	var totalInteractions int
	if totalInteractionsRows.Next() {
		if err := totalInteractionsRows.Scan(&totalInteractions); err != nil {
			c.JSON(500, Response{
				Status:  false,
				Message: fmt.Sprintf("failed to scan total interactions, err: %v", err),
			})
			return
		}
	}

	// total_intrusions
	totalIntrusionsRows, err := rl.db.Query("SELECT COUNT(*) from interaction where intrusion_cause != ''")
	if err != nil {
		c.JSON(500, Response{
			Status:  false,
			Message: fmt.Sprintf("failed to fetch total intrusions, err: %v", err),
		})
		return
	}
	defer totalIntrusionsRows.Close()

	var totalIntrusions int
	if totalIntrusionsRows.Next() {
		if err := totalIntrusionsRows.Scan(&totalIntrusions); err != nil {
			c.JSON(500, Response{
				Status:  false,
				Message: fmt.Sprintf("failed to scan total intrusions, err: %v", err),
			})
			return
		}
	}

	// total_agents
	totalAgentsRows, err := rl.db.Query("SELECT COUNT(*) from nfts")
	if err != nil {
		c.JSON(500, Response{
			Status:  false,
			Message: fmt.Sprintf("failed to fetch total agents, err: %v", err),
		})
		return
	}
	defer totalAgentsRows.Close()

	var totalAgents int
	if totalAgentsRows.Next() {
		if err := totalAgentsRows.Scan(&totalAgents); err != nil {
			c.JSON(500, Response{
				Status:  false,
				Message: fmt.Sprintf("failed to scan total agents, err: %v", err),
			})
			return
		}
	}

	// total_tools
	totalToolsRows, err := rl.db.Query("SELECT COUNT(*) from remote")
	if err != nil {
		c.JSON(500, Response{
			Status:  false,
			Message: fmt.Sprintf("failed to fetch total tools, err: %v", err),
		})
		return
	}
	defer totalToolsRows.Close()

	var totalTools int
	if totalToolsRows.Next() {
		if err := totalToolsRows.Scan(&totalTools); err != nil {
			c.JSON(500, Response{
				Status:  false,
				Message: fmt.Sprintf("failed to scan total tools, err: %v", err),
			})
			return
		}
	}

	c.JSON(200, Response{
		Status: true,
		Data: map[string]interface{}{
			"total_interactions": totalInteractions,
			"total_intrusions":   totalIntrusions,
			"total_agents":       totalAgents,
			"total_tools":        totalTools,
		},
	})
}

func (rl *RateLimiter) getEcosystemMetricsByEmail(c *gin.Context) {
	w := http.ResponseWriter(c.Writer)
	enableCors(&w)

	email := c.Param("email")
	if email == "" {
		c.JSON(400, Response{
			Status: false,
			Message: "email is required",
		})
		return
	}

	rows, err := rl.db.Query(
		`SELECT nft_id FROM nfts WHERE email = ?`,
		email,
	)
	if err != nil {
		c.JSON(500, Response{
			Status: false,
			Message: fmt.Sprintf("failed to fetch agents from email: %v", email),
		})
		return
	}
	defer rows.Close()

	var agents []interface{}
	for rows.Next() {
		var nftID string
		if err := rows.Scan(&nftID); err != nil {
			c.JSON(500, Response{
				Status: false,
				Message: fmt.Sprintf("failed to scan agents from email: %v", email),
			})
			return
		}

		agents = append(agents, nftID)
	}

	var totalInteractions int = 0
	if len(agents) > 0 {
		totalInteractionClause := "(" + strings.Repeat("?,", len(agents)-1) + "?)"

		// total_interactions
		totalInteractionsRows, err := rl.db.Query("SELECT COUNT(*) from interaction WHERE host_id IN "+ totalInteractionClause, agents...)
		if err != nil {
			c.JSON(500, Response{
				Status: false,
				Message: fmt.Sprintf("failed to fetch total interactions for email: %v", email),
			})
			return
		}
		defer totalInteractionsRows.Close()

		if totalInteractionsRows.Next() {
			if err := totalInteractionsRows.Scan(&totalInteractions); err != nil {
				c.JSON(500, Response{
					Status: false,
					Message: fmt.Sprintf("failed to scan total interactions for email: %v", email),
				})
				return
			}
		}
	}

	// total_intrusions
	var totalIntrusions int = 0
	if len(agents) > 0 {
		placeholderTotalIntrusions := "(" + strings.Repeat("?,", len(agents)-1) + "?)"
		totalIntrusionsRows, err := rl.db.Query("SELECT COUNT(*) from interaction where host_id IN "+placeholderTotalIntrusions+" AND intrusion_cause != ''", agents...)
		if err != nil {
			c.JSON(500, Response{
				Status: false,
				Message: fmt.Sprintf("failed to fetch total intrusions for email: %v", email),
			})
			return
		}
		defer totalIntrusionsRows.Close()

		if totalIntrusionsRows.Next() {
			if err := totalIntrusionsRows.Scan(&totalIntrusions); err != nil {
				c.JSON(500, Response{
					Status: false,
					Message: fmt.Sprintf("failed to scan total intrusions for email: %v", email),
				})
				return
			}
		}
	}
	// total_agents
	totalAgents := len(agents)

	// interacted_tools
	var totalInteractedTools int = 0
	if len(agents) > 0 {
		placeholderInteractedTools := "(" + strings.Repeat("?,", len(agents)-1) + "?)"
		interactedToolsRows, err := rl.db.Query("SELECT COUNT(*) FROM (SELECT DISTINCT remote_did AS tools FROM interaction WHERE host_id IN "+placeholderInteractedTools +") AS t", agents...)
		if err != nil {
			c.JSON(500, Response{
				Status: false,
				Message: fmt.Sprintf("failed to fetch interacted tools for email: %v, err: %v", email, err),
			})
			return
		}
		defer interactedToolsRows.Close()

		if interactedToolsRows.Next() {
			if err := interactedToolsRows.Scan(&totalInteractedTools); err != nil {
				c.JSON(500, Response{
					Status: false,
					Message: fmt.Sprintf("failed to scan interacted tools for email: %v", email),
				})
				return
			}
		}
	}

	c.JSON(200, Response{
		Status: true,
		Data: map[string]interface{}{
			"total_interactions": totalInteractions,
			"total_intrusions":   totalIntrusions,
			"total_agents":       totalAgents,
			"interacted_tools":   totalInteractedTools,
		},
	})
}



func (rl *RateLimiter) getUserAgents(c *gin.Context) {
	w := http.ResponseWriter(c.Writer)
	enableCors(&w)

	email := c.Param("email")
	if email == "" {
		c.JSON(400, Response{
			Status: false,
			Message: "did is required",
		})
		return
	}
	
	rows, err := rl.db.Query(
		`SELECT nft_id FROM nfts WHERE email = ?`,
		email,
	)
	if err != nil {
		c.JSON(500, Response{
			Status: false,
			Message: fmt.Sprintf("failed to fetch agents from email: %v", email),
		})
		return
	}
	defer rows.Close()

	var agents []interface{}
	for rows.Next() {
		var nftID string
		if err := rows.Scan(&nftID); err != nil {
			c.JSON(500, Response{
				Status: false,
				Message: fmt.Sprintf("failed to fetch agents from email: %v", email),
			})
			return
		}

		agents = append(agents, nftID)
	}

	if len(agents) == 0 {
		c.JSON(200, Response{
			Status: true,
			Data:   []*agentInteraction{},
		})
		return
	}

	totalInteractionClause := "(" + strings.Repeat("?,", len(agents)-1) + "?)"

	userAgentsRow, err := rl.db.Query("SELECT * from interaction WHERE host_id IN "+totalInteractionClause+" ORDER BY epoch DESC", agents...)
	if err != nil {
		c.JSON(500, Response{
			Status: false,
			Message: fmt.Sprintf("failed to fetch user's interaction by email: %v, err: %v", email, err),
		})
		return
	}

	var agentInteractions []*agentInteraction = make([]*agentInteraction, 0)

	for userAgentsRow.Next() {
		var hostId, hostDid, hostName, remoteDid, remoteName, intrusionCause string
		var epoch int
		if err := userAgentsRow.Scan(&hostId, &hostDid, &hostName, &remoteDid, &remoteName, &intrusionCause, &epoch); err != nil {
			c.JSON(500, Response{
				Status:  false,
				Message: fmt.Sprintf("failed to capture info for interactions, err: %v", err),
			})
			return
		}

		agentInteractions = append(agentInteractions, &agentInteraction{
			HostID:         hostId,
			HostDID:        hostDid,
			HostName:       hostName,
			RemoteDID:      remoteDid,
			RemoteName:     remoteName,
			IntrusionCause: intrusionCause,
			Epoch:          int64(epoch),
		})
	}

	c.JSON(200, Response{
		Status: true,
		Data: agentInteractions,
	})
}

func (rl *RateLimiter) getAgentInteractionsByDID(c *gin.Context) {
	w := http.ResponseWriter(c.Writer)
	enableCors(&w)

	agentDID := c.Param("did")
	if agentDID == "" {
		c.JSON(400, Response{
			Status: false,
			Message: "did is required",
		})
		return
	}

	rows, err := rl.db.Query("SELECT * from interaction WHERE host_did = ? ORDER BY epoch DESC", agentDID)
	if err != nil {
		c.JSON(500, Response{
			Status:  false,
			Message: fmt.Sprintf("failed to fetch interactions, err: %v", err),
		})
		return
	}
	defer rows.Close()

	var agentInteractions []*agentInteraction = make([]*agentInteraction, 0)

	for rows.Next() {
		var hostId, hostDid, hostName, remoteDid, remoteName, intrusionCause string
		var epoch int
		if err := rows.Scan(&hostId, &hostDid, &hostName, &remoteDid, &remoteName, &intrusionCause, &epoch); err != nil {
			c.JSON(500, Response{
				Status:  false,
				Message: fmt.Sprintf("failed to capture info for interactions, err: %v", err),
			})
			return
		}

		agentInteractions = append(agentInteractions, &agentInteraction{
			HostID:         hostId,
			HostDID:        hostDid,
			HostName:       hostName,
			RemoteDID:      remoteDid,
			RemoteName:     remoteName,
			IntrusionCause: intrusionCause,
			Epoch:          int64(epoch),
		})
	}

	c.JSON(200, Response{
		Status: true,
		Data: agentInteractions,
	})
}

type agentInteractionMetric struct {
	AgentName string `json:"agent_name"`
	AgentDid string `json:"agent_did"`
	TotatInteractions int `json:"total_interactions"`
	TotalIntrusions int `json:"total_intrusions"`
	ToolsInteracted int `json:"tools_interacted"`
}

func (rl *RateLimiter) getAgentInteractions(c *gin.Context) {
	w := http.ResponseWriter(c.Writer)
	enableCors(&w)

	rows, err := rl.db.Query("SELECT nft_id, nft_name, nft_did from nfts")
	if err != nil {
		c.JSON(500, Response{
			Status:  false,
			Message: fmt.Sprintf("failed to fetch interactions, err: %v", err),
		})
		return
	}
	defer rows.Close()

	var agentInteractions []*agentInteractionMetric = make([]*agentInteractionMetric, 0)

	for rows.Next() {
		var agentID, agentName, agentDid string

		if err := rows.Scan(&agentID, &agentName, &agentDid); err != nil {
			c.JSON(500, Response{
				Status:  false,
				Message: fmt.Sprintf("failed to capture info for interactions, err: %v", err),
			})
			return
		}

		var totalInteractions int
		err = rl.db.QueryRow("SELECT COUNT(*) from interaction WHERE host_id = ?", agentID).Scan(&totalInteractions)
		if err != nil {
			c.JSON(500, Response{
				Status:  false,
				Message: fmt.Sprintf("failed to fetch total interactions for agent %s, err: %v", agentID, err),
			})
			return
		}

		var totalIntrusions int
		err = rl.db.QueryRow("SELECT COUNT(*) from interaction WHERE host_id = ? AND intrusion_cause != ''", agentID).Scan(&totalIntrusions)
		if err != nil {
			c.JSON(500, Response{
				Status:  false,
				Message: fmt.Sprintf("failed to fetch total intrusions for agent %s, err: %v", agentID, err),
			})
			return
		}

		var toolsIntracted int
		err = rl.db.QueryRow("SELECT COUNT(DISTINCT remote_name) from interaction WHERE host_id = ?", agentID).Scan(&toolsIntracted)
		if err != nil {
			c.JSON(500, Response{
				Status:  false,
				Message: fmt.Sprintf("failed to fetch tools inctracted for agent %s, err: %v", agentID, err),
			})
			return
		}

		agentInteractions = append(agentInteractions, &agentInteractionMetric{
			AgentName: agentName,
			AgentDid:  agentDid,
			TotalIntrusions: totalIntrusions,
			ToolsInteracted: toolsIntracted,
			TotatInteractions: totalInteractions,
		})
	}

	c.JSON(200, Response{
		Status: true,
		Data: agentInteractions,
	})
}

type toolInteractionMetric struct {
	ToolName string `json:"tool_name"`
	ToolDid string `json:"tool_did"`
	TotalInteractions int `json:"total_interactions"`
	TotalIntrusions int `json:"total_intrusions"`
	AgentsInteracted int `json:"agents_interacted"`
}

func (rl *RateLimiter) getToolsInteractions(c *gin.Context) {
	w := http.ResponseWriter(c.Writer)
	enableCors(&w)

	rows, err := rl.db.Query("SELECT * from remote")
	if err != nil {
		c.JSON(500, Response{
			Status:  false,
			Message: fmt.Sprintf("failed to fetch tools, err: %v", err),
		})
		return
	}
	defer rows.Close()

	var toolInteractions []*toolInteractionMetric = make([]*toolInteractionMetric, 0)
	for rows.Next() {
		var toolDid, toolName string
		if err := rows.Scan(&toolDid, &toolName); err != nil {
			c.JSON(500, Response{
				Status:  false,
				Message: fmt.Sprintf("failed to capture info for tools, err: %v", err),
			})
			return
		}

		var totalInteractions int
		err = rl.db.QueryRow("SELECT COUNT(*) from interaction WHERE remote_did = ?", toolDid).Scan(&totalInteractions)
		if err != nil {
			c.JSON(500, Response{
				Status:  false,
				Message: fmt.Sprintf("failed to fetch total interactions for tool %s, err: %v", toolName, err),
			})
			return
		}

		var totalIntrusions int
		err = rl.db.QueryRow("SELECT COUNT(*) from interaction WHERE remote_did = ? AND intrusion_cause != ''", toolDid).Scan(&totalIntrusions)
		if err != nil {
			c.JSON(500, Response{
				Status:  false,
				Message: fmt.Sprintf("failed to fetch total intrusions for tool %s, err: %v", toolName, err),
			})
			return
		}

		var agentsInteracted int
		err = rl.db.QueryRow("SELECT COUNT(DISTINCT host_name) from interaction WHERE remote_did = ?", toolDid).Scan(&agentsInteracted)
		if err != nil {
			c.JSON(500, Response{
				Status:  false,
				Message: fmt.Sprintf("failed to fetch agents interacted for tool %s, err: %v", toolName, err),
			})
			return
		}

		toolInteractions = append(toolInteractions, &toolInteractionMetric{
			ToolName: toolName,
			ToolDid: toolDid,
			TotalInteractions: totalInteractions,
			TotalIntrusions: totalIntrusions,
			AgentsInteracted: agentsInteracted,
		})
	}

	c.JSON(200, Response{
		Status: true,
		Data: toolInteractions,
	})
}

func main() {
	dbFile, backendURL, serverPort := initConfig()
	rl := NewRateLimiter(dbFile, backendURL)
	defer rl.db.Close()

	r := gin.New()
	r.Use(gin.Recovery())

	r.GET("/healthz", rl.healthz)
	r.POST("/admin/add-user", rl.adminAddUser)
	r.GET("/get-balance-credits", rl.getBalanceCredits)
	r.GET("/interactions", rl.getInteractions)
	r.GET("/interactions/tool/:did", rl.getToolInteractionsByDID)
	r.GET("/interactions/agent/:did", rl.getAgentInteractionsByDID)
	r.GET("/interactions/user/:email/agents", rl.getUserAgents)
	r.GET("/agents", rl.getAgentInteractions)
	r.GET("/tools", rl.getToolsInteractions)
	r.GET("/metrics", rl.getEcosystemMetrics)
	r.GET("/metrics/:email", rl.getEcosystemMetricsByEmail)
	
	// Proxy Rubix related endpoints
	api := r.Group("/api")
	api.Any("/*path", rl.proxyHandler)

	log.Printf("Starting on :%s", serverPort)
	r.Run(":" + serverPort)
}
