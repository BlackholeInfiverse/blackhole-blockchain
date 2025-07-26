package bridgesdk

import (
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"go.uber.org/zap"
)

// LogStreamer handles real-time log streaming to web clients
type LogStreamer struct {
	logger      *BridgeLogger
	clients     map[*websocket.Conn]*LogClient
	clientsMu   sync.RWMutex
	upgrader    websocket.Upgrader
	logChannel  chan LogEntry
	stopChannel chan struct{}
	isRunning   bool
}

// LogClient represents a connected web client
type LogClient struct {
	conn       *websocket.Conn
	send       chan LogEntry
	filters    LogFilters
	lastSeen   time.Time
	clientID   string
	userAgent  string
	remoteAddr string
}

// LogFilters defines filtering options for log streaming
type LogFilters struct {
	MinLevel   LogLevel `json:"min_level"`
	Components []string `json:"components"`
	MaxAge     int      `json:"max_age_minutes"`
	Keywords   []string `json:"keywords"`
}

// LogStreamMessage represents a message sent to web clients
type LogStreamMessage struct {
	Type      string      `json:"type"`
	Timestamp time.Time   `json:"timestamp"`
	Data      interface{} `json:"data"`
}

// NewLogStreamer creates a new log streamer
func NewLogStreamer(logger *BridgeLogger) *LogStreamer {
	return &LogStreamer{
		logger:      logger,
		clients:     make(map[*websocket.Conn]*LogClient),
		upgrader: websocket.Upgrader{
			CheckOrigin: func(r *http.Request) bool {
				return true // Allow all origins for development
			},
			ReadBufferSize:  1024,
			WriteBufferSize: 1024,
		},
		logChannel:  logger.Subscribe(),
		stopChannel: make(chan struct{}),
	}
}

// Start begins the log streaming service
func (ls *LogStreamer) Start() {
	if ls.isRunning {
		return
	}

	ls.isRunning = true
	go ls.streamLogs()
	go ls.cleanupClients()

	ls.logger.Info("log_streamer", "Log streaming service started")
}

// Stop stops the log streaming service
func (ls *LogStreamer) Stop() {
	if !ls.isRunning {
		return
	}

	ls.isRunning = false
	close(ls.stopChannel)

	// Close all client connections
	ls.clientsMu.Lock()
	for conn, client := range ls.clients {
		close(client.send)
		conn.Close()
	}
	ls.clients = make(map[*websocket.Conn]*LogClient)
	ls.clientsMu.Unlock()

	// Unsubscribe from logger
	ls.logger.Unsubscribe(ls.logChannel)

	ls.logger.Info("log_streamer", "Log streaming service stopped")
}

// HandleWebSocket handles WebSocket connections for log streaming
func (ls *LogStreamer) HandleWebSocket(w http.ResponseWriter, r *http.Request) {
	conn, err := ls.upgrader.Upgrade(w, r, nil)
	if err != nil {
		ls.logger.Error("log_streamer", "Failed to upgrade WebSocket connection", err)
		return
	}

	client := &LogClient{
		conn:       conn,
		send:       make(chan LogEntry, 256),
		filters:    LogFilters{MinLevel: LogLevelInfo},
		lastSeen:   time.Now(),
		clientID:   generateClientID(),
		userAgent:  r.UserAgent(),
		remoteAddr: r.RemoteAddr,
	}

	ls.clientsMu.Lock()
	ls.clients[conn] = client
	ls.clientsMu.Unlock()

	ls.logger.Info("log_streamer", "New WebSocket client connected",
		zap.String("client_id", client.clientID),
		zap.String("remote_addr", client.remoteAddr),
	)

	// Send recent logs to new client
	go ls.sendRecentLogs(client)

	// Handle client messages and cleanup
	go ls.handleClient(client)
}

// streamLogs distributes log entries to connected clients
func (ls *LogStreamer) streamLogs() {
	for {
		select {
		case logEntry := <-ls.logChannel:
			ls.distributeLogEntry(logEntry)
		case <-ls.stopChannel:
			return
		}
	}
}

// distributeLogEntry sends a log entry to all matching clients
func (ls *LogStreamer) distributeLogEntry(entry LogEntry) {
	ls.clientsMu.RLock()
	defer ls.clientsMu.RUnlock()

	for _, client := range ls.clients {
		if ls.shouldSendToClient(client, entry) {
			select {
			case client.send <- entry:
			default:
				// Client channel is full, skip this entry
				ls.logger.Debug("log_streamer", "Client channel full, skipping log entry",
					zap.String("client_id", client.clientID),
				)
			}
		}
	}
}

// shouldSendToClient determines if a log entry should be sent to a specific client
func (ls *LogStreamer) shouldSendToClient(client *LogClient, entry LogEntry) bool {
	// Check log level
	if !ls.isLevelAllowed(entry.Level, client.filters.MinLevel) {
		return false
	}

	// Check component filter
	if len(client.filters.Components) > 0 {
		found := false
		for _, component := range client.filters.Components {
			if component == entry.Component {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	// Check age filter
	if client.filters.MaxAge > 0 {
		maxAge := time.Duration(client.filters.MaxAge) * time.Minute
		if time.Since(entry.Timestamp) > maxAge {
			return false
		}
	}

	// Check keyword filter
	if len(client.filters.Keywords) > 0 {
		found := false
		for _, keyword := range client.filters.Keywords {
			if containsIgnoreCase(entry.Message, keyword) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	return true
}

// isLevelAllowed checks if a log level meets the minimum requirement
func (ls *LogStreamer) isLevelAllowed(entryLevel string, minLevel LogLevel) bool {
	levels := map[string]int{
		"debug": 0,
		"info":  1,
		"warn":  2,
		"error": 3,
		"fatal": 4,
	}

	entryLevelNum, exists := levels[entryLevel]
	if !exists {
		return true
	}

	minLevelNum, exists := levels[string(minLevel)]
	if !exists {
		return true
	}

	return entryLevelNum >= minLevelNum
}

// containsIgnoreCase checks if a string contains a substring (case-insensitive)
func containsIgnoreCase(str, substr string) bool {
	return strings.Contains(strings.ToLower(str), strings.ToLower(substr))
}

// handleClient manages a WebSocket client connection
func (ls *LogStreamer) handleClient(client *LogClient) {
	defer func() {
		ls.clientsMu.Lock()
		delete(ls.clients, client.conn)
		ls.clientsMu.Unlock()
		
		close(client.send)
		client.conn.Close()
		
		ls.logger.Info("log_streamer", "WebSocket client disconnected",
			zap.String("client_id", client.clientID),
		)
	}()

	// Start goroutine to send messages to client
	go ls.writeToClient(client)

	// Read messages from client (for filter updates)
	for {
		var message map[string]interface{}
		err := client.conn.ReadJSON(&message)
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				ls.logger.Error("log_streamer", "WebSocket read error", err,
					zap.String("client_id", client.clientID),
				)
			}
			break
		}

		client.lastSeen = time.Now()
		ls.handleClientMessage(client, message)
	}
}

// writeToClient sends log entries to a WebSocket client
func (ls *LogStreamer) writeToClient(client *LogClient) {
	ticker := time.NewTicker(54 * time.Second) // Ping interval
	defer ticker.Stop()

	for {
		select {
		case logEntry, ok := <-client.send:
			client.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if !ok {
				client.conn.WriteMessage(websocket.CloseMessage, []byte{})
				return
			}

			message := LogStreamMessage{
				Type:      "log",
				Timestamp: time.Now(),
				Data:      logEntry,
			}

			if err := client.conn.WriteJSON(message); err != nil {
				ls.logger.Error("log_streamer", "Failed to write to WebSocket client", err,
					zap.String("client_id", client.clientID),
				)
				return
			}

		case <-ticker.C:
			client.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if err := client.conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
		}
	}
}

// handleClientMessage processes messages from WebSocket clients
func (ls *LogStreamer) handleClientMessage(client *LogClient, message map[string]interface{}) {
	messageType, ok := message["type"].(string)
	if !ok {
		return
	}

	switch messageType {
	case "set_filters":
		if filtersData, ok := message["filters"].(map[string]interface{}); ok {
			ls.updateClientFilters(client, filtersData)
		}
	case "get_recent_logs":
		go ls.sendRecentLogs(client)
	case "ping":
		// Respond with pong
		response := LogStreamMessage{
			Type:      "pong",
			Timestamp: time.Now(),
			Data:      nil,
		}
		client.conn.WriteJSON(response)
	}
}

// updateClientFilters updates the filters for a specific client
func (ls *LogStreamer) updateClientFilters(client *LogClient, filtersData map[string]interface{}) {
	if minLevel, ok := filtersData["min_level"].(string); ok {
		client.filters.MinLevel = LogLevel(minLevel)
	}

	if components, ok := filtersData["components"].([]interface{}); ok {
		client.filters.Components = make([]string, len(components))
		for i, comp := range components {
			if compStr, ok := comp.(string); ok {
				client.filters.Components[i] = compStr
			}
		}
	}

	if maxAge, ok := filtersData["max_age_minutes"].(float64); ok {
		client.filters.MaxAge = int(maxAge)
	}

	if keywords, ok := filtersData["keywords"].([]interface{}); ok {
		client.filters.Keywords = make([]string, len(keywords))
		for i, keyword := range keywords {
			if keywordStr, ok := keyword.(string); ok {
				client.filters.Keywords[i] = keywordStr
			}
		}
	}

	ls.logger.Debug("log_streamer", "Updated client filters",
		zap.String("client_id", client.clientID),
		zap.Any("filters", client.filters),
	)
}

// sendRecentLogs sends recent log entries to a client
func (ls *LogStreamer) sendRecentLogs(client *LogClient) {
	recentLogs := ls.logger.GetRecentLogs(100) // Get last 100 logs

	for _, logEntry := range recentLogs {
		if ls.shouldSendToClient(client, logEntry) {
			select {
			case client.send <- logEntry:
			default:
				// Channel full, stop sending recent logs
				return
			}
		}
	}
}

// cleanupClients removes inactive clients
func (ls *LogStreamer) cleanupClients() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			ls.cleanupInactiveClients()
		case <-ls.stopChannel:
			return
		}
	}
}

// cleanupInactiveClients removes clients that haven't been seen recently
func (ls *LogStreamer) cleanupInactiveClients() {
	ls.clientsMu.Lock()
	defer ls.clientsMu.Unlock()

	timeout := 5 * time.Minute
	now := time.Now()

	for conn, client := range ls.clients {
		if now.Sub(client.lastSeen) > timeout {
			ls.logger.Info("log_streamer", "Removing inactive client",
				zap.String("client_id", client.clientID),
				zap.Duration("inactive_duration", now.Sub(client.lastSeen)),
			)

			close(client.send)
			conn.Close()
			delete(ls.clients, conn)
		}
	}
}

// generateClientID generates a unique client ID
func generateClientID() string {
	return fmt.Sprintf("client_%d", time.Now().UnixNano())
}

// GetConnectedClients returns information about connected clients
func (ls *LogStreamer) GetConnectedClients() []map[string]interface{} {
	ls.clientsMu.RLock()
	defer ls.clientsMu.RUnlock()

	clients := make([]map[string]interface{}, 0, len(ls.clients))
	for _, client := range ls.clients {
		clients = append(clients, map[string]interface{}{
			"client_id":   client.clientID,
			"remote_addr": client.remoteAddr,
			"user_agent":  client.userAgent,
			"last_seen":   client.lastSeen,
			"filters":     client.filters,
		})
	}

	return clients
}
