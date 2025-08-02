package cybersecurity

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"time"
)

// SecurityAPI provides HTTP API endpoints for cybersecurity management
type SecurityAPI struct {
	securityManager *SecurityManager
	apiKey          string
	port            int
}

// NewSecurityAPI creates a new security API server
func NewSecurityAPI(securityManager *SecurityManager, apiKey string, port int) *SecurityAPI {
	return &SecurityAPI{
		securityManager: securityManager,
		apiKey:          apiKey,
		port:            port,
	}
}

// Start starts the security API server
func (api *SecurityAPI) Start() error {
	mux := http.NewServeMux()

	// Add CORS middleware
	corsHandler := func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-API-Key")

			if r.Method == "OPTIONS" {
				w.WriteHeader(http.StatusOK)
				return
			}

			next(w, r)
		}
	}

	// Public endpoints
	mux.HandleFunc("/api/v1/security/health", corsHandler(api.handleHealthCheck))
	mux.HandleFunc("/api/v1/security/metrics", corsHandler(api.handleMetrics))
	mux.HandleFunc("/api/v1/security/threats", corsHandler(api.handleThreats))

	// Protected endpoints (require API key)
	mux.HandleFunc("/api/v1/security/contracts", corsHandler(api.authMiddleware(api.handleContracts)))
	mux.HandleFunc("/api/v1/security/rules", corsHandler(api.authMiddleware(api.handleRules)))
	mux.HandleFunc("/api/v1/security/incidents", corsHandler(api.authMiddleware(api.handleIncidents)))
	mux.HandleFunc("/api/v1/security/audit", corsHandler(api.authMiddleware(api.handleAudit)))
	mux.HandleFunc("/api/v1/security/compliance", corsHandler(api.authMiddleware(api.handleCompliance)))
	mux.HandleFunc("/api/v1/security/access", corsHandler(api.authMiddleware(api.handleAccessControl)))

	// Admin endpoints
	mux.HandleFunc("/api/v1/security/admin/deploy", corsHandler(api.authMiddleware(api.handleDeployContract)))
	mux.HandleFunc("/api/v1/security/admin/configure", corsHandler(api.authMiddleware(api.handleConfigure)))

	// Web interface
	mux.HandleFunc("/security", api.handleWebInterface)
	mux.HandleFunc("/security/dashboard", api.handleDashboard)

	log.Printf("🔒 Security API server starting on port %d", api.port)
	return http.ListenAndServe(fmt.Sprintf(":%d", api.port), mux)
}

// Middleware for API key authentication
func (api *SecurityAPI) authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		apiKey := r.Header.Get("X-API-Key")
		if apiKey != api.apiKey {
			api.sendError(w, "Unauthorized - Invalid API Key", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

// Health check endpoint
func (api *SecurityAPI) handleHealthCheck(w http.ResponseWriter, r *http.Request) {
	status := map[string]interface{}{
		"status":    "healthy",
		"timestamp": time.Now(),
		"version":   "1.0.0",
		"services": map[string]string{
			"threat_detector":     "active",
			"access_controller":   "active",
			"audit_logger":        "active",
			"incident_manager":    "active",
			"compliance_manager":  "active",
			"monitoring_engine":   "active",
		},
	}

	api.sendSuccess(w, status)
}

// Security metrics endpoint
func (api *SecurityAPI) handleMetrics(w http.ResponseWriter, r *http.Request) {
	metrics := api.securityManager.GetSecurityMetrics()
	api.sendSuccess(w, metrics)
}

// Threat detection endpoint
func (api *SecurityAPI) handleThreats(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		var req struct {
			Data   string `json:"data"`
			Source string `json:"source"`
		}

		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			api.sendError(w, "Invalid request format", http.StatusBadRequest)
			return
		}

		threats := api.securityManager.DetectThreats([]byte(req.Data), req.Source)
		api.sendSuccess(w, map[string]interface{}{
			"threats_detected": len(threats),
			"threats":          threats,
		})
	} else {
		api.sendError(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// Security contracts endpoint
func (api *SecurityAPI) handleContracts(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		// List all security contracts
		contracts := make([]map[string]interface{}, 0)
		for id, contract := range api.securityManager.contracts {
			contracts = append(contracts, map[string]interface{}{
				"id":          id,
				"name":        contract.Name,
				"type":        contract.Type,
				"status":      contract.Status,
				"created_at":  contract.CreatedAt,
				"rules_count": len(contract.Rules),
			})
		}
		api.sendSuccess(w, map[string]interface{}{
			"contracts": contracts,
			"total":     len(contracts),
		})

	case "POST":
		// Deploy new security contract
		var req struct {
			Type        SecurityContractType `json:"type"`
			Name        string               `json:"name"`
			Description string               `json:"description"`
			Creator     string               `json:"creator"`
		}

		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			api.sendError(w, "Invalid request format", http.StatusBadRequest)
			return
		}

		contract, err := api.securityManager.DeploySecurityContract(req.Type, req.Name, req.Description, req.Creator)
		if err != nil {
			api.sendError(w, fmt.Sprintf("Failed to deploy contract: %v", err), http.StatusInternalServerError)
			return
		}

		api.sendSuccess(w, map[string]interface{}{
			"contract_id": contract.ID,
			"message":     "Security contract deployed successfully",
		})

	default:
		api.sendError(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// Security rules endpoint
func (api *SecurityAPI) handleRules(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		// List active security rules
		api.sendSuccess(w, map[string]interface{}{
			"active_rules": api.securityManager.activeRules,
			"total":        len(api.securityManager.activeRules),
		})

	case "POST":
		// Add new security rule
		var req struct {
			ContractID  string        `json:"contract_id"`
			Name        string        `json:"name"`
			Description string        `json:"description"`
			Condition   string        `json:"condition"`
			Action      SecurityAction `json:"action"`
			Severity    SeverityLevel `json:"severity"`
			Enabled     bool          `json:"enabled"`
		}

		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			api.sendError(w, "Invalid request format", http.StatusBadRequest)
			return
		}

		rule := SecurityRule{
			Name:        req.Name,
			Description: req.Description,
			Condition:   req.Condition,
			Action:      req.Action,
			Severity:    req.Severity,
			Enabled:     req.Enabled,
		}

		err := api.securityManager.AddSecurityRule(req.ContractID, rule)
		if err != nil {
			api.sendError(w, fmt.Sprintf("Failed to add rule: %v", err), http.StatusInternalServerError)
			return
		}

		api.sendSuccess(w, map[string]interface{}{
			"message": "Security rule added successfully",
		})

	default:
		api.sendError(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// Security incidents endpoint
func (api *SecurityAPI) handleIncidents(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		// List security incidents
		incidents := make([]map[string]interface{}, 0)
		for id, incident := range api.securityManager.incidentManager.incidents {
			incidents = append(incidents, map[string]interface{}{
				"id":          id,
				"title":       incident.Title,
				"severity":    incident.Severity,
				"status":      incident.Status,
				"category":    incident.Category,
				"created_at":  incident.CreatedAt,
				"reporter":    incident.Reporter,
			})
		}
		api.sendSuccess(w, map[string]interface{}{
			"incidents": incidents,
			"total":     len(incidents),
		})

	case "POST":
		// Report new incident
		var req struct {
			Title       string            `json:"title"`
			Description string            `json:"description"`
			Reporter    string            `json:"reporter"`
			Severity    SeverityLevel     `json:"severity"`
			Category    IncidentCategory  `json:"category"`
		}

		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			api.sendError(w, "Invalid request format", http.StatusBadRequest)
			return
		}

		incident, err := api.securityManager.ReportIncident(req.Title, req.Description, req.Reporter, req.Severity, req.Category)
		if err != nil {
			api.sendError(w, fmt.Sprintf("Failed to report incident: %v", err), http.StatusInternalServerError)
			return
		}

		api.sendSuccess(w, map[string]interface{}{
			"incident_id": incident.ID,
			"message":     "Security incident reported successfully",
		})

	default:
		api.sendError(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// Audit logs endpoint
func (api *SecurityAPI) handleAudit(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		api.sendError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse query parameters
	limit := 100
	if l := r.URL.Query().Get("limit"); l != "" {
		if parsed, err := strconv.Atoi(l); err == nil && parsed > 0 && parsed <= 1000 {
			limit = parsed
		}
	}

	// Get recent audit logs
	logs := api.securityManager.auditLogger.logs
	if len(logs) > limit {
		logs = logs[len(logs)-limit:]
	}

	api.sendSuccess(w, map[string]interface{}{
		"audit_logs": logs,
		"total":      len(logs),
		"limit":      limit,
	})
}

// Compliance endpoint
func (api *SecurityAPI) handleCompliance(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		api.sendError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	status := api.securityManager.complianceManager.GetOverallStatus()
	api.sendSuccess(w, map[string]interface{}{
		"overall_status": status,
		"frameworks":     api.securityManager.complianceManager.frameworks,
		"checks":         api.securityManager.complianceManager.checks,
		"reports":        api.securityManager.complianceManager.reports,
	})
}

// Access control endpoint
func (api *SecurityAPI) handleAccessControl(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		var req struct {
			Subject  string `json:"subject"`
			Resource string `json:"resource"`
			Action   string `json:"action"`
		}

		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			api.sendError(w, "Invalid request format", http.StatusBadRequest)
			return
		}

		allowed, reason := api.securityManager.CheckAccess(req.Subject, req.Resource, req.Action)
		api.sendSuccess(w, map[string]interface{}{
			"allowed": allowed,
			"reason":  reason,
		})
	} else {
		api.sendError(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// Deploy contract endpoint
func (api *SecurityAPI) handleDeployContract(w http.ResponseWriter, r *http.Request) {
	// Implementation for contract deployment
	api.sendSuccess(w, map[string]interface{}{
		"message": "Contract deployment endpoint",
	})
}

// Configure endpoint
func (api *SecurityAPI) handleConfigure(w http.ResponseWriter, r *http.Request) {
	// Implementation for configuration
	api.sendSuccess(w, map[string]interface{}{
		"message": "Configuration endpoint",
	})
}

// Web interface endpoints
func (api *SecurityAPI) handleWebInterface(w http.ResponseWriter, r *http.Request) {
	html := `
<!DOCTYPE html>
<html>
<head>
    <title>🔒 BlackHole Cybersecurity Dashboard</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            min-height: 100vh; color: white; padding: 20px;
        }
        .container { max-width: 1400px; margin: 0 auto; }
        .header { text-align: center; margin-bottom: 40px; }
        .header h1 {
            font-size: 3em; margin-bottom: 15px;
            background: linear-gradient(45deg, #ff6b6b, #4ecdc4);
            -webkit-background-clip: text; -webkit-text-fill-color: transparent;
        }
        .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; }
        .card {
            background: rgba(255,255,255,0.1); backdrop-filter: blur(15px);
            border-radius: 15px; padding: 25px; border: 1px solid rgba(255,255,255,0.2);
        }
        .metric { text-align: center; margin: 15px 0; }
        .metric-value { font-size: 2em; font-weight: bold; color: #4ecdc4; }
        .metric-label { font-size: 0.9em; opacity: 0.8; }
        .status-good { color: #4ecdc4; }
        .status-warning { color: #ffa726; }
        .status-critical { color: #ff6b6b; }
        button {
            background: linear-gradient(45deg, #ff6b6b, #4ecdc4);
            border: none; padding: 10px 20px; border-radius: 8px;
            color: white; cursor: pointer; margin: 5px;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔒 Cybersecurity Dashboard</h1>
            <p>BlackHole Blockchain Security Management</p>
        </div>
        
        <div class="grid">
            <div class="card">
                <h3>🛡️ Security Status</h3>
                <div class="metric">
                    <div class="metric-value status-good" id="securityStatus">SECURE</div>
                    <div class="metric-label">Overall Status</div>
                </div>
                <button onclick="refreshStatus()">Refresh Status</button>
            </div>
            
            <div class="card">
                <h3>📊 Security Metrics</h3>
                <div class="metric">
                    <div class="metric-value" id="totalContracts">-</div>
                    <div class="metric-label">Security Contracts</div>
                </div>
                <div class="metric">
                    <div class="metric-value" id="activeRules">-</div>
                    <div class="metric-label">Active Rules</div>
                </div>
            </div>
            
            <div class="card">
                <h3>🚨 Incidents</h3>
                <div class="metric">
                    <div class="metric-value" id="openIncidents">-</div>
                    <div class="metric-label">Open Incidents</div>
                </div>
                <button onclick="viewIncidents()">View All Incidents</button>
            </div>
            
            <div class="card">
                <h3>📋 Compliance</h3>
                <div class="metric">
                    <div class="metric-value" id="complianceStatus">-</div>
                    <div class="metric-label">Compliance Status</div>
                </div>
                <button onclick="viewCompliance()">View Details</button>
            </div>
        </div>
    </div>

    <script>
        function refreshStatus() {
            fetch('/api/v1/security/metrics')
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    document.getElementById('totalContracts').textContent = data.data.total_contracts || 0;
                    document.getElementById('activeRules').textContent = data.data.active_rules || 0;
                    document.getElementById('openIncidents').textContent = data.data.open_incidents || 0;
                    document.getElementById('complianceStatus').textContent = data.data.compliance_status || 'Unknown';
                }
            })
            .catch(error => console.error('Error:', error));
        }

        function viewIncidents() {
            window.open('/api/v1/security/incidents', '_blank');
        }

        function viewCompliance() {
            window.open('/api/v1/security/compliance', '_blank');
        }

        // Auto-refresh every 30 seconds
        setInterval(refreshStatus, 30000);
        refreshStatus(); // Initial load
    </script>
</body>
</html>`

	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte(html))
}

func (api *SecurityAPI) handleDashboard(w http.ResponseWriter, r *http.Request) {
	// Redirect to main interface
	http.Redirect(w, r, "/security", http.StatusFound)
}

// Utility functions
func (api *SecurityAPI) sendError(w http.ResponseWriter, message string, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":   false,
		"error":     message,
		"timestamp": time.Now(),
	})
}

func (api *SecurityAPI) sendSuccess(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":   true,
		"data":      data,
		"timestamp": time.Now(),
	})
}
