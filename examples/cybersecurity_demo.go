package main

import (
	"fmt"
	"log"

	"github.com/Shivam-Patel-G/blackhole-blockchain/core/relay-chain/chain"
	"github.com/Shivam-Patel-G/blackhole-blockchain/core/relay-chain/cybersecurity"
)

func main() {
	fmt.Println("🔒 BlackHole Blockchain Cybersecurity Demo")
	fmt.Println("==========================================")

	// Initialize blockchain
	blockchain := initializeBlockchain()

	// Initialize cybersecurity system
	if err := blockchain.InitializeCybersecurity(); err != nil {
		log.Fatalf("Failed to initialize cybersecurity: %v", err)
	}

	// Demo 1: Threat Detection
	fmt.Println("\n🔍 Demo 1: Threat Detection")
	demonstrateThreatDetection(blockchain)

	// Demo 2: Access Control
	fmt.Println("\n🛡️ Demo 2: Access Control")
	demonstrateAccessControl(blockchain)

	// Demo 3: Security Incident Management
	fmt.Println("\n🚨 Demo 3: Security Incident Management")
	demonstrateIncidentManagement(blockchain)

	// Demo 4: Compliance Monitoring
	fmt.Println("\n📋 Demo 4: Compliance Monitoring")
	demonstrateComplianceMonitoring(blockchain)

	// Demo 5: Security Audit Logging
	fmt.Println("\n📝 Demo 5: Security Audit Logging")
	demonstrateAuditLogging(blockchain)

	// Demo 6: Custom Security Rules
	fmt.Println("\n⚙️ Demo 6: Custom Security Rules")
	demonstrateCustomRules(blockchain)

	// Demo 7: Real-time Security Monitoring
	fmt.Println("\n📊 Demo 7: Real-time Security Monitoring")
	demonstrateRealTimeMonitoring(blockchain)

	// Start Security API Server
	fmt.Println("\n🌐 Starting Security API Server...")
	startSecurityAPI(blockchain)
}

func initializeBlockchain() *chain.Blockchain {
	// Create a new blockchain instance
	blockchain := &chain.Blockchain{
		Blocks:     make([]*chain.Block, 0),
		PendingTxs: make([]*chain.Transaction, 0),
	}

	log.Println("✅ Blockchain initialized")
	return blockchain
}

func demonstrateThreatDetection(blockchain *chain.Blockchain) {
	// Add threat signatures
	malwareSignature := cybersecurity.ThreatSignature{
		Name:       "Malware Pattern Detection",
		Pattern:    "malicious_payload|virus|trojan",
		ThreatType: cybersecurity.ThreatMalware,
		Severity:   cybersecurity.SeverityHigh,
		Confidence: 0.9,
	}

	phishingSignature := cybersecurity.ThreatSignature{
		Name:       "Phishing Attempt",
		Pattern:    "phishing|fake_wallet|steal_keys",
		ThreatType: cybersecurity.ThreatPhishing,
		Severity:   cybersecurity.SeverityCritical,
		Confidence: 0.95,
	}

	blockchain.SecurityManager.AddThreatSignature(malwareSignature)
	blockchain.SecurityManager.AddThreatSignature(phishingSignature)

	// Test threat detection
	testData := []string{
		"normal transaction data",
		"suspicious malicious_payload detected",
		"phishing attempt to steal_keys",
		"regular blockchain operation",
	}

	for i, data := range testData {
		threats := blockchain.SecurityManager.DetectThreats([]byte(data), fmt.Sprintf("test_source_%d", i))
		if len(threats) > 0 {
			fmt.Printf("  🚨 Threats detected in data %d: %d threats\n", i, len(threats))
			for _, threat := range threats {
				fmt.Printf("    - %s (Confidence: %.2f, Severity: %d)\n", 
					threat.Description, threat.Confidence, threat.Severity)
			}
		} else {
			fmt.Printf("  ✅ No threats detected in data %d\n", i)
		}
	}
}

func demonstrateAccessControl(blockchain *chain.Blockchain) {
	// Test access control
	testCases := []struct {
		subject  string
		resource string
		action   string
	}{
		{"admin_user", "blockchain_transaction", "submit"},
		{"regular_user", "admin_panel", "access"},
		{"validator", "block_creation", "create"},
		{"guest_user", "sensitive_data", "read"},
	}

	for _, test := range testCases {
		allowed, reason := blockchain.SecurityManager.CheckAccess(test.subject, test.resource, test.action)
		status := "❌ DENIED"
		if allowed {
			status = "✅ ALLOWED"
		}
		fmt.Printf("  %s: %s accessing %s to %s - %s\n", 
			status, test.subject, test.resource, test.action, reason)
	}
}

func demonstrateIncidentManagement(blockchain *chain.Blockchain) {
	// Report test incidents
	incidents := []struct {
		title       string
		description string
		severity    cybersecurity.SeverityLevel
		category    cybersecurity.IncidentCategory
	}{
		{
			"Suspicious Transaction Pattern",
			"Multiple high-value transactions from new account",
			cybersecurity.SeverityMedium,
			cybersecurity.CategoryBreach,
		},
		{
			"Failed Login Attempts",
			"Multiple failed login attempts from same IP",
			cybersecurity.SeverityHigh,
			cybersecurity.CategoryUnauthorizedAccess,
		},
		{
			"Malware Detection",
			"Malicious code detected in smart contract",
			cybersecurity.SeverityCritical,
			cybersecurity.CategoryMalware,
		},
	}

	for _, inc := range incidents {
		incident, err := blockchain.SecurityManager.ReportIncident(
			inc.title, inc.description, "security_system", inc.severity, inc.category)
		if err != nil {
			fmt.Printf("  ❌ Failed to report incident: %v\n", err)
		} else {
			fmt.Printf("  🚨 Incident reported: %s (ID: %s)\n", inc.title, incident.ID)
		}
	}

	// Show incident statistics
	openCount := blockchain.SecurityManager.GetSecurityMetrics()["open_incidents"]
	fmt.Printf("  📊 Total open incidents: %v\n", openCount)
}

func demonstrateComplianceMonitoring(blockchain *chain.Blockchain) {
	// Get compliance status
	metrics := blockchain.SecurityManager.GetSecurityMetrics()
	complianceStatus := metrics["compliance_status"]
	fmt.Printf("  📋 Overall compliance status: %v\n", complianceStatus)

	// Simulate compliance checks
	frameworks := []string{"SOC2", "ISO27001", "GDPR", "PCI-DSS"}
	for _, framework := range frameworks {
		// In a real implementation, this would perform actual compliance checks
		status := "PASS"
		if framework == "PCI-DSS" {
			status = "NEEDS_REVIEW" // Simulate a compliance issue
		}
		fmt.Printf("  📋 %s compliance: %s\n", framework, status)
	}
}

func demonstrateAuditLogging(blockchain *chain.Blockchain) {
	// Log various security events
	events := []struct {
		actor    string
		action   string
		resource string
		result   cybersecurity.AuditResult
		details  string
	}{
		{"admin", "deploy_contract", "security_contract_001", cybersecurity.AuditSuccess, "Security contract deployed successfully"},
		{"user123", "access_sensitive_data", "user_database", cybersecurity.AuditFailure, "Access denied - insufficient permissions"},
		{"validator_node", "create_block", "block_12345", cybersecurity.AuditSuccess, "Block created and validated"},
		{"unknown_user", "brute_force_attack", "login_system", cybersecurity.AuditFailure, "Multiple failed login attempts blocked"},
	}

	for _, event := range events {
		blockchain.SecurityManager.LogSecurityEvent(
			event.actor, event.action, event.resource, event.result, event.details)
		
		resultStr := "SUCCESS"
		if event.result == cybersecurity.AuditFailure {
			resultStr = "FAILURE"
		}
		fmt.Printf("  📝 Logged: %s - %s (%s)\n", event.action, resultStr, event.actor)
	}
}

func demonstrateCustomRules(blockchain *chain.Blockchain) {
	// Find a security contract to add rules to
	var contractID string
	for id, _ := range blockchain.SecurityManager.GetSecurityMetrics() {
		if id == "total_contracts" {
			// Get the first available contract (simplified)
			contractID = "sec_threat_detection" // This would be dynamically determined
			break
		}
	}

	if contractID == "" {
		fmt.Println("  ⚠️ No security contracts available for rule addition")
		return
	}

	// Add custom security rules
	customRules := []cybersecurity.SecurityRule{
		{
			Name:        "Large Transaction Alert",
			Description: "Alert on transactions over 1 million tokens",
			Condition:   "transaction.amount > 1000000",
			Action:      cybersecurity.ActionAlert,
			Severity:    cybersecurity.SeverityMedium,
			Enabled:     true,
		},
		{
			Name:        "Rapid Transaction Block",
			Description: "Block accounts with more than 100 transactions per minute",
			Condition:   "transaction.frequency > 100 per minute",
			Action:      cybersecurity.ActionBlock,
			Severity:    cybersecurity.SeverityHigh,
			Enabled:     true,
		},
		{
			Name:        "Suspicious IP Monitor",
			Description: "Monitor transactions from known suspicious IP ranges",
			Condition:   "source.ip in suspicious_ranges",
			Action:      cybersecurity.ActionLog,
			Severity:    cybersecurity.SeverityLow,
			Enabled:     true,
		},
	}

	for _, rule := range customRules {
		err := blockchain.SecurityManager.AddSecurityRule(contractID, rule)
		if err != nil {
			fmt.Printf("  ❌ Failed to add rule '%s': %v\n", rule.Name, err)
		} else {
			fmt.Printf("  ✅ Added custom rule: %s\n", rule.Name)
		}
	}
}

func demonstrateRealTimeMonitoring(blockchain *chain.Blockchain) {
	// Get current security metrics
	metrics := blockchain.SecurityManager.GetSecurityMetrics()
	
	fmt.Println("  📊 Current Security Metrics:")
	for key, value := range metrics {
		fmt.Printf("    - %s: %v\n", key, value)
	}

	// Simulate real-time monitoring alerts
	alerts := []string{
		"High CPU usage detected on validator node",
		"Unusual network traffic pattern observed",
		"Failed authentication attempts spike detected",
		"Smart contract execution anomaly found",
	}

	fmt.Println("  🚨 Real-time Security Alerts:")
	for i, alert := range alerts {
		fmt.Printf("    %d. %s\n", i+1, alert)
	}
}

func startSecurityAPI(blockchain *chain.Blockchain) {
	// Create and start security API
	api := cybersecurity.NewSecurityAPI(blockchain.SecurityManager, "security_api_key_2024", 8096)
	
	fmt.Println("🌐 Security API Server Configuration:")
	fmt.Println("  - Port: 8096")
	fmt.Println("  - API Key: security_api_key_2024")
	fmt.Println("  - Web Interface: http://localhost:8096/security")
	fmt.Println("  - Health Check: http://localhost:8096/api/v1/security/health")
	fmt.Println("  - Metrics: http://localhost:8096/api/v1/security/metrics")
	
	fmt.Println("\n📡 Available API Endpoints:")
	endpoints := []string{
		"GET  /api/v1/security/health",
		"GET  /api/v1/security/metrics",
		"POST /api/v1/security/threats",
		"GET  /api/v1/security/contracts",
		"POST /api/v1/security/contracts",
		"GET  /api/v1/security/rules",
		"POST /api/v1/security/rules",
		"GET  /api/v1/security/incidents",
		"POST /api/v1/security/incidents",
		"GET  /api/v1/security/audit",
		"GET  /api/v1/security/compliance",
		"POST /api/v1/security/access",
	}
	
	for _, endpoint := range endpoints {
		fmt.Printf("  - %s\n", endpoint)
	}

	fmt.Println("\n🚀 Starting Security API Server...")
	fmt.Println("Press Ctrl+C to stop the server")
	
	// Start the API server (this will block)
	if err := api.Start(); err != nil {
		log.Fatalf("Failed to start security API server: %v", err)
	}
}
