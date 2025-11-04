package cybersecurity

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"regexp"
	"strings"
	"time"
)

// ThreatDetection represents a detected threat
type ThreatDetection struct {
	ID          string                 `json:"id"`
	ThreatType  ThreatType             `json:"threat_type"`
	Severity    SeverityLevel          `json:"severity"`
	Confidence  float64                `json:"confidence"`
	Source      string                 `json:"source"`
	Description string                 `json:"description"`
	Evidence    []Evidence             `json:"evidence"`
	Timestamp   time.Time              `json:"timestamp"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// NewThreatDetector creates a new threat detector
func NewThreatDetector() *ThreatDetector {
	return &ThreatDetector{
		signatures:     make(map[string]*ThreatSignature),
		detectionRules: make([]DetectionRule, 0),
		alertThreshold: 0.7, // 70% confidence threshold
	}
}

// AnalyzeData analyzes data for potential threats
func (td *ThreatDetector) AnalyzeData(data []byte, source string) []ThreatDetection {
	td.mu.RLock()
	defer td.mu.RUnlock()

	var detections []ThreatDetection
	dataStr := string(data)

	// Check against threat signatures
	for _, signature := range td.signatures {
		if td.matchesSignature(dataStr, signature) {
			detection := ThreatDetection{
				ID:          generateDetectionID(),
				ThreatType:  signature.ThreatType,
				Severity:    signature.Severity,
				Confidence:  signature.Confidence,
				Source:      source,
				Description: fmt.Sprintf("Threat detected: %s", signature.Name),
				Evidence: []Evidence{
					{
						Type:        "signature_match",
						Description: fmt.Sprintf("Matched signature: %s", signature.Name),
						Data:        signature.Pattern,
						Hash:        calculateHash(signature.Pattern),
						Timestamp:   time.Now(),
					},
				},
				Timestamp: time.Now(),
				Metadata: map[string]interface{}{
					"signature_id": signature.ID,
					"pattern":      signature.Pattern,
				},
			}
			detections = append(detections, detection)
		}
	}

	// Check against detection rules
	for _, rule := range td.detectionRules {
		if td.matchesRule(dataStr, &rule) {
			detection := ThreatDetection{
				ID:          generateDetectionID(),
				ThreatType:  ThreatIntrusion, // Default type for rule-based detection
				Severity:    SeverityMedium,
				Confidence:  0.8,
				Source:      source,
				Description: fmt.Sprintf("Rule violation: %s", rule.Pattern),
				Evidence: []Evidence{
					{
						Type:        "rule_match",
						Description: fmt.Sprintf("Matched rule: %s", rule.ID),
						Data:        rule.Pattern,
						Hash:        calculateHash(rule.Pattern),
						Timestamp:   time.Now(),
					},
				},
				Timestamp: time.Now(),
				Metadata: map[string]interface{}{
					"rule_id": rule.ID,
					"pattern": rule.Pattern,
				},
			}
			detections = append(detections, detection)
		}
	}

	return detections
}

// matchesSignature checks if data matches a threat signature
func (td *ThreatDetector) matchesSignature(data string, signature *ThreatSignature) bool {
	// Simple pattern matching - in production, this would be more sophisticated
	matched, err := regexp.MatchString(signature.Pattern, data)
	if err != nil {
		log.Printf("Error matching signature pattern: %v", err)
		return false
	}
	return matched
}

// matchesRule checks if data matches a detection rule
func (td *ThreatDetector) matchesRule(data string, rule *DetectionRule) bool {
	// Simple pattern matching
	return strings.Contains(data, rule.Pattern)
}

// NewAccessController creates a new access controller
func NewAccessController() *AccessController {
	return &AccessController{
		policies:       make(map[string]*SecurityPolicy),
		accessRules:    make(map[string]*AccessControl),
		sessionManager: NewSessionManager(),
	}
}

// CheckAccess checks if access should be granted
func (ac *AccessController) CheckAccess(subject, resource, action string) (bool, string) {
	ac.mu.RLock()
	defer ac.mu.RUnlock()

	// Check explicit access rules first
	for _, rule := range ac.accessRules {
		if rule.Subject == subject && rule.Resource == resource && rule.Action == action {
			switch rule.Permission {
			case PermissionAllow:
				return true, fmt.Sprintf("Explicit allow rule: %s", rule.ID)
			case PermissionDeny:
				return false, fmt.Sprintf("Explicit deny rule: %s", rule.ID)
			case PermissionConditional:
				// Check conditions (simplified)
				if ac.checkConditions(rule.Conditions, subject, resource, action) {
					return true, fmt.Sprintf("Conditional allow: %s", rule.ID)
				}
				return false, fmt.Sprintf("Conditional deny: %s", rule.ID)
			}
		}
	}

	// Check policies
	for _, policy := range ac.policies {
		if ac.policyApplies(policy, subject, resource, action) {
			switch policy.Enforcement {
			case EnforcementMandatory, EnforcementStrict:
				return false, fmt.Sprintf("Policy enforcement: %s", policy.Name)
			case EnforcementAdvisory:
				log.Printf("Advisory policy violation: %s", policy.Name)
			}
		}
	}

	// Default deny
	return false, "No explicit permission found"
}

// checkConditions checks if conditions are met (simplified implementation)
func (ac *AccessController) checkConditions(conditions []string, subject, resource, action string) bool {
	// Simplified condition checking
	for _, condition := range conditions {
		if strings.Contains(condition, "time") {
			// Time-based condition
			now := time.Now()
			if now.Hour() < 9 || now.Hour() > 17 {
				return false // Outside business hours
			}
		}
		// Add more condition types as needed
	}
	return true
}

// policyApplies checks if a policy applies to the given access request
func (ac *AccessController) policyApplies(policy *SecurityPolicy, subject, resource, action string) bool {
	// Check if the resource is in the policy scope
	for _, scope := range policy.Scope {
		if strings.Contains(resource, scope) {
			return true
		}
	}
	return false
}

// NewSessionManager creates a new session manager
func NewSessionManager() *SessionManager {
	return &SessionManager{
		sessions: make(map[string]*SecuritySession),
		timeout:  30 * time.Minute,
	}
}

// NewAuditLogger creates a new audit logger
func NewAuditLogger() *AuditLogger {
	return &AuditLogger{
		logs:      make([]AuditLog, 0),
		retention: 365 * 24 * time.Hour, // 1 year
		maxLogs:   100000,               // Maximum 100k logs
	}
}

// LogEvent logs a security event
func (al *AuditLogger) LogEvent(actor, action, resource string, result AuditResult, details, ipAddress, userAgent string) {
	al.mu.Lock()
	defer al.mu.Unlock()

	logEntry := AuditLog{
		ID:        generateAuditLogID(),
		Timestamp: time.Now(),
		Actor:     actor,
		Action:    action,
		Resource:  resource,
		Result:    result,
		Details:   details,
		IPAddress: ipAddress,
		UserAgent: userAgent,
		Metadata:  make(map[string]interface{}),
	}

	al.logs = append(al.logs, logEntry)

	// Enforce max logs limit
	if len(al.logs) > al.maxLogs {
		al.logs = al.logs[len(al.logs)-al.maxLogs:]
	}

	log.Printf("📝 Audit log: %s performed %s on %s - %v", actor, action, resource, result)
}

// CleanupOldLogs removes old audit logs based on retention policy
func (al *AuditLogger) CleanupOldLogs() {
	al.mu.Lock()
	defer al.mu.Unlock()

	cutoff := time.Now().Add(-al.retention)
	var newLogs []AuditLog

	for _, logEntry := range al.logs {
		if logEntry.Timestamp.After(cutoff) {
			newLogs = append(newLogs, logEntry)
		}
	}

	removed := len(al.logs) - len(newLogs)
	al.logs = newLogs

	if removed > 0 {
		log.Printf("🧹 Cleaned up %d old audit logs", removed)
	}
}

// NewIncidentManager creates a new incident manager
func NewIncidentManager() *IncidentManager {
	return &IncidentManager{
		incidents:       make(map[string]*SecurityIncident),
		responseTeam:    []string{"security_admin", "incident_commander"},
		escalationRules: make([]EscalationRule, 0),
	}
}

// ReportIncident reports a new security incident
func (im *IncidentManager) ReportIncident(title, description, reporter string, severity SeverityLevel, category IncidentCategory) (*SecurityIncident, error) {
	im.mu.Lock()
	defer im.mu.Unlock()

	incident := &SecurityIncident{
		ID:          generateIncidentID(),
		Title:       title,
		Description: description,
		Severity:    severity,
		Status:      IncidentOpen,
		Category:    category,
		Reporter:    reporter,
		Assignee:    im.getNextAssignee(),
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
		Evidence:    make([]Evidence, 0),
		Response:    make([]ResponseAction, 0),
		Metadata:    make(map[string]interface{}),
	}

	im.incidents[incident.ID] = incident
	log.Printf("🚨 Security incident reported: %s (%s)", title, incident.ID)
	return incident, nil
}

// GetOpenIncidentCount returns the number of open incidents
func (im *IncidentManager) GetOpenIncidentCount() int {
	im.mu.RLock()
	defer im.mu.RUnlock()

	count := 0
	for _, incident := range im.incidents {
		if incident.Status == IncidentOpen || incident.Status == IncidentInProgress {
			count++
		}
	}
	return count
}

// getNextAssignee returns the next assignee for an incident
func (im *IncidentManager) getNextAssignee() string {
	if len(im.responseTeam) > 0 {
		return im.responseTeam[0] // Simple round-robin could be implemented
	}
	return "unassigned"
}

// NewComplianceManager creates a new compliance manager
func NewComplianceManager() *ComplianceManager {
	return &ComplianceManager{
		frameworks: make(map[string]*ComplianceFramework),
		checks:     make(map[string]*ComplianceCheck),
		reports:    make([]ComplianceReport, 0),
	}
}

// GetOverallStatus returns the overall compliance status
func (cm *ComplianceManager) GetOverallStatus() string {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	totalChecks := len(cm.checks)
	if totalChecks == 0 {
		return "no_checks"
	}

	passCount := 0
	for _, check := range cm.checks {
		if check.Status == CompliancePass {
			passCount++
		}
	}

	percentage := float64(passCount) / float64(totalChecks) * 100
	if percentage >= 95 {
		return "excellent"
	} else if percentage >= 80 {
		return "good"
	} else if percentage >= 60 {
		return "needs_improvement"
	} else {
		return "poor"
	}
}

// NewMonitoringEngine creates a new monitoring engine
func NewMonitoringEngine() *MonitoringEngine {
	return &MonitoringEngine{
		rules:   make(map[string]*MonitoringRule),
		alerts:  make([]SecurityAlert, 0),
		metrics: make(map[string]float64),
	}
}

// Utility functions
func generateDetectionID() string {
	return fmt.Sprintf("detection_%d", time.Now().UnixNano())
}

func generateAuditLogID() string {
	return fmt.Sprintf("audit_%d", time.Now().UnixNano())
}

func generateIncidentID() string {
	return fmt.Sprintf("incident_%d", time.Now().UnixNano())
}

func calculateHash(data string) string {
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}
