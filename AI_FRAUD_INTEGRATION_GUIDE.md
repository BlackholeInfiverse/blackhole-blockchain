# 🤖 AI Fraud Detection Integration Guide

## For Keval & Aryan

**SIMPLE INTEGRATION:** Just give us your ngrok URL and one API endpoint. We'll handle everything else!

## 🎯 **What We Need from You**

### **1. Your Ngrok URL**
Just share your ngrok URL, like:
```
https://abc123-def456.ngrok.io
```

### **2. One Simple API Endpoint**
**Route:** `GET /api/wallet-data/{wallet_address}`

**Return ALL your data** - we'll decide how to use it:
```json
{
  "wallet": "alice",
  "reports": [
    {
      "reason": "Large unusual transfer",
      "severity": 4,
      "status": "approved",
      "riskLevel": "high",
      "riskScore": 85,
      "tags": ["large-transfer", "anomaly"],
      "ipGeo": {
        "city": "Unknown",
        "org": "Suspicious VPN"
      },
      "source": "contract",
      "createdAt": "2024-01-01T12:00:00Z"
    }
  ],
  "totalReports": 3,
  "approvedReports": 2,
  "highestRiskScore": 85,
  "highestSeverity": 4,
  "commonTags": ["large-transfer", "phishing"],
  "lastReportDate": "2024-01-01T12:00:00Z"
}
```

### **3. That's It!**
- ✅ **Keep your existing MongoDB schema** - don't change anything
- ✅ **Keep your existing dashboard** - no modifications needed
- ✅ **Keep your existing workflow** - pending/approved/rejected stays the same
- ✅ **Just give us the data** - we'll decide the blocking logic

## 🔗 **How It Works**

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   BlackHole     │    │   Your Ngrok    │    │   Your MongoDB  │
│   Blockchain    │    │   API Service   │    │   Database      │
│   (Shivam's)    │    │   (Your URL)    │    │   (Existing)    │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         │ 1. Check wallet       │                       │
         │ ─────────────────────▶│                       │
         │                       │ 2. Query reports      │
         │                       │ ─────────────────────▶│
         │                       │ 3. Return all data    │
         │                       │◀─────────────────────│
         │ 4. Get full data      │                       │
         │◀─────────────────────│                       │
         │ 5. WE decide to       │                       │
         │    block/allow        │                       │
```

**Simple:** You give us ALL your data, we decide what to do with it!

## 💻 **Simple Implementation Example**

### **Node.js/Express Example:**
```javascript
const express = require('express');
const Report = require('./models/Report'); // Your existing model
const app = express();

// The ONLY endpoint we need
app.get('/api/wallet-data/:wallet', async (req, res) => {
  try {
    const wallet = req.params.wallet;

    // Get all reports for this wallet using YOUR existing schema
    const reports = await Report.find({ wallet: wallet });

    // Calculate summary data
    const approvedReports = reports.filter(r => r.status === 'approved');
    const highestRiskScore = Math.max(...reports.map(r => r.riskScore), 0);
    const highestSeverity = Math.max(...reports.map(r => r.severity), 0);

    // Get all unique tags
    const allTags = reports.flatMap(r => r.tags);
    const commonTags = [...new Set(allTags)];

    // Return EVERYTHING - let Shivam's blockchain decide what to do
    res.json({
      wallet: wallet,
      reports: reports,                    // All your report data
      totalReports: reports.length,
      approvedReports: approvedReports.length,
      pendingReports: reports.filter(r => r.status === 'pending').length,
      rejectedReports: reports.filter(r => r.status === 'rejected').length,
      escalatedReports: reports.filter(r => r.status === 'escalated').length,
      highestRiskScore: highestRiskScore,
      highestSeverity: highestSeverity,
      commonTags: commonTags,
      lastReportDate: reports.length > 0 ? reports[reports.length - 1].createdAt : null,
      hasHighRiskReports: approvedReports.some(r => r.riskScore >= 80),
      hasPhishingTags: commonTags.includes('phishing'),
      hasBotnetTags: commonTags.includes('botnet'),
      // Add any other data you want us to have access to
    });

  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.listen(3000, () => {
  console.log('API running on port 3000');
  console.log('Ngrok this port and share the URL with Shivam');
});
```

### **That's All You Need!**
- ✅ **One endpoint** - `/api/wallet-data/{wallet}`
- ✅ **Return all your data** - we'll use what we need
- ✅ **Keep your existing code** - no changes to your schema or dashboard

## 🎯 **Our Decision Logic (Shivam's Side)**

**We'll get ALL your data and decide using these rules:**

```go
// We block wallets if:
1. ApprovedReports >= 2                    // 2+ approved reports
2. HighestRiskScore >= 90                  // Very high risk (90-100)
3. HighestSeverity >= 5 AND approved > 0  // Max severity + approved
4. HasPhishingTags = true                  // Phishing detected
5. HasBotnetTags = true                    // Botnet detected
6. HasHighRiskReports = true AND approved > 0  // High risk + approved
```

**Examples:**
- ✅ **Allow:** 1 pending report, risk score 60
- ❌ **Block:** 2 approved reports, any risk score
- ❌ **Block:** 1 approved report with phishing tags
- ❌ **Block:** Risk score 95, even if pending
- ✅ **Allow:** 5 rejected reports (rejected = safe)

## 🚀 **Quick Setup Steps**

### **Step 1: Add the endpoint to your existing API**
```javascript
// Add this to your existing Express app
app.get('/api/wallet-data/:wallet', async (req, res) => {
  // Copy the code from above
});
```

### **Step 2: Start ngrok**
```bash
ngrok http 3000
# Copy the https URL (e.g., https://abc123.ngrok.io)
```

### **Step 3: Share with Shivam**
```
"Hey Shivam, our API is ready:
URL: https://abc123.ngrok.io
Endpoint: GET /api/wallet-data/{wallet}
Test it: https://abc123.ngrok.io/api/wallet-data/test_wallet"
```

### **Step 4: Test Integration**
```bash
# Test your endpoint
curl https://your-ngrok-url.ngrok.io/api/wallet-data/alice

# Should return all your MongoDB data
```

## ✅ **Integration Complete!**

**That's it! Super simple:**

1. ✅ **You:** Add one endpoint that returns all your MongoDB data
2. ✅ **Us:** We call your endpoint and decide whether to block transactions
3. ✅ **Result:** Your AI fraud detection protects the blockchain!

**No complex integration, no schema changes, no new databases needed!** 🚀

