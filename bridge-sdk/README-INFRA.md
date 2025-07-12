# BlackHole Bridge Infra Dashboard & Core Infrastructure

## Overview
This document explains the workflow and usage of the advanced infrastructure dashboard and core modules (listener, retry, relay, mock endpoint) for the BlackHole Bridge, all integrated with the real BlackHole blockchain.

---

## Dashboard Access
- **Infra Dashboard URL:** `/infra-dashboard`
- **Main Dashboard URL:** `/`
- Use the navigation button to switch between dashboards.

---

## Dashboard Sections

### 1. Listener Status
- Shows real-time health of Ethereum, Solana, and BlackHole listeners.
- Displays the last event timestamp.
- **Purpose:** Monitor if listeners are running and catching events from the real blockchains.

### 2. Retry Queue
- Shows the current length of the retry queue and last retry time.
- **Purpose:** Ensures dropped/missed events are retried with exponential backoff and not lost.
- **Extending:** You can adjust retry logic in `retry_queue.go` and expose more stats via `/infra/retry-status`.

### 3. Relay Server
- Shows relay server status and last relay event.
- **Purpose:** Confirms the relay infrastructure is running and propagating cross-chain events.
- **Extending:** Add more relay stats or controls in `relay.go` and update `/infra/relay-status`.

### 4. Mock Endpoint
- Allows sending a mock event to `/mock/bridge` for safe testing.
- **Purpose:** Test the relay and event pipeline without affecting the real blockchain.
- **Extending:** Implement more complex mock scenarios in the handler.

---

## Rearranging/Extending Features
- The dashboard UI is modular and rearrangeable (drag-and-drop cards).
- To add new sections, create a new API endpoint and add a new card in the dashboard HTML/JS.
- All backend logic is encapsulated in separate handlers for easy modification.

---

## Security & Configuration
- All endpoints validate input and use replay protection where needed.
- Sensitive endpoints (relay, mock) can be restricted by IP or authentication in production.
- All configuration (RPC URLs, retry settings, etc.) is via environment variables or config files.

---

## Real BlackHole Blockchain Integration
- All listeners and relay logic are connected to the real BlackHole blockchain (not simulation).
- For more details, see `blockchain_interface.go` and the main `main.go` setup.

---

## How to Extend or Reverse Features
- Each feature is in its own handler/module. To disable, comment out the route or handler.
- To extend, add new API endpoints and dashboard cards as needed.
- All changes are non-destructive to the original dashboard and core logic.

---

## How to Add a New Infra Card/Feature

1. **Add a New API Endpoint**
   - In `example/main.go`, add a new `r.HandleFunc` route (e.g., `/infra/my-feature`) in the `StartWebServer` function.
   - Implement the handler to return JSON data for your feature.
   - Example:
     ```go
     r.HandleFunc("/infra/my-feature", func(w http.ResponseWriter, r *http.Request) {
         w.Header().Set("Content-Type", "application/json")
         json.NewEncoder(w).Encode(map[string]interface{}{
             "success": true,
             "data": map[string]interface{}{"my_metric": 42},
         })
     }).Methods("GET")
     ```

2. **Create a New Dashboard Card**
   - In the `handleInfraDashboard` HTML/JS, add a new `<div class="infra-card modular" ...>` for your feature.
   - Give it a unique `id` (e.g., `myFeatureCard`) and a section for content (e.g., `myFeatureStatus`).
   - Example:
     ```html
     <div class="infra-card modular" draggable="true" id="myFeatureCard">
         <h2>My Feature</h2>
         <div class="section-content" id="myFeatureStatus">Loading...</div>
     </div>
     ```

3. **Wire Up Real-Time Updates**
   - In the dashboard JS, add a fetch call in `updateInfraSections()` to your new endpoint.
   - Update the corresponding section content with the fetched data.
   - Example:
     ```js
     try {
         const res = await fetch('/infra/my-feature');
         const data = await res.json();
         document.getElementById('myFeatureStatus').textContent = data.success ? JSON.stringify(data.data, null, 2) : 'Error';
     } catch (e) { document.getElementById('myFeatureStatus').textContent = 'Error'; }
     ```

4. **Keep the Dashboard Modular**
   - Each card is rearrangeable via drag-and-drop.
   - Keep new features in their own Go handler and dashboard card for easy future modification or removal.

5. **(Optional) Add Integration Tests**
   - Add a test in `test-integration.go` to check your new endpoint for accessibility and correct response.

---

## Contact & Support
For questions or to report issues, contact the BlackHole Bridge development team. 