# ThreatGraph Walkthrough

This document walks through the app functionality from first run to feature use.

It is written as a practical operator guide.

---

## 1. Start the system

### Option A: use the already-populated local DB

```bash
export SURREALDB_URL="file://$(pwd)/.context/dev-core-clean.db"
export SURREALDB_NS="threatgraph"
export SURREALDB_DB="main"

streamlit run app.py --server.address 127.0.0.1 --server.port 8501
```

### Option B: rebuild from scratch

```bash
export SURREALDB_URL="file://$(pwd)/.context/app.db"
export SURREALDB_NS="threatgraph"
export SURREALDB_DB="main"

python3 ingest.py
streamlit run app.py --server.address 127.0.0.1 --server.port 8501
```

---

## 2. Read the sidebar first

Before touching the tabs, look at the sidebar.

It tells you:

- how many nodes and edges are loaded
- whether the graph is populated
- which investigation thread is active
- whether LangSmith tracing is enabled or disabled
- what recent investigation history exists for the current thread

This is important because it proves the app is using persistent state.

---

## 3. Use the Analyst tab

The Analyst tab is the main demo path.

### What to do

1. Type a question in the analyst query box.
2. Click Analyze.

### Good questions

- `Which asset is most exposed?`
- `Am I vulnerable to APT29?`
- `tell me about Cleaver`
- `Now give me remediation steps for that one`

### What to look for

After a successful run, the page shows:

- query classification badge
- threat assessment
- workflow state
- evidence bundle summary
- ranked assets
- top CVE evidence
- evidence paths
- remediation playbook

### Why the Workflow State section matters

It makes the hidden workflow visible.

It shows:

- thread ID
- matched group
- matched asset
- prior context loaded for this thread

That is one of the easiest ways to demonstrate persistent state.

---

## 4. Reuse the same thread ID

This is one of the best hackathon demos.

### Example

1. Ask: `Which asset is most exposed?`
2. Keep the same thread ID in the sidebar.
3. Ask: `Now give me remediation steps for that one`

### What should happen

The app should:

- remember the previous top asset
- use that as the follow-up focus
- store the new investigation summary under the same thread

### Where you see proof

- the sidebar investigation history
- the workflow state section
- the resulting matched asset

---

## 5. Use the Exposure tab

This tab is for risk ranking.

### What it shows

- organization total score
- asset count
- total CVEs
- actively exploited CVEs
- per-asset exposure rows

### What to explain

The score is graph-backed, not only a vulnerability count.

It includes:

- CVEs
- KEV
- criticality
- criticality score
- crown-jewel state
- network zone
- controls
- threat vectors

---

## 6. Use the Attack Graph tab

This tab shows the enterprise attack surface visually.

### Controls

- filter by asset
- include threat groups
- show controls
- show threat vectors
- show attack paths

### What the graph should show

- assets
- internal software versions
- CVEs
- controls
- threat vectors
- optional ATT&CK threat layer

### What the detail expander shows

The `Detailed Attack Path Data` expander now shows structured path candidates:

- path number
- risk score
- route
- top CVEs on the path
- top threat groups on the path

That is better for a demo than only dumping per-asset data.

---

## 7. Use the Asset Intel tab

This tab is for one-asset deep dives.

### What to do

1. Choose an asset from the select box.
2. Review:
   - software inventory
   - CVEs
   - KEV count
   - controls
   - threat vectors
   - CVSS distribution

### What to explain

This tab is powered by the same evidence bundle the analyst uses.

It is not a separate fake asset page.

---

## 8. Use the ATT&CK Matrix tab

This tab is a threat-side view.

### What it shows

- tactics
- most active threat groups
- most commonly used ATT&CK software

### What to explain

These are live graph queries over the ATT&CK portion of SurrealDB, not a static image.

---

## 9. Use the Gaps tab

This tab surfaces unmitigated ATT&CK techniques.

### What it means

It is looking for ATT&CK techniques that are present in the graph evidence but do not have mapped mitigations.

### Why it is useful

It turns the graph into an action list, not just a diagram.

---

## 10. Use the Guide tab

The Guide tab is documentation inside the app.

It is useful for onboarding, but it is not the strongest part of the demo.

For judging, focus more on:

- Analyst
- Exposure
- Attack Graph
- persistent thread reuse

---

## 11. Best live demo order

The best live order is:

1. show sidebar node/edge counts and thread ID
2. ask an analyst question
3. show evidence bundle and workflow state
4. move to Exposure
5. move to Attack Graph
6. reuse the same thread for a follow-up query

This sequence makes the SurrealDB and LangGraph parts obvious.
