# ThreatGraph Demo Flow

This is a polished demo flow from a cold start to an impressive finish.

The goal is to show:

- structured memory in SurrealDB
- LangGraph orchestration
- persistent thread state
- graph-backed attack-path reasoning

---

## Demo goal

Tell a story like this:

“ThreatGraph takes a seeded enterprise environment, grounds it in ATT&CK and CVE intelligence, and lets a stateful agent investigate exposure using a persistent SurrealDB-backed graph.”

---

## Step 1: Start from scratch

Run:

```bash
export SURREALDB_URL="file://$(pwd)/.context/demo.db"
export SURREALDB_NS="threatgraph"
export SURREALDB_DB="main"

python3 ingest.py
streamlit run app.py --server.address 127.0.0.1 --server.port 8501
```

What to say:

- “This is not a static screenshot. I am building the graph now.”
- “The ingest loads ATT&CK, the enterprise environment, software links, and CVE relationships.”

---

## Step 2: Show the sidebar

Point out:

- node/edge counts
- thread ID
- LangSmith tracing status
- recent investigation history

What to say:

- “This thread ID is the persistent investigation key.”
- “SurrealDB is storing both the graph and the investigation state.”

---

## Step 3: Run the first analyst question

Ask:

```text
Which asset is most exposed?
```

What to highlight:

- query classification
- threat assessment
- workflow state
- evidence bundle
- ranked assets

What to say:

- “This is not just an LLM answer.”
- “The result is grounded in graph evidence assembled from assets, software versions, CVEs, controls, and threat vectors.”

---

## Step 4: Show the Exposure tab

Move to the Exposure tab.

What to show:

- the top asset
- total score
- CVE and KEV counts

What to say:

- “The score is not just CVSS.”
- “It includes business criticality, crown-jewel status, network zone, controls, and non-software threats.”

---

## Step 5: Show the Attack Graph tab

Move to the Attack Graph tab.

Turn on:

- threat groups
- controls
- threat vectors
- attack paths

Open:

- `Detailed Attack Path Data`

What to show:

- path risk
- route
- top CVEs
- top threat groups

What to say:

- “This tab is not just network topology.”
- “The path candidates come from exploit-sequence logic over the evidence graph.”

---

## Step 6: Ask a named threat-group question

Back in Analyst, ask:

```text
tell me about Cleaver
```

What to show:

- matched group
- group exposure result
- relevant internal assets

What to say:

- “The system can resolve named threat groups and map them onto internal assets through ATT&CK software and evidence bundles.”

---

## Step 7: Show persistence with a follow-up

Without changing the thread ID, ask:

```text
Now give me remediation steps for that one
```

What to show:

- same thread ID
- prior context reused
- matched asset preserved
- new playbook returned

What to say:

- “This is the persistent-state part of the hackathon story.”
- “The follow-up is not stateless; it reloads the investigation context from SurrealDB.”

---

## Step 8: Close on the hackathon criteria

Say this clearly:

- “SurrealDB is the structured memory layer.”
- “LangGraph is the workflow/orchestration layer.”
- “The agent is stateful.”
- “The answers are evidence-backed.”
- “The graph and investigation history persist across turns.”

---

## Fast fallback demo

If time is short:

1. show sidebar thread ID
2. ask `Which asset is most exposed?`
3. open Attack Graph detail expander
4. ask follow-up `Now give me remediation steps for that one`

That is enough to demonstrate the core.
