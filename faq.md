# ThreatGraph FAQ

## Product and problem

### What does ThreatGraph do?

It joins threat intelligence, enterprise assets, CVEs, controls, and threat vectors into one graph so the user can investigate exposure and attack paths.

### What is the practical use case?

Security prioritization:

- what to patch first
- which assets are most exposed
- which threat groups matter
- what attack paths exist

### Is this a real product or a demo?

It is a hackathon prototype with real graph/state logic and a seeded environment.

### Is the seeded environment static?

The seed data is deterministic, but it is stored as real graph records in SurrealDB and queried dynamically.

---

## Hackathon technologies

### Where is SurrealDB used?

SurrealDB stores:

- ATT&CK data
- asset/environment data
- software/CVE relationships
- controls and threat vectors
- investigation history
- workflow checkpoint data

### Where is LangGraph used?

The query workflow in `src/agents/workflow.py` is built as a LangGraph state graph with routing and persistence.

### Where is LangChain used?

LangChain is used for model wrappers and ecosystem compatibility around the LangGraph workflow.

### Is this actually using structured memory?

Yes.

The graph and the investigation thread state are both persistent structured memory.

### What is the persistent state?

- investigation summaries
- checkpoint rows
- checkpoint write logs
- graph state itself

---

## Investigation state and threads

### What is the thread ID?

It is the investigation session key.

### Why does it matter?

Because follow-up queries reuse it to load prior context.

### Is the thread ID fake UI?

No.

It is passed into the workflow and used to retrieve prior saved investigation data.

### What happens if I change the thread ID?

You start a different investigation context.

### What happens if I keep the same thread ID?

The next question can reuse the prior focus asset/group.

---

## Tracing and observability

### What does `LangSmith tracing: disabled` mean?

The app checked tracing configuration and determined LangSmith is not active in the current environment.

### Does the app still work if tracing is disabled?

Yes.

### How do I enable tracing?

Set:

- `LANGSMITH_API_KEY`
- `LANGCHAIN_TRACING_V2=true`
- optionally `LANGCHAIN_PROJECT`

### Why is tracing important?

It helps show:

- workflow execution
- node ordering
- state transitions
- timing

### How should I showcase tracing in a demo?

Run one query and one follow-up with the same thread ID, then open the LangSmith project and show both runs.

---

## Graph and data model

### What is the difference between `software_version` and ATT&CK `software`?

- `software_version` = what is installed on your asset
- `software` = ATT&CK software concept from MITRE

### Why does that distinction matter?

Because the bridge between the two is what makes internal asset exposure relevant to ATT&CK behavior.

### What is `linked_to_software`?

It is the bridge edge between internal software versions and ATT&CK software.

### What is `has_cve`?

The edge between a software version and a CVE.

### What is `affects`?

The edge from a CVE to an asset after blast radius is resolved.

### What is a threat vector in this app?

A non-software exposure source like phishing, brute force, or man-in-the-middle.

### What is a crown jewel?

A business-critical asset given special importance in scoring and path analysis.

---

## Scoring

### Is the score just CVSS?

No.

### What contributes to the score?

- CVSS
- KEV
- criticality
- criticality score
- crown-jewel status
- network zone
- controls
- threat vectors
- ATT&CK software relevance

### Why can an asset with few CVEs still score high?

Because business criticality, network exposure, control gaps, and threat vectors can raise priority.

### Why can an asset with many CVEs score lower than expected?

Because controls, lower criticality, or less exposed network position can reduce urgency.

---

## Query behavior

### Why does `tell me about Cleaver` work?

Because the workflow resolves real threat-group names from the graph and routes to the group exposure path.

### Why does `that one` work in follow-ups?

Because the workflow loads the prior investigation summary using the same thread ID.

### Are the answers hardcoded?

The instructional copy is partly static, but the main analysis results are graph-backed and stateful.

### Are the quick-query buttons hardcoded?

Yes, as examples.

But the underlying analysis they trigger is not hardcoded.

---

## UI

### Is the attack graph just decoration?

No.

It is built from live graph data and attack-path planning logic.

### What do the attack-path details show?

- route
- path risk
- top CVEs
- top threat groups

### Is the attack-path planner perfect?

No.

It is a hackathon exploit-sequence planner, not a production exploit simulation engine.

### Does Asset Intel use the same data as the Analyst?

Yes.

Both are driven by evidence bundles.

---

## Setup and deployment

### Do I need a separate SurrealDB server?

No.

For local demo use, file-backed embedded SurrealDB is enough.

### Can I deploy this to the cloud?

Yes.

See `deployment.md`.

### What is the fastest hackathon deployment?

A single container or VM running:

- the app
- a persistent SurrealDB data directory

### What is the cleaner longer-term deployment?

Separate app and database services with proper secrets, persistence, and observability.

---

## Limitations

### Is the environment discovered from real infrastructure?

No, it is seeded.

### Is the Code tab the main story?

No.

The strongest story is the threat/asset graph plus stateful agent workflow.

### Is every piece of UI text dynamic?

No.

Some onboarding/tutorial text is intentionally static.

### What should I emphasize if judges ask about limitations?

Emphasize that the structured memory, graph joins, persistent thread state, and workflow orchestration are real and are the core judging criteria.
