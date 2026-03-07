# ThreatGraph Explainer

This file explains the app from beginner level to advanced level.

It is intentionally detailed.

The goal is that someone can read this and understand:

- what the app does
- how the data model works
- how LangGraph is used
- how SurrealDB is used
- what each tab does
- what the graph nodes mean
- what `Investigation State` means
- what the thread ID means
- what `LangSmith tracing: disabled` means
- how traversal works
- how scoring works
- what parts are core to the hackathon

---

## Part 1: Beginner Explanation

### What problem is ThreatGraph solving?

Most security demos stop at one of these:

- a list of assets
- a list of CVEs
- a list of threat groups
- a chatbot that sounds smart

ThreatGraph tries to connect those pieces into one system.

Instead of only asking:

- what vulnerabilities do I have?

it asks:

- what software is on my assets?
- what CVEs affect that software?
- which assets matter most to the business?
- what controls protect them?
- what threat vectors still expose them?
- which ATT&CK software, techniques, and threat groups are relevant?
- what sequence could an attacker follow from the outside to a crown jewel?

That is the core idea.

### The one-sentence summary

ThreatGraph is a SurrealDB-backed cybersecurity knowledge graph with a LangGraph agent on top.

### The five-sentence summary

1. The app loads MITRE ATT&CK into SurrealDB as a threat graph.
2. It seeds an internal enterprise environment with assets, zones, controls, threat vectors, and software.
3. It links internal software versions to ATT&CK software and correlates CVEs from NVD.
4. It uses LangGraph to turn a question into a structured investigation over that graph.
5. It stores investigation state so follow-up questions can continue the same thread.

### What the app is not

It is not:

- a full production vulnerability management platform
- a full SIEM
- a live EDR
- a complete exploit simulator

It is a hackathon prototype focused on structured memory, graph reasoning, persistent state, and explainable evidence.

---

## Part 2: The Main Technologies

### SurrealDB

SurrealDB is the persistent data layer.

It stores:

- graph data
- relational-like records
- investigation state
- checkpoint data

Why SurrealDB matters here:

- ATT&CK is naturally graph-shaped
- enterprise assets are naturally structured records
- investigation history needs persistence
- the hackathon specifically rewards structured memory in SurrealDB

In this app, SurrealDB is not a sidecar.
It is the system of record.

### LangGraph

LangGraph is the workflow engine.

It gives the app:

- explicit workflow nodes
- stateful execution
- conditional routing
- checkpoint integration

This matters for the hackathon because the app is not doing one direct function call.
It is running a multi-step workflow with persisted context.

### LangChain

LangChain is used more lightly than LangGraph, but still legitimately:

- model wrappers for Anthropic/OpenAI
- compatibility with the LangGraph ecosystem
- optional tracing integration patterns

### LangSmith

LangSmith is the observability layer.

When enabled, it can show:

- which workflow path ran
- what tool/query steps happened
- how long things took
- what state moved between steps

If disabled, the app still works.

### Streamlit

Streamlit is the UI layer.

It renders:

- the analyst
- the exposure dashboard
- the attack graph
- the asset intel views
- the ATT&CK matrix
- the gaps view

### NetworkX + pyvis

These are used for the attack graph visualization.

- NetworkX builds the graph in memory
- pyvis renders it as interactive HTML

---

## Part 3: The Data Model

This is the most important part of the app.

If you understand the data model, you understand most of the system.

### Core node types

#### `asset`

Represents a machine or system in the enterprise environment.

Important fields:

- `hostname`
- `os`
- `ip_address`
- `network_zone`
- `criticality`
- `criticality_score`
- `business_function`
- `is_crown_jewel`
- `open_ports`
- `services`
- `owner`

Examples:

- `web-server-01`
- `db-server-01`
- `ad-server-01`
- `finance-db`

#### `software_version`

Represents a specific installed product/version on an asset.

Important fields:

- `name`
- `version`
- `cpe`

Examples:

- Apache HTTP Server 2.4.49
- OpenLDAP 2.5.14
- OpenSSL 1.1.1k
- PsExec 2.43

#### `cve`

Represents a vulnerability from NVD.

Important fields:

- `cve_id`
- `cvss_score`
- `cvss_vector`
- `description`
- `published`
- `affected_cpe`
- `is_kev`
- `exploit_available`

#### `software`

Represents ATT&CK software.

Important fields:

- `external_id`
- `name`
- `aliases`
- `sw_type`
- `platforms`

This is not the same as `software_version`.

That distinction matters:

- `software_version` = your installed thing
- `software` = ATT&CK software concept

#### `technique`

Represents an ATT&CK technique.

Important fields:

- `external_id`
- `name`
- `description`
- `platforms`
- `detection`

#### `threat_group`

Represents an ATT&CK threat group.

Important fields:

- `external_id`
- `name`
- `aliases`
- `description`

#### `network_segment`

Represents a network zone or segment.

Examples:

- internet
- dmz
- internal
- corporate
- airgap

#### `security_control`

Represents a protective control.

Examples:

- WAF
- firewall
- MFA
- EDR
- segmentation

#### `threat_vector`

Represents non-software attack pressure.

Examples:

- phishing
- brute force
- man-in-the-middle
- social engineering
- supply chain
- port scanning

#### `investigation`

Represents saved investigation history.

This is one of the hackathon-important state tables.

#### `checkpoint`

Represents persisted LangGraph checkpoint state.

This is the other hackathon-important state table.

---

## Part 4: The Important Edges

Edges are the reason this app is a graph app instead of only a table app.

### Asset-side edges

#### `asset -> runs -> software_version`

This means an asset runs a given software version.

Example:

- `web-server-01 -> runs -> Apache HTTP Server 2.4.49`

#### `software_version -> has_cve -> cve`

This means that installed software version is affected by the CVE.

#### `cve -> affects -> asset`

This means that a CVE has blast radius to the asset through installed software.

#### `asset -> resides_in -> network_segment`

This places the asset in a network zone.

#### `asset -> connects_to -> asset`

This models lateral movement and network adjacency.

#### `security_control -> protects -> asset`

This models direct protection on an asset.

#### `security_control -> guards -> network_segment`

This models controls that defend an entire segment.

#### `threat_vector -> exposes -> asset`

This models external or non-software exposure pressure.

#### `threat_vector -> blocked_by -> security_control`

This models which controls help reduce that vector.

### ATT&CK-side edges

#### `threat_group -> employs -> software`

This means an ATT&CK group uses ATT&CK software.

#### `threat_group -> uses -> technique`

This means a group uses an ATT&CK technique.

#### `technique -> belongs_to -> tactic`

This maps techniques to ATT&CK tactics.

#### `mitigation -> mitigates -> technique`

This maps ATT&CK mitigations to techniques.

### Bridge edge

#### `software_version -> linked_to_software -> software`

This is the most important bridge.

Without it, your internal environment and the ATT&CK graph are disconnected.

This edge is what makes it possible to say:

- this internal software version is relevant to ATT&CK software
- which is relevant to techniques
- which is relevant to threat groups

---

## Part 5: What Each Graph Node Represents in the UI

This refers specifically to the attack graph tab.

### Asset node

- shape: box
- meaning: internal machine/system
- color: based on criticality
- crown jewel: gold styling / crown marker
- zone context: internet-facing, internal, or air-gapped indicator

### Internal software node

- shape: diamond
- meaning: installed `software_version`
- examples: OpenSSL 1.1.1k, OpenLDAP 2.5.14

### CVE node

- shape: triangle
- meaning: vulnerability affecting a software version

### Security control node

- shape: hexagon
- meaning: a defensive control

### Threat vector node

- shape: star
- meaning: a non-software attack vector like phishing or brute force

### ATT&CK software node

- shape: diamond
- meaning: ATT&CK software relevant to the internal environment

### ATT&CK technique node

- shape: dot
- meaning: ATT&CK technique linked through software/group relationships

### Threat group node

- shape: star
- meaning: ATT&CK threat group relevant to the environment

### Compromised asset step

Important:

The exploit-path planner introduces compromised-asset states internally.

Those are planning states, not base stored graph nodes.

They show up in path details so that the path can say:

- reach asset
- exploit software/CVE
- now the asset is compromised
- pivot onward

That is a planner concept layered on top of the stored graph.

---

## Part 6: How Data Gets Into the System

The ingest pipeline is very important.

The order matters.

### Step 1: Schema initialization

File:

- `src/database.py`

This creates the SurrealDB tables and fields.

Why this matters:

- if the schema is wrong, arrays and checkpoint fields can silently fail
- the app used to have exactly that problem

### Step 2: ATT&CK ingestion

File:

- `src/ingestion/attack_loader.py`

This loads:

- threat groups
- techniques
- software
- mitigations
- tactics
- relationships

Important improvement:

- threat-group-to-software relationships are now stored as `employs`

### Step 3: Asset/environment seeding

File:

- `src/ingestion/asset_seeder.py`

This loads the demo enterprise:

- 15 assets
- 5 network segments
- controls
- threat vectors
- connectivity
- software versions

Important improvement:

- stable IDs
- resettable seed
- deterministic reruns

### Step 4: Software linking

File:

- `src/ingestion/software_linker.py`

This creates:

- `software_version -> linked_to_software -> software`

That bridge is built through deterministic matching and curated demo mappings.

### Step 5: CVE correlation

File:

- `src/ingestion/cve_correlator.py`

This:

- queries NVD
- pages through results
- caches results locally
- creates CVE nodes
- creates `has_cve`
- creates `affects`
- marks KEV CVEs

### Why the ingest order matters

The correct order is:

1. schema
2. ATT&CK
3. assets
4. software linking
5. CVE correlation

If you do CVE correlation before the graph bridge and seeded asset layer are stable, the result is weaker and harder to explain.

---

## Part 7: How Querying Works

This app does not answer by hallucinating from prompts alone.

It first builds real graph evidence.

### The core evidence bundle

File:

- `src/tools/surreal_tools.py`

The most important function is:

- `get_asset_evidence_bundle(db, hostname)`

It assembles, step by step:

1. the asset record
2. software versions on that asset
3. ATT&CK software linked from those software versions
4. CVEs on those software versions
5. techniques associated to that ATT&CK software
6. threat groups associated to that ATT&CK software or technique
7. controls and threat vectors relevant to the asset
8. explicit evidence paths joining them

This is the object that powers:

- asset intel
- exposure scoring
- group exposure
- analyst output
- attack graph threat layer

### Group exposure

The key function is:

- `get_exposure_for_group(db, group_name)`

This:

1. resolves the group
2. gets ATT&CK software employed by the group
3. finds internal software versions linked to that ATT&CK software
4. finds assets running those software versions
5. builds evidence bundles for those assets
6. scores them

That is why `tell me about Cleaver` can return real internal assets instead of only group metadata.

### Search

There is also a general KG search path:

- keyword-oriented
- across techniques, groups, software, CVEs, mitigations

That is the fallback when the question is not one of the stronger structured cases.

---

## Part 8: How Traversal Works

Traversal happens in multiple places.

### SurrealDB traversal

SurrealDB supports graph traversal directly in queries.

Examples:

- asset to software
- software to CVEs
- group to software
- group to techniques

But the app does not try to do everything in one giant query.

Instead it usually:

1. runs smaller Surreal queries
2. normalizes them
3. joins them in Python into evidence bundles

That was a deliberate choice for reliability.

### Attack-path traversal

The attack graph planner is now more than a plain network shortest path.

It builds an exploit-state planner with:

- entry from `internet` or a `threat_vector`
- move to an exposed asset
- move to software on that asset
- move to CVE on that software
- transition to a compromised-asset state
- laterally move to a connected asset
- repeat until a crown jewel is compromised

This is still a hackathon planner, not a formal exploit engine, but it is far more meaningful than a plain path over topology.

---

## Part 9: How the LangGraph Workflow Works

File:

- `src/agents/workflow.py`

### The workflow state

The state carries things like:

- query text
- thread ID
- query type
- ranked assets
- evidence bundle
- matched asset
- matched group
- investigation context
- synthesis
- playbook

### Main nodes

#### `classify`

Looks at the question and decides if it is:

- exposure check
- threat hunt
- CVE alert
- coverage gap
- general

#### `kg_query`

Runs the structured graph logic for:

- exposure questions
- threat-group questions
- general search
- coverage gap analysis

#### `cve_lookup`

Handles direct CVE questions.

#### `synthesize`

Turns evidence into a readable answer.

If an LLM key is configured, it uses the model.
If not, it falls back to deterministic text assembly.

#### `playbook`

Builds remediation guidance.

Again:

- model-backed if available
- fallback if not

### Why this matters for the hackathon

This is not a single “search then print” step.

It is a multi-step stateful workflow with routing and persistence.

That is exactly the kind of LangGraph usage the hackathon wants.

---

## Part 10: Investigation State, Thread ID, and Persistence

This is one of the most important things judges can ask about.

### What is the thread ID?

In the sidebar you will see something like:

- `Investigation State`
- `Thread ID`
- `e8551bce-0d9f-4c18-86e6-bfe237335ec7`

That value is a UUID.

It is not decorative.

It is the key that identifies one investigation thread.

### What happens when a query uses that thread ID?

When you click Analyze:

1. the current `thread_id` is passed into `run_query(...)`
2. the Surreal checkpointer loads the latest saved investigation context for that thread
3. the workflow runs
4. the new result is summarized
5. the summary is stored back into SurrealDB under the same thread

That means a follow-up question can reuse prior focus.

Example:

1. ask: `Which asset is most exposed?`
2. the workflow stores the top asset
3. ask: `Now give me remediation steps for that one`
4. the workflow reloads the prior context and understands what `that one` means

### Where is that state stored?

Primarily in:

- `investigation`
- `checkpoint`
- `checkpoint_write`

### What is shown in the app?

The sidebar shows:

- current thread ID
- recent investigation history for that thread
- recent focus values from stored findings

That is the visible proof of persistent state.

---

## Part 11: What `LangSmith tracing: disabled` Means

In the sidebar you may see:

- `LangSmith tracing: disabled`

This means:

- the app checked the tracing configuration
- LangSmith credentials are not active in the current environment
- therefore traces are not being sent to LangSmith

The app still works when tracing is disabled.

### Why would it be disabled?

Usually because:

- `LANGSMITH_API_KEY` is not set
- or `LANGCHAIN_TRACING_V2` is not enabled

### How to enable tracing

Set environment variables before launching:

```bash
export LANGSMITH_API_KEY="your-key"
export LANGCHAIN_TRACING_V2="true"
export LANGCHAIN_PROJECT="threatgraph"
```

Then start the app and run a query.

### How to showcase tracing in a demo

The simplest flow is:

1. enable LangSmith env vars
2. open the app
3. ask one threat-group question
4. ask one follow-up question with the same thread ID
5. show the LangSmith project
6. show:
   - one run for the first question
   - one run for the follow-up
   - node execution order
   - evidence-related state

### Why tracing matters for the hackathon

Observability is explicitly in the judging criteria.

Tracing shows:

- the workflow is real
- the routing is real
- the state is real
- the system is debuggable

---

## Part 12: How the Score Works

The score is not arbitrary anymore.

### What the app considers

The exposure score combines:

- sum of CVSS scores
- KEV bonus
- ATT&CK software bonus
- threat-vector bonus
- crown-jewel bonus
- group-relevance bonus when applicable
- criticality weight
- criticality score multiplier
- network zone weight
- control multiplier

### In plain English

An asset scores higher when:

- it has more severe CVEs
- some of those CVEs are actively exploited
- it is important to the business
- it sits in a more exposed zone
- it has fewer effective controls
- it is a crown jewel
- it is exposed to more relevant threat vectors

### Why some assets score high even with few CVEs

Because the score is not just CVE count.

Example:

- crown jewel
- weak controls
- strong threat-vector exposure
- high business criticality

can still matter a lot.

### Why this matters for judging

It shows that structured context from SurrealDB is changing the behavior of the agent.

That is stronger than just “sort by CVSS.”

---

## Part 13: What Each App Tab Does

### Sidebar

Shows:

- graph counts
- thread ID
- recent investigation history
- tracing status
- quick queries

### Analyst

The main question-answering workflow.

It shows:

- threat assessment
- workflow state
- evidence bundle summary
- ranked assets
- CVE evidence
- evidence paths
- remediation playbook

### Exposure

Shows organization-wide asset ranking by exposure score.

### Attack Graph

Shows the interactive graph and structured attack-path details.

### Asset Intel

Shows one selected asset in detail.

### ATT&CK Matrix

Shows tactic and group/software summaries from the ATT&CK graph.

### Gaps

Shows unmitigated ATT&CK techniques.

### Code

This is a stretch feature path and not the main judging focus.

### Guide

Explains how to use the app.

---

## Part 14: The Main Hackathon Story

If a judge asks:

“Where are LangGraph and SurrealDB actually being used?”

the short answer is:

- SurrealDB stores the structured evolving graph and investigation state
- LangGraph orchestrates the agent workflow across that stored context

If a judge asks:

“What is the persistent memory?”

the short answer is:

- the graph itself
- the investigation table
- the checkpoint tables
- the reused thread ID

If a judge asks:

“How is this more than a chatbot?”

the short answer is:

- the answer comes from graph evidence bundles and persisted state
- the system can continue an investigation thread
- the attack graph and risk model are derived from structured data

---

## Part 15: Honest Limitations

The strongest way to talk about the app is honestly.

Current limitations:

- the environment is seeded, not discovered live from a customer network
- the attack-path planner is still a hackathon planner, not a production exploit engine
- some UI copy is instructional/static
- some tabs are stronger than others
- the Code tab is less central than the threat graph and agent flows

Those limitations are okay as long as the core story is clear:

- SurrealDB-backed structured memory
- LangGraph-backed stateful orchestration
- evidence-backed cyber reasoning

---

## Part 16: Questions You Should Be Ready For

### “Why SurrealDB instead of a normal SQL database?”

Because this problem is both record-shaped and graph-shaped.

### “Why LangGraph instead of just a function?”

Because the system has routing, state, follow-up continuity, and checkpointing.

### “What exactly is persisted?”

Investigation summaries, checkpoint rows, and the underlying graph itself.

### “What happens when tracing is off?”

The app still works, but LangSmith does not receive traces.

### “How do you prove the app is not hardcoded?”

Show:

- the thread ID changing
- the investigation history table
- a named threat-group query like `Cleaver`
- the evidence bundle table
- the attack-path detail list with real CVEs/groups
- the focused tests

---

## Final takeaway

ThreatGraph matters because it does not treat cybersecurity knowledge as flat text.

It treats it as structured, persistent, traversable state.

That is exactly why SurrealDB matters here.

And it does not treat the agent as one prompt call.

It treats it as a multi-step, stateful workflow.

That is exactly why LangGraph matters here.
