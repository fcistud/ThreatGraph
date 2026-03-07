# ThreatGraph Core Fixes

## Purpose

This document records what was wrong in the MVP, what was fixed, and why the fixes matter.

It also confirms that the requested architecture improvements are implemented in the current codebase.

---

## What Was Wrong

### 1. Database configuration was not trustworthy

- `src/database.py` hardcoded `http://localhost:8000`.
- `src/config.py` exposed `SURREALDB_URL`, but the runtime path ignored it.
- Result: local, container, and embedded/file-backed SurrealDB usage were inconsistent.

### 2. Schema initialization hid real failures

- Schema setup swallowed exceptions broadly.
- Real DDL failures were easy to miss.
- Result: the graph could appear to load while key fields or tables were missing.

### 3. Schemafull array fields were silently dropping data

- Generic `array` fields in SurrealDB schemafull tables were not persisting values as expected.
- This affected aliases, open ports, services, investigation history, and other list fields.
- Result: important context looked present in code but was missing in stored records.

### 4. The internal software layer was disconnected from ATT&CK software

- The schema defined `linked_to_software`, but nothing created those edges.
- Result: seeded assets had software versions and CVEs, but no credible ATT&CK software, technique, or group linkage.

### 5. ATT&CK relationship loading lost semantic meaning

- All STIX `uses` relationships were loaded into the same edge table.
- Threat-group-to-software relationships were not promoted into `employs`.
- Result: group exposure queries could not reliably traverse from group to software to internal asset.

### 6. Asset seeding was not deterministic

- The seeder relied on `CREATE ...` plus broad exception swallowing.
- Record IDs were implicit and reruns depended on “already exists” behavior.
- Result: reset/idempotency behavior was weak and later graph-link stages were brittle.

### 7. CVE correlation was shallow and unstable

- NVD lookups fetched only a small first page.
- No local cache.
- No reliable duplicate checks for `has_cve` and `affects`.
- Result: repeated runs could drift and graph coverage was incomplete.

### 8. Query helpers were not evidence-backed

- The original “attack paths” query was mostly nested projections over assets and CVEs.
- Group exposure mostly returned group metadata.
- Exposure scoring used partial projections instead of real graph evidence bundles.
- Result: answers looked plausible but were not grounded in inspectable evidence chains.

### 9. Investigation persistence was not real enough

- The checkpointer did not match the installed LangGraph saver contract.
- Investigation history was not reliably reloaded into follow-up queries.
- Result: `thread_id` continuity was weak and easy to overstate.

### 10. The richer enterprise architecture existed only partially in practice

- The seed data already modeled network zones, controls, connectivity, and non-software threats.
- But the core evidence and scoring paths did not surface enough of that context.
- Result: the demo graph was richer than the core query outputs.

---

## What Was Fixed

### Database and schema

- Added Surreal URL normalization in `src/config.py`.
- Reworked `get_db()` to use the env-driven URL correctly.
- Added strict schema execution with explicit failure reporting.
- Added checkpoint schema.
- Tightened schemafull list fields to typed arrays like `array<string>` and `array<int>`.

Why this matters:

- The same code now works against env-configured HTTP URLs and embedded/file-backed SurrealDB.
- Core metadata no longer disappears silently.

### Deterministic asset and topology seeding

- Added stable asset/software-version record ID builders.
- Added `seed_assets(reset=True)` with a reset path for the demo asset layer.
- Preserved and validated:
  - network segments
  - asset-to-asset connectivity
  - network-zone categorization
  - criticality and crown-jewel tagging
  - controls/mitigations
  - non-software threat vectors

Why this matters:

- The seeded environment is repeatable.
- The graph now contains a real network/threat-surface model, not just a flat asset list.

### ATT&CK software bridge

- Added `src/ingestion/software_linker.py`.
- Added deterministic software matching and real `linked_to_software` edge creation.
- Seeded a small set of ATT&CK-compatible demo software versions such as `PsExec`, `AdFind`, `ngrok`, and `Rclone`.

Why this matters:

- At least some internal assets now traverse cleanly into ATT&CK software, techniques, and threat groups.

### ATT&CK ingest semantics

- Updated ATT&CK relationship loading so threat-group-to-software becomes `employs`.
- Added software alias ingestion support.

Why this matters:

- Group exposure and ATT&CK software traversals now reflect the intended graph model.

### CVE correlation

- Added paginated NVD retrieval.
- Added local cache support.
- Added duplicate-safe `has_cve` and `affects` edge creation.
- Returned structured correlation stats.

Why this matters:

- CVE linking is stable enough to rerun and inspect.

### Evidence-backed query layer

- Rebuilt asset evidence bundles from real graph relationships.
- `get_asset_evidence_bundle()` now includes:
  - software versions
  - ATT&CK software
  - CVEs
  - techniques
  - threat groups
  - network segments
  - connected assets
  - in-place controls
  - non-software threat vectors
  - explicit evidence paths
- `get_exposure_for_group()` now returns real internal assets with group-specific evidence.
- `compute_exposure_score()` now ranks from evidence bundles instead of shallow projections.

Why this matters:

- The main answers are inspectable and tied to graph facts.

### Risk scoring improvements

- Exposure scoring now incorporates:
  - CVSS accumulation
  - KEV bonus
  - ATT&CK software relevance
  - network-zone weighting
  - criticality weighting
  - criticality score multiplier
  - crown-jewel bonus
  - control-based reduction
  - non-software threat-vector bonus

Why this matters:

- The score reflects business impact and attack surface, not just CVE counts.

### Workflow persistence

- Reworked the workflow result contract to return structured data.
- Updated the Surreal checkpointer to match the installed LangGraph saver contract.
- Added persisted investigation summaries and reload of latest thread context.

Why this matters:

- Follow-up questions can reuse the prior focus asset/group through `thread_id`.

### Ingest order

- The ingest pipeline now runs in the correct order:
  1. schema
  2. ATT&CK
  3. seeded assets
  4. software linking
  5. CVE correlation

Why this matters:

- CVE and group evidence now sit on top of a complete graph instead of a partially linked one.

### Focused core tests

- Added `tests/test_core_graph_flow.py`.
- Verified:
  - seeded software versions link to ATT&CK software
  - attack paths include ATT&CK context
  - group exposure returns internal assets
  - exposure scoring returns ranked assets
  - `run_query(..., thread_id=...)` persists and reloads context

Why this matters:

- The core claims are now enforced by repeatable tests instead of manual demos alone.

---

## Requested Architecture Improvements: Implementation Status

### Full network / threat-surface architecture

Implemented.

- Assets are connected with `connects_to`.
- Assets reside in network segments via `resides_in`.
- Segments route via `routes_to`.
- Evidence bundles now surface connected assets and network segments.

### Exposure categories: public-facing / internal / air-gapped

Implemented.

- Assets carry `network_zone`.
- Seed data includes `dmz`, `internal`, `corporate`, and `airgap`.
- Scoring uses network-zone weighting.

### Criticality and crown jewels

Implemented.

- Assets carry `criticality`, `criticality_score`, and `is_crown_jewel`.
- Scoring now includes criticality weighting, criticality-score multiplier, and crown-jewel bonus.

### In-place mitigations / controls

Implemented.

- Controls are modeled as `security_control`.
- Controls protect assets and guard segments.
- Threat vectors can be blocked by controls.
- Evidence bundles now surface applicable controls.
- Scoring now reduces risk based on control effectiveness.

### Additional threat vectors beyond software CVEs

Implemented.

- Threat vectors include phishing, brute force, man-in-the-middle, social engineering, supply chain, and port scanning.
- Threat vectors expose assets directly.
- Evidence bundles now surface threat vectors.
- Scoring now includes a threat-vector component.

### Rich knowledge graph and attack-path context from periphery to crown jewel

Implemented at the graph/model level and surfaced in the core evidence layer.

- The graph now contains:
  - network topology
  - asset criticality
  - controls
  - threat vectors
  - ATT&CK software
  - techniques
  - threat groups
  - CVEs
- The core query layer returns evidence bundles and group exposure paths over that graph.

---

## Current Outcome

The MVP is no longer just “assets + CVEs + prose.”

The current system now has:

- env-correct SurrealDB connectivity
- stable demo seeding
- real ATT&CK software linking
- stable CVE edge creation
- evidence-backed asset and group exposure output
- persistent investigation continuity
- a richer enterprise network/threat-surface model carried into the evidence layer

---

## Validation

The focused core test suite passes repeatedly:

- `pytest tests/test_core_graph_flow.py -q`

Observed result during validation:

- `5 passed` on two consecutive runs

