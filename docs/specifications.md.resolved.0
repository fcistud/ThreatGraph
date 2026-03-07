# ThreatGraph — Specifications

---

## 1. Functional Requirements

### P0 — Must Have (Hackathon Demo)

| ID | Requirement | Description |
|---|---|---|
| FR-01 | **ATT&CK KG Ingestion** | Ingest MITRE ATT&CK Enterprise STIX 2.1 JSON into SurrealDB as a knowledge graph. All techniques, tactics, groups, software, and mitigations as nodes with proper `RELATE` edges |
| FR-02 | **Asset Inventory Input** | Accept manual asset inventory (hostname, OS, software name + version, network zone, criticality level). Store as nodes in SurrealDB with `runs` edges to software nodes |
| FR-03 | **CVE Correlation** | Query NVD API for CVEs affecting software versions in asset inventory. Create CVE nodes with `affects` edges to assets and `has_cve` edges to ATT&CK software |
| FR-04 | **Attack Path Discovery** | Traverse the KG to find complete attack chains: `threat_group→technique→software→CVE→asset`. Return paths with all intermediate nodes |
| FR-05 | **Natural Language Queries** | Accept security questions in natural language. Agent classifies query type, generates SurrealQL, executes, and synthesizes results |
| FR-06 | **Exposure Assessment** | For any asset or group of assets, compute an exposure score based on: number of mapped CVEs × CVSS severity × number of threat groups using related techniques |
| FR-07 | **LangSmith Tracing** | All agent actions fully traced in LangSmith: query classification, plan generation, SurrealQL execution, synthesis steps |

### P1 — Should Have (Strong Demo)

| ID | Requirement | Description |
|---|---|---|
| FR-08 | **Remediation Generation** | For each identified attack path, generate remediation recommendations: specific patches, detection rules (Sigma/Yara format), and MITRE mitigation references |
| FR-09 | **Vector Search on Techniques** | Embed technique descriptions for semantic search. Enable: "Find techniques similar to 'credential harvesting'" even with non-exact terminology |
| FR-10 | **Investigation Sessions** | Support persistent investigation sessions via SurrealDB checkpointing. Resume an ongoing investigation across multiple interactions |
| FR-11 | **Threat Group Profiling** | For any threat group, generate a complete profile: TTPs used, software employed, sectors targeted, known campaigns, and overlap with the organization's attack surface |
| FR-12 | **CISA KEV Integration** | Ingest CISA Known Exploited Vulnerabilities catalog. Flag CVEs that are confirmed actively exploited |

### P2 — Nice to Have (Impressive Demo)

| ID | Requirement | Description |
|---|---|---|
| FR-13 | **Codebase Awareness** | GitNexus-inspired: parse a sample codebase for dependencies → link dependencies to software nodes in KG → create `imports` / `depends_on` edges. Enable: "This CVE affects library X used in file Y" |
| FR-14 | **Temporal Queries** | Track exposure over time. "How has our exposure to APT29 changed this month?" using SurrealDB's time-series capabilities |
| FR-15 | **Coverage Gap Analysis** | Compare the organization's detection capabilities against ATT&CK techniques. Identify technique gaps: "You have no detection for T1059.001 (PowerShell)" |
| FR-16 | **Risk Dashboard** | Streamlit-based dashboard showing: top risks, attack paths, exposure trends, coverage gaps |

### P3 — Stretch Goals

| ID | Requirement | Description |
|---|---|---|
| FR-17 | **Multi-Org Benchmarking** | Anonymized comparison: "Organizations in your sector typically have 65% ATT&CK coverage. You have 42%" |
| FR-18 | **Automated Asset Discovery** | Integrate with cloud APIs (AWS/Azure/GCP) to auto-discover assets and software versions |
| FR-19 | **Playbook Export** | Export detection rules and remediation plans as structured YAML/JSON for integration with SIEM tools |

---

## 2. Non-Functional Requirements

| ID | Requirement | Target |
|---|---|---|
| NFR-01 | **Privacy** | No customer asset data leaves the system. All processing is local. LLM calls contain only technique descriptions, not asset details |
| NFR-02 | **Graph Size** | Handle ~50K nodes and ~200K edges (full ATT&CK + 500 assets + 5K CVEs) with <2s query response |
| NFR-03 | **Agent Response Time** | Complex multi-hop queries return synthesized answers in <15 seconds |
| NFR-04 | **Deployment** | Deployable via `docker compose up` (SurrealDB + Python app) |
| NFR-05 | **LLM Flexibility** | Support OpenAI GPT-4o, Claude Sonnet, or local models via LangChain's model abstraction |
| NFR-06 | **Accuracy** | CVE→software matching via CPE must have >95% precision (validated against NVD ground truth) |
| NFR-07 | **False Positive Control** | Multi-stage verification: agent challenges its own attack path findings before reporting |
| NFR-08 | **Auditability** | Every agent decision recorded in LangSmith trace with reasoning visible |
| NFR-09 | **Extensibility** | New data sources (Shodan, VirusTotal, etc.) can be added as LangGraph tool nodes |
| NFR-10 | **Open Source** | Core toolkit published under MIT license |

---

## 3. Data Source Specifications

| Source | API Endpoint | Auth | Rate Limit | Data Volume | Update Frequency |
|---|---|---|---|---|---|
| MITRE ATT&CK | `github.com/mitre-attack/attack-stix-data` | None | N/A (static file) | ~5MB JSON | Quarterly (v18.1 Nov 2025) |
| NVD CVE | `services.nvd.nist.gov/rest/json/cves/2.0` | API key (free) | 50 req/30s with key | 250K+ CVEs | Real-time |
| CISA KEV | `cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` | None | N/A (static file) | ~1K CVEs | Weekly |

---

## 4. Agent Tool Specifications

| Tool Name | Input | Output | SurrealDB? | LLM? |
|---|---|---|---|---|
| `surreal_query` | SurrealQL string | Query results (JSON) | ✅ Read | ❌ |
| `surreal_write` | Node/edge data | Created record | ✅ Write | ❌ |
| `vector_search` | Text query + top_k | Similar techniques | ✅ Vector | ❌ |
| `nvd_lookup` | CVE ID or CPE string | CVE details (CVSS, description) | ❌ External API | ❌ |
| `exposure_score` | Asset ID or group | Numeric score + breakdown | ✅ Read | ❌ |
| `synthesize` | KG results + question | Natural language answer | ❌ | ✅ |
| `generate_playbook` | Attack path data | Detection rules + mitigations | ❌ | ✅ |
| `classify_query` | User question | Query type enum | ❌ | ✅ |

---

## 5. Hackathon Compliance Matrix

| Judging Criterion | Weight | How ThreatGraph Satisfies |
|---|---|---|
| **Structured Memory / KG (SurrealDB)** | 30% | ATT&CK is literally a knowledge graph. Multi-table graph with `RELATE` edges. Vector index for semantic search. Hybrid retrieval. Evolving context as assets/CVEs are added |
| **Agent Workflow (LangGraph)** | 20% | Multi-step pipeline: classify → plan → query → search → synthesize → remediate. Conditional branching based on query type. Tool coordination |
| **Persistent Agent State** | 20% | Investigation sessions persist in SurrealDB. KG state evolves (new CVEs, new assets). Checkpointing via SurrealDB backend |
| **Practical Use Case** | 20% | Every company with a SOC needs this. Clear ROI: 2 hours → 3 seconds per CVE analysis |
| **Observability** | 10% | Full LangSmith tracing on every agent step |
| **Bonus: Open-Source** | + | `langchain-surrealdb-mitre-toolkit` — reusable LangChain integration |
