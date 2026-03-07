# ThreatGraph — Implementation Plan

---

## Pre-Hackathon Preparation (Before Friday 6 PM)

> [!IMPORTANT]
> Do these BEFORE the hackathon starts. This saves 2-3 hours during build time.

| Task | Time | Status |
|---|---|---|
| Register for MITRE ATT&CK STIX data: download `enterprise-attack.json` from `mitre-attack/attack-stix-data` | 5 min | ☐ |
| Get NVD API key (free, instant): `nvd.nist.gov/developers/request-an-api-key` | 2 min | ☐ |
| Download CISA KEV JSON: `cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` | 1 min | ☐ |
| Get OpenAI API key (GPT-4o) or Anthropic API key (Claude Sonnet) | 2 min | ☐ |
| Get LangSmith API key: `smith.langchain.com` | 2 min | ☐ |
| Install SurrealDB locally: `curl -sSf https://install.surrealdb.com \| sh` | 2 min | ☐ |
| Install Surrealist (GUI): `surrealist.app` for visual KG exploration | 2 min | ☐ |
| Set up Python environment: `pip install langchain langgraph langchain-openai langchain-surrealdb surrealdb streamlit` | 5 min | ☐ |
| Read through STIX 2.1 JSON structure (understand `objects`, `type`, `external_references`, `relationship`) | 15 min | ☐ |
| Prepare 5 sample assets with realistic software versions (Apache, Nginx, PostgreSQL, OpenSSH, etc.) | 10 min | ☐ |
| Write and test the STIX JSON parser script (tested locally before hackathon) | 45 min | ☐ |
| Create GitHub repo with README skeleton, `docker-compose.yml`, `.env.example` | 15 min | ☐ |

---

## Phase 1: KG Foundation (Friday 6 PM - 10 PM) — 4 hours

> **Goal**: ATT&CK KG loaded in SurrealDB, verified, and queryable.

### Hour 1 (6-7 PM): Environment + SurrealDB Setup
| Task | Time |
|---|---|
| Start SurrealDB via Docker | 5 min |
| Create namespace/database/schema (run DDL from architecture doc) | 15 min |
| Test connection from Python | 10 min |
| Set up LangSmith tracing | 10 min |
| Set up project structure: `src/`, `data/`, `tools/`, `agents/` | 10 min |

### Hour 2-3 (7-9 PM): MITRE ATT&CK Ingestion
| Task | Time |
|---|---|
| Run pre-written STIX parser → load all techniques (~794 nodes) | 15 min |
| Load all threat groups (~143 nodes) | 10 min |
| Load all software items (~680 nodes) | 10 min |
| Load all mitigations (~43 nodes) | 5 min |
| Load all tactics (~14 nodes) | 5 min |
| Create all `RELATE` edges from STIX relationships | 30 min |
| Debug any parsing issues | 15 min |
| **CHECKPOINT**: Verify in Surrealist — visualize APT29's technique graph | 15 min |
| Generate embeddings for technique descriptions (batch → OpenAI) | 15 min |

### Hour 4 (9-10 PM): Asset Overlay + CVE Correlation
| Task | Time |
|---|---|
| Create 5 sample assets with software versions | 10 min |
| Write CPE matching logic | 15 min |
| Query NVD for CVEs affecting those software versions | 15 min |
| Create CVE nodes + `has_cve` and `affects` edges | 15 min |
| **CHECKPOINT**: Run test query — "Show me all CVEs affecting web-server-01" | 5 min |

**End of Friday**: Full KG loaded with 1,700+ nodes and 5,000+ edges. Verified in Surrealist.

---

## Phase 2: Agent Core (Saturday 10 AM - 2 PM) — 4 hours

> **Goal**: Working LangGraph agent that answers natural-language security questions.

### Hour 5 (10-11 AM): LangGraph Skeleton
| Task | Time |
|---|---|
| Create `ThreatGraphState` TypedDict | 10 min |
| Build 7-node workflow skeleton (empty nodes) | 15 min |
| Wire edges + conditional routing | 15 min |
| Test compilation + empty state flow | 10 min |

### Hour 6 (11 AM-12 PM): Classification + Planning Nodes
| Task | Time |
|---|---|
| Implement `classify_query` with structured LLM output | 25 min |
| Implement `plan_investigation` with SurrealQL generation | 25 min |
| Test: "Am I vulnerable to APT29?" → verify correct classification + plan | 10 min |

### Hour 7 (12 PM-1 PM): Execution Nodes
| Task | Time |
|---|---|
| Implement `execute_kg_queries` tool (SurrealQL executor) | 20 min |
| Implement `execute_vector_search` tool (semantic technique matching) | 20 min |
| Implement `lookup_cves` tool (NVD API + KG cross-reference) | 20 min |

### Hour 8 (1-2 PM): Synthesis + Lunch
| Task | Time |
|---|---|
| Implement `synthesize_results` node | 20 min |
| **CHECKPOINT**: End-to-end test — "Am I vulnerable to APT29?" → full answer | 15 min |
| Lunch + fix bugs | 25 min |

**End of Phase 2**: Agent answers natural-language security questions via graph traversal. Full LangSmith traces visible.

---

## Phase 3: Attack Paths + Remediation (Saturday 2 PM - 6 PM) — 4 hours

> **Goal**: Attack path discovery + remediation playbook generation.

### Hour 9-10 (2-4 PM): Attack Path Engine
| Task | Time |
|---|---|
| Implement `discover_attack_paths` — multi-hop traversal query | 60 min |
| Test with different query types (exposure, CVE alert, threat hunt) | 30 min |
| Add exposure scoring calculation | 30 min |

### Hour 11-12 (4-6 PM): Playbook + Checkpointing
| Task | Time |
|---|---|
| Implement `generate_playbook` node — Sigma rules + mitigations | 45 min |
| Implement SurrealDB checkpointing backend | 30 min |
| Test investigation session persistence (stop → resume) | 15 min |
| **CHECKPOINT**: Full pipeline working. Record LangSmith trace for demo | 15 min |

**End of Phase 3**: Complete agent pipeline end-to-end with attack paths and remediation. Persistent sessions.

---

## Phase 4: UI + Polish (Saturday 6 PM - 10 PM) — 4 hours

> **Goal**: Demo-ready interface, README, video recording prep.

### Hour 13-14 (6-8 PM): Streamlit Dashboard
| Task | Time |
|---|---|
| Build main query interface (text input → streaming response) | 30 min |
| Add KG stats sidebar (node/edge counts, top threat groups) | 20 min |
| Add attack path visualization (networkx → pyvis or D3.js) | 40 min |
| Add exposure score heatmap | 30 min |

### Hour 15-16 (8-10 PM): Polish + README + Video
| Task | Time |
|---|---|
| Write comprehensive README (what/why/how/demo/install) | 30 min |
| Clean up code, add docstrings | 15 min |
| Prepare 3 demo scenarios with scripted queries | 15 min |
| Record 2-minute project video (screen recording + voiceover) | 30 min |
| Push to GitHub, verify it runs from clean clone | 15 min |
| Buffer for bugs | 15 min |

---

## Phase 5: Demo Day (Sunday 10 AM - 2 PM)

### Hour 17-18 (10 AM-12 PM): Final Push + Submission
| Task | Time |
|---|---|
| Stretch goal: add codebase awareness layer (if time) | 60 min |
| Final bug fixes | 30 min |
| Submit GitHub link + video | 10 min |
| Prepare live demo flow (3 scenarios, 3 min each) | 20 min |

### 12:45-2 PM: Video Showcase + Live Demo
Practice the 3-minute live demo:
1. **Scenario A** (60 sec): "A new CVE just dropped" — live blast radius analysis
2. **Scenario B** (60 sec): "Am I vulnerable to APT29?" — full exposure assessment
3. **Scenario C** (60 sec): "Show me my weakest point" — priority risk ranking

---

## Risk Mitigation

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| STIX parser bugs | Medium | High | Pre-write and test parser before hackathon |
| NVD API rate limiting | Low | Medium | Cache CVE responses; pre-fetch for demo assets |
| SurrealDB graph query performance | Low | Medium | Keep KG under 50K nodes; index key fields |
| LLM generates incorrect SurrealQL | Medium | Medium | Validate generated queries before execution; provide schema in prompt |
| LangSmith down | Low | Low | Add backup logging to file |
| UI too slow | Low | Medium | Skip UI → use CLI for demo (still impressive) |

---

## Minimum Viable Demo (If Everything Goes Wrong)

Even with only Phase 1 + Phase 2, you have:
1. ✅ ATT&CK KG in SurrealDB (satisfies 30% KG criterion)
2. ✅ LangGraph agent answering questions (satisfies 20% agent criterion)
3. ✅ Persistent KG state (satisfies 20% persistence criterion)
4. ✅ Clear cybersecurity use case (satisfies 20% practical criterion)
5. ✅ LangSmith traces (satisfies 10% observability)
= **90/100 possible with just Phases 1-2**

---

## Post-Hackathon Roadmap

| Timeline | Milestone |
|---|---|
| Week 1 post-hack | Publish `langchain-surrealdb-mitre-toolkit` as standalone package on PyPI |
| Month 1 | Add automated asset discovery (AWS/Azure/GCP APIs) |
| Month 2 | Apply to Osney Capital / NCSC Cyber Accelerator |
| Month 3 | SOC integration: Splunk/Elastic SIEM connectors |
| Month 6 | Multi-tenant SaaS MVP with first enterprise pilot |
| Month 12 | Seed round target: £750K-1.5M |
