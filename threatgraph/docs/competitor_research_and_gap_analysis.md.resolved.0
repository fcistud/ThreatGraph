# ThreatGraph — Competitor Research & Gap Analysis

---

## 1. Competitive Landscape Overview

The cybersecurity AI space is vast but fragmented. No single tool combines **threat intelligence knowledge graphs + asset vulnerability correlation + agentic remediation + codebase-aware security analysis**. This section maps every relevant competitor across 5 categories.

---

## 2. Enterprise Threat Intelligence Platforms

| Company | Valuation / Revenue | Core Product | KG-Native? | LLM Agent? | Codebase Awareness? |
|---|---|---|---|---|---|
| **CrowdStrike** | $83B market cap | Falcon XDR — endpoint/cloud/identity protection | ❌ Uses ATT&CK as label taxonomy | Partial (Charlotte AI assistant) | ❌ |
| **SentinelOne** | $18B market cap | Singularity — EDR + XDR, automated threat hunting | ❌ | Partial (Purple AI) | ❌ |
| **Palo Alto Networks** | $120B market cap | Cortex XSIAM — AI-driven SOC platform | ❌ | Partial (XSIAM copilot) | ❌ |
| **IBM** | $180B market cap | QRadar Suite — SIEM, AI-powered TDIR | ❌ | Partial (Watson) | ❌ |
| **Fortinet** | $72B market cap | FortiGuard — real-time threat intel | ❌ | ❌ | ❌ |
| **Tenable** | $5.5B market cap | Nessus/Tenable.io — vulnerability management | ❌ | Partial | ❌ |
| **Qualys** | $5B market cap | VMDR — cloud-based vulnerability management | ❌ | ❌ | ❌ |

**Key finding**: These are massive incumbents focused on signature-based / ML-based detection. None exposes MITRE ATT&CK as a queryable knowledge graph. None integrates LLM agents for autonomous investigation. None has codebase-level security awareness.

---

## 3. Cybersecurity AI Agent Startups (2025-2026)

| Company | Stage / Funding | What they do | KG? | Agent? | How ThreatGraph differs |
|---|---|---|---|---|---|
| **Hunters.AI** | Series C ($68M) | AI-powered SIEM, auto TDIR | ❌ | ✅ | No KG, no codebase awareness |
| **Calmo AI** | Seed | Temporal KG for incident RCA | ✅ | ✅ | Closest competitor — but focused on post-incident RCA, NOT proactive exposure analysis |
| **Deep Instinct** | Series D ($230M) | Zero-day prevention via deep learning | ❌ | ❌ | ML-only, no graph, no agent |
| **VulnCheck** | Series A | Machine-readable exploit intel | ❌ | ❌ | Data source, not a platform |
| **Cyb3r Operations** (London) | Seed (£4M, Jan 2026) | Real-time supplier cyber risk monitoring | ❌ | ❌ | Supply chain focus only |
| **ThreatAware** (London) | Growth ($25M, Feb 2026) | Cyber asset management + hygiene | ❌ | Planned | Asset inventory but no ATT&CK KG integration |

---

## 4. AI Code Security Tools (2025-2026)

| Tool | Released | What it does | KG? | Agent? | Gap vs. ThreatGraph |
|---|---|---|---|---|---|
| **Claude Code Security** (Anthropic) | Feb 2026 | Reasoning-based codebase vuln scanning. Found 500+ high-severity vulns in OSS. GitHub Action for PR reviews. `/security-review` command | ❌ | ✅ Agentic | Code-level only; no infrastructure KG, no ATT&CK mapping, no asset correlation |
| **HexStrike AI** (`0x4m4/hexstrike-ai`) | 2025 | MCP server enabling AI agents to run 150+ cybersecurity tools for pentesting | ❌ | ✅ via MCP | Offensive-focused; no KG, no defensive posture mapping |
| **Strix** (`usestrix/strix`) | 2025-2026 | Autonomous AI pentesting agent with collaborative agent teams | ❌ | ✅ Teams | Offensive pentesting; no defensive KG, no asset-ATT&CK correlation |
| **SWE-agent** (Princeton) | NeurIPS 2024 | GitHub issue → auto-fix. Can do offensive cybersecurity | ❌ | ✅ | General-purpose code agent, not security-focused KG |
| **Trail of Bits Skills** | 2025 | Claude Code skills for security research, vuln detection, audit workflows | ❌ | ✅ Skills | Individual skills, not an integrated platform |
| **Snyk Agent Scan** | 2025 | Security scanner for AI agents and MCP servers | ❌ | ✅ Scanner | Scans agents, doesn't protect infrastructure |
| **NVISO cyber-security-llm-agents** | 2025 | Collection of LLM agents for common cybersecurity tasks | ❌ | ✅ Collection | Individual task agents, no unified KG platform |

**Key finding**: Claude Code Security is best-in-class for code vulnerability detection but operates at the **code level only**. It doesn't map to MITRE ATT&CK, doesn't correlate with asset inventories, and doesn't provide infrastructure-level threat intelligence. ThreatGraph operates at the **infrastructure + threat intelligence level**, making them complementary, not competitive.

---

## 5. MITRE ATT&CK + Graph Database Projects (GitHub)

| Project | Stars | Graph DB | Agent? | What it does | Gap |
|---|---|---|---|---|---|
| `vmapps/attack2neo` | ~200 | Neo4j | ❌ | ATT&CK JSON → Neo4j import + Cypher queries | No agent, no asset correlation, no LLM |
| `EricssonResearch/cti-kb` | ~150 | Neo4j | ❌ | Full CTI knowledge base in Neo4j | Research project, not productized |
| `selffins/mitre_attack_neo4j_kg` | ~50 | Neo4j | ❌ | ATT&CK as Neo4j KG proof-of-concept | PoC only |
| `viyer-research/mitre-gnn-analysis` | ~30 | GNN+GraphRAG | ❌ | GNN analysis of ATT&CK + GraphRAG | Academic, not productized |
| `li-zhenyuan/AttacKG` | ~100 | Custom | ❌ | Extracts attack graphs from CTI reports | NLP-focused, no live correlation |
| `Kirtar22/ATTACK-Threat_Intel` | ~80 | Neo4j | ❌ | STIX → Neo4j via py2neo | Import script only |
| `ascentcore/mitre-neo4j` | ~40 | Neo4j | ❌ | ATT&CK → Neo4j visualization | Visualization only |

**Key finding**: Every project stops at "load ATT&CK into a graph database." None adds: (a) asset inventory overlay, (b) CVE/CPE correlation, (c) LLM agent reasoning, (d) remediation generation, or (e) codebase awareness.

---

## 6. Codebase Knowledge Graph Tools

| Tool | What it does | Gap vs. ThreatGraph |
|---|---|---|
| **GitNexus** (`abhigyanpatwari/GitNexus`) | Transforms codebase into interactive KG (files, functions, deps, call chains). Uses Tree-sitter WASM + KuzuDB. MCP-enabled | Not security-focused; no ATT&CK, no CVE correlation |
| **Potpie** | AI codebase understanding with KG | General-purpose, no security angle |
| **Sourcegraph Cody** | Code intelligence + search | No graph, not security-focused |

**Integration opportunity**: GitNexus-style codebase KG **inside** the ThreatGraph platform would enable: "This CVE affects library X → which is imported by file Y → which is called by function Z → here's the fix." This is the **code-to-infrastructure bridge** nobody has built.

---

## 7. Gap Analysis Matrix

```
                    KG-Native  LLM Agent  Asset       Codebase   ATT&CK    Remediation
                               Orchestr.  Correlation Awareness  Mapping   Generation
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
CrowdStrike          ❌         Partial     ✅          ❌          Label      ❌
Claude Code Security ❌         ✅          ❌          ✅          ❌         ✅ (code)
Calmo AI             ✅         ✅          ❌          ❌          Partial    ❌
attack2neo (GitHub)  ✅         ❌          ❌          ❌          ✅         ❌
GitNexus             ✅         ❌          ❌          ✅          ❌         ❌
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
ThreatGraph          ✅         ✅          ✅          ✅          ✅         ✅
```

> **No existing tool scores ✅ across all six dimensions.** ThreatGraph is the first to unify them.

---

## 8. Precise MOAT

1. **Schema IP**: The multi-layer graph schema (`threat_group→technique→software→CVE→asset→codebase_module`) is non-trivial and creates the only end-to-end threat-to-code mapping
2. **Free data advantage**: MITRE ATT&CK (free), NVD CVEs (free), CISA KEV (free), Companies House (free) — the data moat is in the RELATIONSHIPS, not the data itself
3. **Temporal evolution**: SurrealDB timestamps every edge. "Show me how my exposure changed this quarter" is impossible to retrofit
4. **Open-source flywheel**: Publishing `langchain-surrealdb-mitre-toolkit` makes SurrealDB the default for security KGs, creating ecosystem lock-in
5. **Codebase bridge**: The GitNexus-inspired code KG layer creates a unique code→infrastructure→threat correlation no one else has
