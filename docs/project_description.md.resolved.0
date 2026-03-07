# ThreatGraph — Project Description

---

## The Problem

Every Security Operations Center (SOC) in the world has MITRE ATT&CK posters on the wall. These posters map **794 techniques** used by **143 threat groups** via **680 software tools**. But this knowledge is trapped in static JSON files and PDF matrices. Meanwhile:

- **CVE volume is exploding**: 40,000+ new CVEs in 2025 alone. When a new CVE drops, an analyst manually cross-references the CVE → the affected software → which techniques exploit it → which threat groups use those techniques → whether any of their assets run that software → what to do about it. This takes **2-4 hours per CVE**.
- **The data exists but isn't connected**: MITRE ATT&CK has the threat actor techniques. The NVD has the CVEs. CPE has the software identifiers. But there's no system that **connects** them into a single queryable graph where you can ask: *"Which of MY assets are vulnerable to techniques used by APT groups targeting MY industry?"*
- **Code-level vulnerabilities are invisible at the infrastructure level**: Tools like Claude Code Security find vulnerabilities in code. But nobody maps those code-level findings to the MITRE ATT&CK techniques they enable, or to the specific assets running that code.

---

## The Solution: ThreatGraph

ThreatGraph is an **AI-powered cybersecurity agent** that builds a multi-layer knowledge graph connecting threat intelligence, asset inventories, vulnerabilities, and codebases — then uses LangGraph-orchestrated agents to answer natural-language security questions, discover exposure paths, and generate remediation plans.

### How It Works: The Complete Pipeline

```
MITRE ATT&CK KG          Asset Inventory          NVD CVE Data
(threat groups,           (servers, OS,            (vulnerabilities,
 techniques, software)     software versions)       CVSS scores, CPE)
       │                        │                        │
       └────────────┬───────────┘────────────────────────┘
                    │
                    ▼
        ┌───────────────────────┐
        │    SURREALDB KG       │
        │                       │
        │  Unified Multi-Layer  │
        │  Knowledge Graph      │
        └───────────┬───────────┘
                    │
                    ▼
        ┌───────────────────────┐
        │  LANGGRAPH AGENT      │
        │                       │
        │  Natural Language      │
        │  Query → Graph         │
        │  Traversal → Analysis  │
        │  → Remediation         │
        └───────────┬───────────┘
                    │
                    ▼
        ┌───────────────────────┐
        │    ACTIONABLE OUTPUT  │
        │                       │
        │  • Exposure report     │
        │  • Attack paths        │
        │  • Detection rules     │
        │  • Remediation steps   │
        │  • Priority ranking    │
        └───────────────────────┘
```

### Step-by-Step: From ATT&CK to "Fix This"

**Step 1 — Build the Threat Intelligence KG** (automated, ~5 minutes)

The system ingests MITRE ATT&CK STIX 2.1 JSON, creating nodes for every technique, tactic, threat group, and software item, with `RELATE` edges connecting them:

```
APT29 ──uses──▶ T1566.001 (Phishing: Spearphishing Attachment)
T1566.001 ──belongs_to──▶ TA0001 (Initial Access)
APT29 ──employs──▶ SUNBURST
T1566.001 ──mitigated_by──▶ M1049 (Antivirus/Antimalware)
```

**Step 2 — Overlay the Asset Inventory** (manual input or API import)

The organization's assets are added with their software versions:

```
web-server-01 ──runs──▶ Apache/2.4.49
db-server-03 ──runs──▶ PostgreSQL/13.2
```

**Step 3 — Correlate CVEs** (automated via NVD API)

The system queries the NVD for CVEs affecting the software versions in the asset inventory, linking them via CPE matching:

```
CVE-2021-41773 ──affects──▶ Apache/2.4.49
CVE-2021-41773 ──has_cve──▶ Apache (software node in ATT&CK)
Apache ◀──employs── APT41
APT41 ──uses──▶ T1190 (Exploit Public-Facing Application)
```

**Step 4 — Discover Attack Paths** (graph traversal)

Now the KG contains the full chain. A single SurrealQL query reveals:

```
web-server-01 ──runs──▶ Apache/2.4.49 ──has_cve──▶ CVE-2021-41773
    ──exploitable_via──▶ T1190 ──used_by──▶ APT41
    ──used_by──▶ Hafnium
```

**In plain English**: "Your web server is running a version of Apache with a known path traversal vulnerability (CVE-2021-41773). This vulnerability enables the 'Exploit Public-Facing Application' technique (T1190), which is actively used by APT41 and Hafnium. APT41 specifically targets the technology sector."

**Step 5 — Generate Remediation** (LLM synthesis)

The agent generates actionable output:
- **Immediate**: Upgrade Apache to 2.4.51+
- **Detection rule**: Monitor for `%2e%2e/` path traversal patterns in HTTP logs
- **Mitigation**: Apply MITRE mitigation M1048 (Application Isolation and Sandboxing)
- **Priority**: HIGH — CVSS 9.8, actively exploited, APT41 targeting your sector

---

## The Four Architecture Layers

### Layer 1: Threat Intelligence KG (Core)
The foundation — MITRE ATT&CK data as a fully queryable graph in SurrealDB. 794 techniques, 143 groups, 680 software items, all with proper `RELATE` edges. Enriched with CISA Known Exploited Vulnerabilities (KEV) catalog.

### Layer 2: Asset & Vulnerability Overlay
The organization's specific attack surface — servers, software versions, network zones, and their mapped CVEs from the NVD. CPE matching links assets to the ATT&CK software nodes.

### Layer 3: Codebase Awareness (Stretch Goal)
Inspired by GitNexus, this layer builds a KG of the organization's codebase (files, functions, imports, dependencies) and links library dependencies to the CVE layer. This enables: "CVE-2021-41773 affects Apache → Apache is used by `deploy/nginx.conf` → which is deployed on `web-server-01`."

### Layer 4: Agent Orchestration
LangGraph-powered agents that classify queries, plan investigation steps, execute multi-hop graph traversals, and synthesize actionable reports. Fully traced via LangSmith.

---

## Target Users

| User | Use Case | Value |
|---|---|---|
| **SOC Analysts** | "Am I vulnerable to APT29?" | Instant exposure assessment in natural language |
| **CISOs** | "What's our top risk this quarter?" | Aggregate exposure scores with ATT&CK context |
| **Incident Responders** | "A new CVE just dropped — who's affected?" | Instant blast radius analysis |
| **DevSecOps** | "Which of our code dependencies have known CVEs?" | Code→CVE→technique mapping |
| **Compliance Teams** | "Show our coverage against MITRE ATT&CK" | Gap analysis for regulatory reporting |

---

## Open-Source Contribution

### `langchain-surrealdb-mitre-toolkit`

A standalone, reusable LangChain integration:

| Component | What it does |
|---|---|
| `MITREAttackLoader` | Parses ATT&CK STIX 2.1 JSON → SurrealDB `CREATE` + `RELATE` |
| `MITREGraphRetriever` | LangChain retriever combining vector similarity + graph traversal |
| `ThreatExposureTool` | LangChain tool computing exposure scores via graph analysis |
| `CVECorrelationTool` | Maps NVD CVEs to ATT&CK techniques via CPE matching |
| `SurrealCheckpointer` | LangGraph checkpoint backend using SurrealDB |

This contribution lives beyond the hackathon as a reusable building block for any security team building on LangChain + SurrealDB.

---

## Why This Wins

1. **Purest KG use case**: MITRE ATT&CK IS a knowledge graph. We're not forcing data into a graph — we're giving a graph its natural home
2. **Free data, zero risk**: All data sources (ATT&CK, NVD, CISA KEV) are public and free
3. **Universal audience**: Every engineer in the room understands cybersecurity
4. **Clear before/after**: "2 hours per CVE → 3 seconds per CVE" is an instantly compelling pitch
5. **Hackathon-perfect demo**: The attack path visualization is visually stunning and immediately understandable
