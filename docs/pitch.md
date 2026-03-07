# ThreatGraph — Pitch

---

## 2-Minute Pitch Script

*This is the script for the live demo on Sunday + the 2-minute video submission.*

---

### HOOK (15 seconds)

> "A new CVE just dropped. Right now. CVE-2026-1234. Apache HTTP Server. CVSS 9.8.
>
> Your SOC analyst opens a browser. Searches the NVD. Reads the advisory. Opens the ATT&CK matrix. Cross-references. Checks the CMDB. Two hours later, they know if they're affected.
>
> **We do that in 3 seconds.**"

---

### THE PROBLEM (20 seconds)

> "Every SOC has MITRE ATT&CK posters on the wall — 794 techniques, 143 threat groups, 680 software tools. But it's stuck in a PDF.
>
> Meanwhile, 40,000 new CVEs hit the NVD every year. Each one needs to be cross-referenced: CVE → software → technique → threat group → your assets. The data to connect them exists. But it's in **separate databases, separate formats, separate teams**.
>
> Nobody has connected the dots."

---

### THE SOLUTION (30 seconds)

> "ThreatGraph loads the entire MITRE ATT&CK framework as a knowledge graph in SurrealDB. Then it overlays YOUR asset inventory and YOUR vulnerabilities.
>
> The result: a single queryable graph where **threat actors, techniques, CVEs, and your specific assets are all connected by real edges**.
>
> Then a LangGraph AI agent lets you ask questions in plain English..."

**[SWITCH TO LIVE DEMO]**

---

### LIVE DEMO (45 seconds — 3 queries)

**Demo 1 — CVE Alert (15 sec)**

*Type*: `"CVE-2026-1234 just dropped. Am I affected?"`

*Agent responds*: Shows affected assets, maps to APT groups, suggests patches + detection rules.

> "3 seconds. Not 2 hours."

**Demo 2 — Threat Group Exposure (15 sec)**

*Type*: `"How exposed am I to APT29?"`

*Agent responds*: Lists techniques APT29 uses, cross-references with your assets, shows which ones are vulnerable, gives exposure score.

> "A question that used to require a Red Team engagement. Now it's a chat message."

**Demo 3 — Priority Ranking (15 sec)**

*Type*: `"What's my biggest risk right now?"`

*Agent responds*: Ranks assets by exposure score. Shows the #1 risk with full attack path: threat group → technique → software → CVE → your server.

> "This is the question every CISO asks. Now it has an instant, data-driven answer."

---

### WHY IT WORKS (15 seconds)

> "Three things make this different:
>
> **One**: MITRE ATT&CK IS a knowledge graph. We're not forcing data into a graph — we're giving it its natural home. SurrealDB handles graph traversal, vector search, and relational state in one engine.
>
> **Two**: LangGraph orchestrates the investigation — classify, plan, query, synthesize, remediate — with full LangSmith observability.
>
> **Three**: We're publishing `langchain-surrealdb-mitre-toolkit` as an open-source LangChain integration. This tool lives beyond this weekend."

---

### CLOSE (10 seconds)

> "ThreatGraph doesn't just search for threats. It **connects** them — from threat group to technique to CVE to **your** server.
>
> Every SOC needs this. Every CISO is asking for this.
>
> We built it this weekend."

---

## Slide Deck Outline (for 2-min Video)

If recording a video with slides alongside the demo:

| Slide | Content | Duration |
|---|---|---|
| 1 | **Title**: ThreatGraph — Your ATT&CK KG, Queryable | 5 sec |
| 2 | **The Problem**: 794 techniques × 40K CVEs × N assets = manual investigation | 10 sec |
| 3 | **Architecture**: 4-layer diagram (Threat KG → Asset Overlay → Code Awareness → Agent) | 10 sec |
| 4 | **Live Demo**: Screen recording of 3 queries | 60 sec |
| 5 | **How it scores**: Judging criteria alignment (30% KG ✅ / 20% Agent ✅ / 20% State ✅ / 20% Use Case ✅ / 10% Observability ✅) | 10 sec |
| 6 | **Open Source**: `langchain-surrealdb-mitre-toolkit` components | 10 sec |
| 7 | **Close**: "Every SOC needs this. We built it this weekend." | 10 sec |

---

## Pitch Tips

1. **Start with the CVE hook** — it's visceral and every engineer understands it
2. **Show, don't tell** — the live demo IS the pitch. Keep the slides minimal
3. **Time the demo queries** — practice until each query + response is <5 seconds
4. **End with the open-source mention** — judges explicitly reward this
5. **Have a backup**: Pre-recorded LangSmith trace screenshots in case live demo glitches
