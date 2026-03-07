# ThreatGraph Deployment Guide

This document explains how to deploy the project to the cloud.

The focus is practical deployment, not vendor-specific marketing.

---

## 1. What needs to be deployed

ThreatGraph has two essential runtime pieces:

1. the Streamlit app
2. the SurrealDB data layer

There is also one important optional piece:

3. LangSmith tracing

---

## 2. Simplest deployment for a hackathon

The fastest cloud deployment is a single VM or single container host.

Run:

- the app
- file-backed SurrealDB storage
- the local data directory

### Why this is the fastest

- fewest moving parts
- easiest to debug
- easiest to demo

### Shape

```text
Internet
  |
Reverse proxy / HTTPS
  |
App container / VM
  |
Streamlit app + file-backed SurrealDB data path
```

### Good for

- demo deployment
- hackathon submission
- quick preview links

### Weakness

- app and DB are coupled
- not ideal for scale

---

## 3. Cleaner cloud deployment

The cleaner design separates app and DB.

### Recommended architecture

```text
Browser
  |
HTTPS / load balancer
  |
Streamlit app container
  |
SurrealDB service with persistent volume
```

### Components

#### App service

Runs:

- Python
- Streamlit
- app code

#### Database service

Runs:

- SurrealDB
- persistent volume

#### Object/blob storage (optional)

Useful for:

- backups
- exported screenshots
- future artifacts

---

## 4. Environment variables

At minimum:

```bash
SURREALDB_URL=...
SURREALDB_NS=threatgraph
SURREALDB_DB=main
SURREALDB_USER=...
SURREALDB_PASS=...
```

Optional:

```bash
OPENAI_API_KEY=...
ANTHROPIC_API_KEY=...
NVD_API_KEY=...
LANGSMITH_API_KEY=...
LANGCHAIN_TRACING_V2=true
LANGCHAIN_PROJECT=threatgraph
```

---

## 5. Deployment steps

### Step 1: Build image

Use the existing Dockerfile or a Python container image.

### Step 2: Set persistent SurrealDB storage

Do not use in-memory mode in the cloud.

Use:

- file-backed storage
- or a dedicated SurrealDB server deployment

### Step 3: Run ingest

Before exposing the app:

```bash
python3 ingest.py
```

This should either:

- run once as an initialization job
- or run as a separate bootstrap step

### Step 4: Start the app

```bash
streamlit run app.py --server.address 0.0.0.0 --server.port 8501
```

### Step 5: Put HTTPS in front

Use a reverse proxy or platform TLS termination.

---

## 6. Deployment modes

### Mode A: demo mode

- one instance
- one DB
- one volume
- okay for judges and demos

### Mode B: pilot mode

- separate app and DB
- backups
- secrets management
- monitoring

### Mode C: production direction

- dedicated auth
- tenant isolation
- ingestion jobs
- operational alerting
- role-based controls

---

## 7. Data persistence strategy

You need persistence for:

- SurrealDB graph data
- investigation history
- checkpoint data
- NVD cache

Recommended:

- persistent DB volume
- persistent app storage or mounted volume for `.context` cache if you want cache retention

---

## 8. CI/CD

Simple CI/CD path:

1. push to GitHub
2. run tests
3. build image
4. deploy app
5. run ingest/bootstrap if needed

For the hackathon, keep this simple.

The important thing is reproducibility, not enterprise release engineering.

---

## 9. Security considerations

### Secrets

Do not hardcode:

- API keys
- DB passwords

Use environment variables or a secrets manager.

### Network exposure

If the DB is separate, do not expose it publicly.

Only the app should be public.

### TLS

Use HTTPS in front of the app.

### Logging

Avoid logging secrets or raw API keys.

---

## 10. How to showcase deployment in the demo

You do not need to fully deploy live during the demo.

But you should be able to explain:

- where SurrealDB lives
- where the app lives
- where persistence happens
- how tracing is enabled
- how ingest/bootstrap happens

That is enough for a strong technical explanation.

---

## 11. Recommended demo deployment story

For the hackathon, the best story is:

- local or single-host deployment for demo reliability
- file-backed SurrealDB persistence
- Streamlit app on a public URL
- optional LangSmith tracing enabled

That keeps the story tight and reduces failure risk during judging.
