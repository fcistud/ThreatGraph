# ThreatGraph Pitch

## 2-4 minute version

Hi, I am presenting ThreatGraph.

ThreatGraph is a cybersecurity investigation app built specifically around the LangChain x SurrealDB stack.

The problem we are solving is that most security tools leave you with disconnected pieces of information:

- an asset inventory
- a vulnerability list
- threat intelligence
- and a chatbot that may sound useful but is not grounded in persistent state

ThreatGraph connects those pieces into one structured system.

We load MITRE ATT&CK into SurrealDB as a threat knowledge graph.
We seed an enterprise environment with assets, software versions, controls, network zones, and threat vectors.
We correlate CVEs from NVD.
Then we use LangGraph to orchestrate multi-step investigations over that graph.

The key point is that SurrealDB is not just storing flat rows.
It stores both the threat graph and the evolving investigation state.
That lets us do things like:

- link an internal software version to ATT&CK software
- map that to techniques and threat groups
- rank internal assets using evidence bundles
- and persist the result under a reusable investigation thread ID

On the LangGraph side, the workflow is explicit.
The system classifies the question, routes to the right graph logic, collects evidence, synthesizes the answer, and stores investigation context for the next turn.

So if I ask:

- “Which asset is most exposed?”

and then ask:

- “Now give me remediation steps for that one”

the second question is not stateless.
It reloads the prior investigation context from SurrealDB.

In the UI, we expose that thread state directly.
We also expose evidence bundles, attack-path details, and recent investigation history so the system is explainable instead of magical.

From a hackathon perspective, the story is simple:

- SurrealDB gives us structured persistent memory
- LangGraph gives us stateful agent orchestration
- the graph evolves through ingest and investigations
- and the app solves a real-world use case: security exposure analysis and threat-informed prioritization

ThreatGraph is not just a chat demo.
It is a graph-backed, stateful cyber investigation workflow built around the exact technologies this hackathon is about.
