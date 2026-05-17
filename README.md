# Enterprise Identity Graph

A Python project that models identity relationships across users, roles, groups, applications, and privileges. This repository is designed to showcase both the solution architect mindset and the hands-on IAM engineering work needed to turn identity graph concepts into a recruiter-friendly portfolio piece.

## Why this project exists

Large organizations have identity relationships spread across HR systems, Active Directory, cloud accounts, SaaS apps, and IAM platforms. No single source of truth gives a full picture of who can access what and how privilege escalation paths are formed.

This project demonstrates:
- **Architecture thinking**: modular design, clear separation between data model, graph analysis, and risk scoring
- **IAM engineering**: identity graph construction, privilege escalation detection, over-privilege analysis
- **Recruiter appeal**: business problem framing, technical design, sample output, and next-step recommendations

## What the project does

- Builds an in-memory identity graph from users, roles, groups, apps, and privileges
- Finds privilege escalation and access paths through relationships
- Scores identity risk using application exposure and privileged role concentration
- Produces clear, actionable analysis suitable for a technical portfolio

## Project structure

- `src/enterprise_identity_graph/graph.py` — graph builder and traversal engine
- `src/enterprise_identity_graph/risk.py` — risk and exposure scoring
- `src/enterprise_identity_graph/demo.py` — sample scenario with example output
- `docs/architecture.md` — architecture thinking, edge cases, and extension roadmap
- `tests/test_identity_graph.py` — unit tests demonstrating correctness and engineering rigor

## Run the demo

```bash
python src/enterprise_identity_graph/demo.py
```

## Solution architect narrative

A solution architect writes this project with the following priorities:

1. **Problem-first design**: start from the real enterprise problem of scattered identity sources and privilege paths.
2. **Clear abstractions**: separate nodes, edges, graph traversal, and risk scoring so each module can evolve independently.
3. **Scalable pattern**: design the code so it can later ingest CSV, APIs, or graph databases without changing core analysis.
4. **Recruiter storytelling**: include a README that explains the business value, technical approach, and next steps.

## Next evolution ideas

- Add connectors for HR/AD/SaaS feeds
- Store the graph in Neo4j or Amazon Neptune
- Add a web dashboard showing privilege paths and risk scores
- Add anomaly detection for orphaned privileged accounts and stale access
