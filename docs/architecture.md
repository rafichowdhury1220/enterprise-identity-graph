# Architecture and Design

This document captures the solution architect thinking behind the `enterprise-identity-graph` project.

## Business challenge

Enterprises need a single lens over identity relationships across users, groups, roles, applications, and privileges. The goal is to detect hidden escalation paths and over-privileged users without depending on a single vendor.

## Core design principles

- **Modularity**: separate model, graph traversal, and risk scoring so each layer can be extended independently.
- **Domain-driven structure**: identify business entities such as `User`, `Role`, `Group`, `Application`, and `Privilege` explicitly.
- **Readability**: use simple Python dataclasses and clear method names so the code is accessible to reviewers and recruiters.
- **Analyst-friendly output**: include summary and recommendation text that mirrors what an IAM analyst or security architect would present.

## Component overview

- `src/enterprise_identity_graph/graph.py`
  - Builds and stores identity graph nodes and relationships.
  - Supports path search and escalation detection.
  - Can be extended later to load from CSV, API, or graph stores.

- `src/enterprise_identity_graph/risk.py`
  - Calculates risk scores for users using exposure and privilege concentration metrics.
  - Produces recommendation guidance aligned to IAM best practices.

- `src/enterprise_identity_graph/demo.py`
  - Provides a sample domain scenario and output formatting.
  - Demonstrates how a solution architect frames the problem and results.

## Technical extension roadmap

1. Add a connector layer for HR systems, Active Directory, and SaaS entitlement APIs.
2. Replace the in-memory graph with a persisted graph store like Neo4j or Amazon Neptune.
3. Add a service API and visualization layer for enterprise dashboards.
4. Add governance signals such as stale access age, last login, and policy compliance status.

## Recruiter-friendly messaging

Builds credibility by showing:
- enterprise IAM domain knowledge
- graph-based privilege analysis
- risk scoring logic, not just data parsing
- a clear path for productizing the solution
