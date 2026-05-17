import pytest

from enterprise_identity_graph import IdentityGraph, NodeType, RiskEngine


def test_graph_build_and_path_detection() -> None:
    graph = IdentityGraph()
    graph.add_node("alice", NodeType.USER)
    graph.add_node("group_a", NodeType.GROUP)
    graph.add_node("role_a", NodeType.ROLE)
    graph.add_node("app_a", NodeType.APPLICATION)
    graph.add_node("priv_a", NodeType.PRIVILEGE)

    graph.add_edge("alice", "group_a", "member-of")
    graph.add_edge("group_a", "role_a", "grants-role")
    graph.add_edge("role_a", "app_a", "access-to")
    graph.add_edge("role_a", "priv_a", "grants-privilege")

    paths = graph.detect_privilege_escalation_paths("alice")
    assert any(path[-1].type == NodeType.PRIVILEGE for path in paths)
    assert any(path[-1].type == NodeType.APPLICATION for path in paths)


def test_risk_engine_scores_user() -> None:
    graph = IdentityGraph()
    graph.add_node("bob", NodeType.USER)
    graph.add_node("role_b", NodeType.ROLE)
    graph.add_node("app_b", NodeType.APPLICATION)
    graph.add_node("priv_b", NodeType.PRIVILEGE)

    graph.add_edge("bob", "role_b", "has-role")
    graph.add_edge("role_b", "app_b", "access-to")
    graph.add_edge("role_b", "priv_b", "grants-privilege")

    engine = RiskEngine(graph)
    report = engine.score_user("bob")

    assert report["summary"]["applications"] == 1
    assert report["summary"]["roles"] == 1
    assert report["risk_category"] in {"Low", "Medium", "High"}
    assert isinstance(report["recommendations"], list)
