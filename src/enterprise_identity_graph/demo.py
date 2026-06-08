import sys
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parents[1]))

from enterprise_identity_graph import IdentityGraph, NodeType, RiskEngine


def build_sample_graph() -> IdentityGraph:
    graph = IdentityGraph()

    # Users
    graph.add_node("rafi", NodeType.USER, {"name": "Rafi Khan", "business_unit": "Finance"})
    graph.add_node("devin", NodeType.USER, {"name": "Devin Lee", "business_unit": "Cloud Ops"})

    # Roles
    graph.add_node("finance_admin", NodeType.ROLE, {"name": "Finance Admin"})
    graph.add_node("sap_user", NodeType.ROLE, {"name": "SAP User"})
    graph.add_node("cloud_security", NodeType.ROLE, {"name": "Cloud Security"})

    # Groups
    graph.add_node("finance_dept", NodeType.GROUP, {"name": "Finance Department"})
    graph.add_node("security_team", NodeType.GROUP, {"name": "Security Team"})

    # Applications
    graph.add_node("sap", NodeType.APPLICATION, {"name": "SAP"})
    graph.add_node("workday", NodeType.APPLICATION, {"name": "Workday"})
    graph.add_node("aws_console", NodeType.APPLICATION, {"name": "AWS Console"})

    # Privileges
    graph.add_node("approve_payments", NodeType.PRIVILEGE, {"description": "Approve payments"})
    graph.add_node("manage_users", NodeType.PRIVILEGE, {"description": "Manage identity accounts"})
    graph.add_node("deploy_infrastructure", NodeType.PRIVILEGE, {"description": "Deploy infrastructure"})

    # Relationships
    graph.add_edge("rafi", "finance_dept", "member-of")
    graph.add_edge("finance_dept", "finance_admin", "grants-role")
    graph.add_edge("finance_admin", "sap", "access-to")
    graph.add_edge("finance_admin", "workday", "access-to")
    graph.add_edge("finance_admin", "approve_payments", "grants-privilege")

    graph.add_edge("devin", "security_team", "member-of")
    graph.add_edge("security_team", "cloud_security", "grants-role")
    graph.add_edge("cloud_security", "aws_console", "access-to")
    graph.add_edge("cloud_security", "manage_users", "grants-privilege")
    graph.add_edge("cloud_security", "deploy_infrastructure", "grants-privilege")

    return graph


def print_analysis(graph: IdentityGraph) -> None:
    engine = RiskEngine(graph)
    for user in graph.get_user_nodes():
        result = engine.score_user(user.id)
        print("User:", user.metadata.get("name", user.id))
        print("  Business unit:", user.metadata.get("business_unit", "n/a"))
        print("  Access summary:", result["summary"])
        print("  Risk category:", result["risk_category"])
        print("  Recommendations:")
        for rec in result["recommendations"]:
            print("    -", rec)
        print("")

        escalation_paths = graph.detect_privilege_escalation_paths(user.id)
        if escalation_paths:
            print("  Privilege escalation paths:")
            for path in escalation_paths:
                print("    -", " -> ".join(f"{node.type}:{node.id}" for node in path))
            print("")


if __name__ == "__main__":
    sample_graph = build_sample_graph()
    print("Enterprise Identity Graph Demo")
    print("===============================\n")
    print_analysis(sample_graph)
