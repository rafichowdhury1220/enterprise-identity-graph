from __future__ import annotations

from typing import Dict, Iterable, List

from .graph import IdentityGraph, NodeType


class RiskEngine:
    def __init__(self, graph: IdentityGraph) -> None:
        self.graph = graph

    def score_user(self, user_id: str) -> Dict[str, object]:
        summary = self.graph.summarize_user_access(user_id)
        app_count = summary["applications"]
        role_count = summary["roles"]
        privilege_count = summary["privilege_paths"]

        scores = {
            "application_exposure": self._score_application_exposure(app_count),
            "privileged_role_concentration": self._score_role_concentration(role_count),
            "privilege_path_risk": self._score_privilege_path_count(privilege_count),
        }

        return {
            "user_id": user_id,
            "summary": summary,
            "scores": scores,
            "risk_category": self._build_risk_category(scores),
            "recommendations": self._build_recommendations(scores),
        }

    def _score_application_exposure(self, app_count: int) -> int:
        if app_count >= 10:
            return 5
        if app_count >= 6:
            return 4
        if app_count >= 3:
            return 3
        return 1 if app_count > 0 else 0

    def _score_role_concentration(self, role_count: int) -> int:
        if role_count >= 4:
            return 5
        if role_count >= 2:
            return 3
        return 1

    def _score_privilege_path_count(self, privilege_count: int) -> int:
        if privilege_count >= 4:
            return 5
        if privilege_count >= 2:
            return 3
        return 1

    def _build_risk_category(self, scores: Dict[str, int]) -> str:
        weighted = scores["application_exposure"] + scores["privileged_role_concentration"] + scores["privilege_path_risk"]
        if weighted >= 12:
            return "High"
        if weighted >= 7:
            return "Medium"
        return "Low"

    def _build_recommendations(self, scores: Dict[str, int]) -> List[str]:
        recommendations: List[str] = []
        if scores["application_exposure"] >= 4:
            recommendations.append("Review application access and remove stale SaaS credentials.")
        if scores["privileged_role_concentration"] >= 3:
            recommendations.append("Break out privileged responsibilities into least-privilege roles.")
        if scores["privilege_path_risk"] >= 3:
            recommendations.append("Inspect privilege escalation paths and enforce role-based access controls.")
        if not recommendations:
            recommendations.append("Status looks stable. Continue periodic entitlement reviews.")
        return recommendations

    def score_all_users(self) -> List[Dict[str, object]]:
        return [self.score_user(user.id) for user in self.graph.get_user_nodes()]

