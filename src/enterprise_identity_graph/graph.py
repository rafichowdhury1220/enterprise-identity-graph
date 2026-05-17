from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, Iterable, List, Optional, Set, Tuple


class NodeType(str, Enum):
    USER = "user"
    ROLE = "role"
    GROUP = "group"
    APPLICATION = "application"
    PRIVILEGE = "privilege"


@dataclass(frozen=True)
class IdentityNode:
    id: str
    type: NodeType
    metadata: Dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class Relationship:
    source: IdentityNode
    target: IdentityNode
    label: str


class IdentityGraph:
    def __init__(self) -> None:
        self.nodes: Dict[str, IdentityNode] = {}
        self.adjacency: Dict[str, Set[str]] = {}
        self.relationships: List[Relationship] = []

    def add_node(self, node_id: str, node_type: NodeType, metadata: Optional[Dict[str, str]] = None) -> IdentityNode:
        metadata = metadata or {}
        if node_id not in self.nodes:
            node = IdentityNode(id=node_id, type=node_type, metadata=metadata)
            self.nodes[node_id] = node
            self.adjacency[node_id] = set()
        return self.nodes[node_id]

    def add_edge(self, source_id: str, target_id: str, label: str) -> None:
        if source_id not in self.nodes or target_id not in self.nodes:
            raise KeyError("Both source and target nodes must exist before adding an edge.")
        self.adjacency[source_id].add(target_id)
        self.relationships.append(Relationship(source=self.nodes[source_id], target=self.nodes[target_id], label=label))

    def get_neighbors(self, node_id: str) -> Set[str]:
        return self.adjacency.get(node_id, set())

    def _bfs_paths(self, start_id: str, goal_type: Optional[NodeType] = None, max_depth: int = 5) -> List[List[str]]:
        if start_id not in self.nodes:
            return []

        paths: List[List[str]] = []
        queue: List[List[str]] = [[start_id]]

        while queue:
            path = queue.pop(0)
            node_id = path[-1]
            if goal_type and self.nodes[node_id].type == goal_type and node_id != start_id:
                paths.append(path)
            if len(path) >= max_depth:
                continue
            for neighbor in self.get_neighbors(node_id):
                if neighbor in path:
                    continue
                queue.append(path + [neighbor])

        return paths

    def find_paths(self, start_id: str, goal_type: NodeType, max_depth: int = 6) -> List[List[IdentityNode]]:
        raw_paths = self._bfs_paths(start_id, goal_type=goal_type, max_depth=max_depth)
        return [[self.nodes[node_id] for node_id in path] for path in raw_paths]

    def get_user_nodes(self) -> List[IdentityNode]:
        return [node for node in self.nodes.values() if node.type == NodeType.USER]

    def get_direct_privileges(self, user_id: str) -> Set[IdentityNode]:
        privilege_nodes: Set[IdentityNode] = set()
        for role_path in self.find_paths(user_id, NodeType.ROLE):
            role_id = role_path[-1].id
            for priv_path in self.find_paths(role_id, NodeType.PRIVILEGE):
                privilege_nodes.add(priv_path[-1])
        for group_path in self.find_paths(user_id, NodeType.GROUP):
            group_id = group_path[-1].id
            for role_path in self.find_paths(group_id, NodeType.ROLE):
                role_id = role_path[-1].id
                for priv_path in self.find_paths(role_id, NodeType.PRIVILEGE):
                    privilege_nodes.add(priv_path[-1])
        return privilege_nodes

    def detect_privilege_escalation_paths(self, user_id: str, max_depth: int = 6) -> List[List[IdentityNode]]:
        escalation_paths: List[List[IdentityNode]] = []
        if user_id not in self.nodes:
            return escalation_paths

        goal_types = {NodeType.PRIVILEGE, NodeType.APPLICATION}
        queue: List[List[str]] = [[user_id]]

        while queue:
            path = queue.pop(0)
            node_id = path[-1]
            node = self.nodes[node_id]
            if node.type in goal_types and node_id != user_id:
                escalation_paths.append([self.nodes[n] for n in path])
            if len(path) >= max_depth:
                continue
            for neighbor in self.get_neighbors(node_id):
                if neighbor in path:
                    continue
                queue.append(path + [neighbor])

        return escalation_paths

    def summarize_user_access(self, user_id: str) -> Dict[str, int]:
        if user_id not in self.nodes:
            raise KeyError(f"User {user_id} not found in identity graph.")

        role_count = len(self.find_paths(user_id, NodeType.ROLE))
        group_count = len(self.find_paths(user_id, NodeType.GROUP))
        app_count = len(self.find_paths(user_id, NodeType.APPLICATION))
        privilege_count = len(self.detect_privilege_escalation_paths(user_id))

        return {
            "roles": role_count,
            "groups": group_count,
            "applications": app_count,
            "privilege_paths": privilege_count,
        }
