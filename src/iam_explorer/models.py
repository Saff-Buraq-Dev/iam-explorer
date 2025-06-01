"""
Data models for IAM resources and graph representation.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Any
from datetime import datetime
import networkx as nx


@dataclass
class IAMPolicy:
    """Represents an IAM policy."""
    arn: str
    name: str
    policy_document: Dict[str, Any]
    is_aws_managed: bool = False
    description: Optional[str] = None
    create_date: Optional[datetime] = None
    update_date: Optional[datetime] = None

    def get_allowed_actions(self) -> Set[str]:
        """Extract allowed actions from policy document."""
        actions = set()
        statements = self.policy_document.get("Statement", [])

        for statement in statements:
            if statement.get("Effect") == "Allow":
                action_list = statement.get("Action", [])
                if isinstance(action_list, str):
                    action_list = [action_list]
                actions.update(action_list)

        return actions

    def get_denied_actions(self) -> Set[str]:
        """Extract denied actions from policy document."""
        actions = set()
        statements = self.policy_document.get("Statement", [])

        for statement in statements:
            if statement.get("Effect") == "Deny":
                action_list = statement.get("Action", [])
                if isinstance(action_list, str):
                    action_list = [action_list]
                actions.update(action_list)

        return actions


@dataclass
class IAMUser:
    """Represents an IAM user."""
    arn: str
    name: str
    user_id: str
    path: str = "/"
    create_date: Optional[datetime] = None
    password_last_used: Optional[datetime] = None
    attached_policies: List[str] = field(default_factory=list)
    inline_policies: Dict[str, Dict] = field(default_factory=dict)
    groups: List[str] = field(default_factory=list)
    permission_boundary: Optional[str] = None
    tags: Dict[str, str] = field(default_factory=dict)


@dataclass
class IAMRole:
    """Represents an IAM role."""
    arn: str
    name: str
    role_id: str
    path: str = "/"
    assume_role_policy: Dict[str, Any] = field(default_factory=dict)
    create_date: Optional[datetime] = None
    max_session_duration: int = 3600
    attached_policies: List[str] = field(default_factory=list)
    inline_policies: Dict[str, Dict] = field(default_factory=dict)
    permission_boundary: Optional[str] = None
    tags: Dict[str, str] = field(default_factory=dict)

    def get_trusted_entities(self) -> Set[str]:
        """Extract trusted entities from assume role policy."""
        trusted = set()
        statements = self.assume_role_policy.get("Statement", [])

        for statement in statements:
            if statement.get("Effect") == "Allow":
                principals = statement.get("Principal", {})
                if isinstance(principals, dict):
                    # Handle AWS principals
                    aws_principals = principals.get("AWS", [])
                    if isinstance(aws_principals, str):
                        aws_principals = [aws_principals]
                    trusted.update(aws_principals)

                    # Handle Service principals
                    service_principals = principals.get("Service", [])
                    if isinstance(service_principals, str):
                        service_principals = [service_principals]
                    trusted.update(service_principals)
                elif isinstance(principals, str):
                    trusted.add(principals)

        return trusted


@dataclass
class IAMGroup:
    """Represents an IAM group."""
    arn: str
    name: str
    group_id: str
    path: str = "/"
    create_date: Optional[datetime] = None
    attached_policies: List[str] = field(default_factory=list)
    inline_policies: Dict[str, Dict] = field(default_factory=dict)


@dataclass
class IAMGraph:
    """Represents the complete IAM graph with all relationships."""
    users: Dict[str, IAMUser] = field(default_factory=dict)
    roles: Dict[str, IAMRole] = field(default_factory=dict)
    groups: Dict[str, IAMGroup] = field(default_factory=dict)
    policies: Dict[str, IAMPolicy] = field(default_factory=dict)
    graph: nx.DiGraph = field(default_factory=nx.DiGraph)

    def add_user(self, user: IAMUser):
        """Add a user to the graph."""
        self.users[user.arn] = user
        self.graph.add_node(user.arn, type="user", name=user.name, data=user)

    def add_role(self, role: IAMRole):
        """Add a role to the graph."""
        self.roles[role.arn] = role
        self.graph.add_node(role.arn, type="role", name=role.name, data=role)

    def add_group(self, group: IAMGroup):
        """Add a group to the graph."""
        self.groups[group.arn] = group
        self.graph.add_node(group.arn, type="group", name=group.name, data=group)

    def add_policy(self, policy: IAMPolicy):
        """Add a policy to the graph."""
        self.policies[policy.arn] = policy
        self.graph.add_node(policy.arn, type="policy", name=policy.name, data=policy)

    def add_relationship(self, source: str, target: str, relationship_type: str, **kwargs):
        """Add a relationship between two entities."""
        self.graph.add_edge(source, target, type=relationship_type, **kwargs)

    def get_entity_by_name(self, name: str) -> Optional[Any]:
        """Get an entity by its name."""
        for entity_dict in [self.users, self.roles, self.groups]:
            for entity in entity_dict.values():
                if entity.name == name:
                    return entity
        return None

    def get_policies_for_entity(self, entity_arn: str) -> List[IAMPolicy]:
        """Get all policies attached to an entity."""
        policies = []

        # Direct policy attachments
        for edge in self.graph.edges(entity_arn, data=True):
            if edge[2].get("type") == "attached_policy":
                policy_arn = edge[1]
                if policy_arn in self.policies:
                    policies.append(self.policies[policy_arn])

        return policies
