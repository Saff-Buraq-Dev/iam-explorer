"""
Query engine for IAM permission analysis.
"""

import re
import logging
from typing import Dict, List, Optional, Any
from fnmatch import fnmatch

from .models import IAMGraph, IAMRole, IAMPolicy

logger = logging.getLogger(__name__)


class QueryEngine:
    """Engine for querying IAM permissions and relationships."""

    def __init__(self, graph: IAMGraph):
        """
        Initialize the query engine.

        Args:
            graph: IAMGraph object containing all IAM relationships
        """
        self.graph = graph

    def who_can_do(self, action: str, resource: str = "*") -> List[Dict[str, Any]]:
        """
        Find all entities that can perform a specific action.

        Args:
            action: AWS action (e.g., 's3:GetObject', 's3:*')
            resource: Resource ARN or pattern (default: '*')

        Returns:
            List of entities that can perform the action
        """
        logger.info(f"Querying who can do action: {action} on resource: {resource}")

        results = []

        # Check all users
        for user_arn, user in self.graph.users.items():
            if self._can_entity_do_action(user_arn, action, resource):
                results.append({
                    "type": "user",
                    "arn": user_arn,
                    "name": user.name,
                    "path": self._get_permission_path(user_arn, action, resource)
                })

        # Check all roles
        for role_arn, role in self.graph.roles.items():
            if self._can_entity_do_action(role_arn, action, resource):
                # Also check who can assume this role
                assumers = self._who_can_assume_role(role_arn)
                results.append({
                    "type": "role",
                    "arn": role_arn,
                    "name": role.name,
                    "path": self._get_permission_path(role_arn, action, resource),
                    "can_be_assumed_by": assumers
                })

        logger.info(f"Found {len(results)} entities that can perform {action}")
        return results

    def what_can_entity_do(self, entity_name: str) -> Dict[str, Any]:
        """
        Find all actions an entity can perform.

        Args:
            entity_name: Name of the user, role, or group

        Returns:
            Dictionary containing all allowed and denied actions
        """
        logger.info(f"Querying what {entity_name} can do")

        entity = self.graph.get_entity_by_name(entity_name)
        if not entity:
            return {"error": f"Entity '{entity_name}' not found"}

        entity_arn = entity.arn
        allowed_actions = set()
        denied_actions = set()

        # Get all policies for this entity
        policies = self._get_all_policies_for_entity(entity_arn)

        for policy in policies:
            allowed_actions.update(policy.get_allowed_actions())
            denied_actions.update(policy.get_denied_actions())

        # If it's a role, also check what roles it can assume
        assumable_roles = []
        if isinstance(entity, IAMRole):
            assumable_roles = self._get_assumable_roles(entity_arn)

        return {
            "entity_name": entity_name,
            "entity_type": type(entity).__name__.replace("IAM", "").lower(),
            "entity_arn": entity_arn,
            "allowed_actions": sorted(list(allowed_actions)),
            "denied_actions": sorted(list(denied_actions)),
            "effective_actions": sorted(list(allowed_actions - denied_actions)),
            "assumable_roles": assumable_roles,
            "policies_applied": len(policies)
        }

    def get_permission_path(self, entity_name: str, action: str, resource: str = "*") -> List[str]:
        """
        Get the path of permissions that allow an entity to perform an action.

        Args:
            entity_name: Name of the entity
            action: AWS action
            resource: Resource ARN or pattern

        Returns:
            List of permission paths
        """
        entity = self.graph.get_entity_by_name(entity_name)
        if not entity:
            return []

        return self._get_permission_path(entity.arn, action, resource)

    def _can_entity_do_action(self, entity_arn: str, action: str, resource: str = "*") -> bool:
        """Check if an entity can perform a specific action."""
        # Get all policies for this entity
        policies = self._get_all_policies_for_entity(entity_arn)

        # Check if action is allowed
        is_allowed = False
        is_denied = False

        for policy in policies:
            # Check for explicit allow
            if self._policy_allows_action(policy, action, resource):
                is_allowed = True

            # Check for explicit deny
            if self._policy_denies_action(policy, action, resource):
                is_denied = True

        # Deny always wins
        return is_allowed and not is_denied

    def _get_all_policies_for_entity(self, entity_arn: str) -> List[IAMPolicy]:
        """Get all policies that apply to an entity (direct, group, inline)."""
        policies = []

        # Direct attached policies
        policies.extend(self.graph.get_policies_for_entity(entity_arn))

        # If it's a user, also get group policies
        if entity_arn in self.graph.users:
            user = self.graph.users[entity_arn]
            for group_name in user.groups:
                group_arn = self._find_group_arn_by_name(group_name)
                if group_arn:
                    policies.extend(self.graph.get_policies_for_entity(group_arn))

        # Add inline policies
        entity = self._get_entity_by_arn(entity_arn)
        if entity and hasattr(entity, 'inline_policies'):
            for policy_name, policy_doc in entity.inline_policies.items():
                inline_policy = IAMPolicy(
                    arn=f"{entity_arn}/inline/{policy_name}",
                    name=policy_name,
                    policy_document=policy_doc,
                    is_aws_managed=False
                )
                policies.append(inline_policy)

        return policies

    def _policy_allows_action(self, policy: IAMPolicy, action: str, resource: str = "*") -> bool:
        """Check if a policy allows a specific action."""
        statements = policy.policy_document.get("Statement", [])

        for statement in statements:
            if statement.get("Effect") == "Allow":
                if self._statement_matches_action(statement, action, resource):
                    return True

        return False

    def _policy_denies_action(self, policy: IAMPolicy, action: str, resource: str = "*") -> bool:
        """Check if a policy denies a specific action."""
        statements = policy.policy_document.get("Statement", [])

        for statement in statements:
            if statement.get("Effect") == "Deny":
                if self._statement_matches_action(statement, action, resource):
                    return True

        return False

    def _statement_matches_action(self, statement: Dict[str, Any], action: str, resource: str = "*") -> bool:
        """Check if a statement matches the given action and resource."""
        # Check action
        statement_actions = statement.get("Action", [])
        if isinstance(statement_actions, str):
            statement_actions = [statement_actions]

        action_matches = False
        for stmt_action in statement_actions:
            if self._action_matches(stmt_action, action):
                action_matches = True
                break

        if not action_matches:
            return False

        # Check resource
        statement_resources = statement.get("Resource", ["*"])
        if isinstance(statement_resources, str):
            statement_resources = [statement_resources]

        for stmt_resource in statement_resources:
            if self._resource_matches(stmt_resource, resource):
                return True

        return False

    def _action_matches(self, policy_action: str, query_action: str) -> bool:
        """Check if a policy action matches a query action."""
        # If query action has wildcards, check if policy action matches the pattern
        if "*" in query_action:
            query_pattern = query_action.replace("*", ".*")
            return bool(re.match(f"^{query_pattern}$", policy_action, re.IGNORECASE))

        # If policy action has wildcards, check if it covers the query action
        if "*" in policy_action:
            policy_pattern = policy_action.replace("*", ".*")
            return bool(re.match(f"^{policy_pattern}$", query_action, re.IGNORECASE))

        # Exact match
        return policy_action.lower() == query_action.lower()

    def _resource_matches(self, pattern: str, resource: str) -> bool:
        """Check if a resource pattern matches a specific resource."""
        if pattern == "*" or resource == "*":
            return True

        # Use fnmatch for wildcard matching
        return fnmatch(resource, pattern)

    def _get_permission_path(self, entity_arn: str, action: str, resource: str = "*") -> List[str]:
        """Get the path of permissions that allow an action."""
        paths = []
        policies = self._get_all_policies_for_entity(entity_arn)

        for policy in policies:
            if self._policy_allows_action(policy, action, resource):
                paths.append(f"Policy: {policy.name} ({policy.arn})")

        return paths

    def _who_can_assume_role(self, role_arn: str) -> List[str]:
        """Find who can assume a specific role."""
        assumers = []

        # Look for incoming "can_assume" edges
        for edge in self.graph.graph.in_edges(role_arn, data=True):
            if edge[2].get("type") == "can_assume":
                source_arn = edge[0]
                if source_arn in self.graph.users:
                    assumers.append(f"User: {self.graph.users[source_arn].name}")
                elif source_arn in self.graph.roles:
                    assumers.append(f"Role: {self.graph.roles[source_arn].name}")
                else:
                    assumers.append(f"Service/Other: {source_arn}")

        return assumers

    def _get_assumable_roles(self, entity_arn: str) -> List[str]:
        """Get roles that an entity can assume."""
        assumable = []

        # Look for outgoing "can_assume" edges
        for edge in self.graph.graph.out_edges(entity_arn, data=True):
            if edge[2].get("type") == "can_assume":
                target_arn = edge[1]
                if target_arn in self.graph.roles:
                    assumable.append(f"Role: {self.graph.roles[target_arn].name}")

        return assumable

    def _find_group_arn_by_name(self, group_name: str) -> Optional[str]:
        """Find group ARN by name."""
        for arn, group in self.graph.groups.items():
            if group.name == group_name:
                return arn
        return None

    def _get_entity_by_arn(self, arn: str) -> Optional[Any]:
        """Get entity by ARN."""
        if arn in self.graph.users:
            return self.graph.users[arn]
        elif arn in self.graph.roles:
            return self.graph.roles[arn]
        elif arn in self.graph.groups:
            return self.graph.groups[arn]
        return None
