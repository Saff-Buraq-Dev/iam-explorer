"""
Graph builder for IAM relationships using NetworkX.
"""

import json
import logging
import pickle
from typing import Dict, List, Any, Optional
from datetime import datetime

from .models import IAMUser, IAMRole, IAMGroup, IAMPolicy, IAMGraph

logger = logging.getLogger(__name__)


class GraphBuilder:
    """Builds a graph representation of IAM relationships."""

    def __init__(self):
        """Initialize the graph builder."""
        self.graph = IAMGraph()

    def build_from_data(self, data: Dict[str, Any]) -> IAMGraph:
        """
        Build IAM graph from fetched data.

        Args:
            data: Dictionary containing IAM data from fetcher

        Returns:
            IAMGraph object with all relationships
        """
        logger.info("Building IAM graph from data...")

        # First pass: Create all entities
        self._create_policies(data.get('policies', []))
        self._create_users(data.get('users', []))
        self._create_roles(data.get('roles', []))
        self._create_groups(data.get('groups', []))

        # Second pass: Create relationships
        self._create_user_relationships(data.get('users', []))
        self._create_role_relationships(data.get('roles', []))
        self._create_group_relationships(data.get('groups', []))

        logger.info(f"Graph built with {len(self.graph.graph.nodes)} nodes and "
                    f"{len(self.graph.graph.edges)} edges")

        return self.graph

    def build_from_file(self, filename: str) -> IAMGraph:
        """
        Build IAM graph from JSON file.

        Args:
            filename: Path to JSON file containing IAM data

        Returns:
            IAMGraph object with all relationships
        """
        logger.info(f"Loading IAM data from {filename}...")

        try:
            with open(filename, 'r') as f:
                data = json.load(f)

            return self.build_from_data(data)

        except Exception as e:
            logger.error(f"Error loading data from {filename}: {e}")
            raise

    def _create_policies(self, policies_data: List[Dict[str, Any]]):
        """Create policy entities."""
        logger.info(f"Creating {len(policies_data)} policies...")

        for policy_data in policies_data:
            policy = IAMPolicy(
                arn=policy_data['arn'],
                name=policy_data['name'],
                policy_document=policy_data['policy_document'],
                is_aws_managed=policy_data.get('is_aws_managed', False),
                description=policy_data.get('description'),
                create_date=datetime.fromisoformat(
                    policy_data['create_date']) if policy_data.get('create_date') else None,
                update_date=datetime.fromisoformat(
                    policy_data['update_date']) if policy_data.get('update_date') else None
            )
            self.graph.add_policy(policy)

    def _create_users(self, users_data: List[Dict[str, Any]]):
        """Create user entities."""
        logger.info(f"Creating {len(users_data)} users...")

        for user_data in users_data:
            user = IAMUser(
                arn=user_data['arn'],
                name=user_data['name'],
                user_id=user_data['user_id'],
                path=user_data.get('path', '/'),
                create_date=datetime.fromisoformat(user_data['create_date']) if user_data.get('create_date') else None,
                password_last_used=datetime.fromisoformat(
                    user_data['password_last_used']) if user_data.get('password_last_used') else None,
                attached_policies=user_data.get('attached_policies', []),
                inline_policies=user_data.get('inline_policies', {}),
                groups=user_data.get('groups', []),
                permission_boundary=user_data.get('permission_boundary'),
                tags={tag.get('Key', ''): tag.get('Value', '') for tag in user_data.get('tags', [])}
            )
            self.graph.add_user(user)

    def _create_roles(self, roles_data: List[Dict[str, Any]]):
        """Create role entities."""
        logger.info(f"Creating {len(roles_data)} roles...")

        for role_data in roles_data:
            role = IAMRole(
                arn=role_data['arn'],
                name=role_data['name'],
                role_id=role_data['role_id'],
                path=role_data.get('path', '/'),
                assume_role_policy=role_data.get('assume_role_policy', {}),
                create_date=datetime.fromisoformat(role_data['create_date']) if role_data.get('create_date') else None,
                max_session_duration=role_data.get('max_session_duration', 3600),
                attached_policies=role_data.get('attached_policies', []),
                inline_policies=role_data.get('inline_policies', {}),
                permission_boundary=role_data.get('permission_boundary'),
                tags={tag.get('Key', ''): tag.get('Value', '') for tag in role_data.get('tags', [])}
            )
            self.graph.add_role(role)

    def _create_groups(self, groups_data: List[Dict[str, Any]]):
        """Create group entities."""
        logger.info(f"Creating {len(groups_data)} groups...")

        for group_data in groups_data:
            group = IAMGroup(
                arn=group_data['arn'],
                name=group_data['name'],
                group_id=group_data['group_id'],
                path=group_data.get('path', '/'),
                create_date=datetime.fromisoformat(
                    group_data['create_date']) if group_data.get('create_date') else None,
                attached_policies=group_data.get('attached_policies', []),
                inline_policies=group_data.get('inline_policies', {})
            )
            self.graph.add_group(group)

    def _create_user_relationships(self, users_data: List[Dict[str, Any]]):
        """Create relationships for users."""
        logger.info("Creating user relationships...")

        for user_data in users_data:
            user_arn = user_data['arn']

            # User -> Policy relationships
            for policy_arn in user_data.get('attached_policies', []):
                if policy_arn in self.graph.policies:
                    self.graph.add_relationship(user_arn, policy_arn, "attached_policy")

            # User -> Group relationships
            for group_name in user_data.get('groups', []):
                # Find group by name
                group_arn = self._find_group_arn_by_name(group_name)
                if group_arn:
                    self.graph.add_relationship(user_arn, group_arn, "member_of")

            # Permission boundary
            if user_data.get('permission_boundary'):
                boundary_arn = user_data['permission_boundary']
                if boundary_arn in self.graph.policies:
                    self.graph.add_relationship(user_arn, boundary_arn, "permission_boundary")

    def _create_role_relationships(self, roles_data: List[Dict[str, Any]]):
        """Create relationships for roles."""
        logger.info("Creating role relationships...")

        for role_data in roles_data:
            role_arn = role_data['arn']
            role = self.graph.roles[role_arn]

            # Role -> Policy relationships
            for policy_arn in role_data.get('attached_policies', []):
                if policy_arn in self.graph.policies:
                    self.graph.add_relationship(role_arn, policy_arn, "attached_policy")

            # Trust relationships (who can assume this role)
            trusted_entities = role.get_trusted_entities()
            for trusted_entity in trusted_entities:
                # Handle different types of trusted entities
                if trusted_entity.startswith('arn:aws:iam::'):
                    # It's an IAM entity
                    if trusted_entity in self.graph.users or trusted_entity in self.graph.roles:
                        self.graph.add_relationship(trusted_entity, role_arn, "can_assume")
                elif trusted_entity == '*':
                    # Anyone can assume (dangerous!)
                    self.graph.add_relationship("*", role_arn, "can_assume")
                else:
                    # Service principal or other
                    self.graph.add_relationship(trusted_entity, role_arn, "can_assume")

            # Permission boundary
            if role_data.get('permission_boundary'):
                boundary_arn = role_data['permission_boundary']
                if boundary_arn in self.graph.policies:
                    self.graph.add_relationship(role_arn, boundary_arn, "permission_boundary")

    def _create_group_relationships(self, groups_data: List[Dict[str, Any]]):
        """Create relationships for groups."""
        logger.info("Creating group relationships...")

        for group_data in groups_data:
            group_arn = group_data['arn']

            # Group -> Policy relationships
            for policy_arn in group_data.get('attached_policies', []):
                if policy_arn in self.graph.policies:
                    self.graph.add_relationship(group_arn, policy_arn, "attached_policy")

    def _find_group_arn_by_name(self, group_name: str) -> Optional[str]:
        """Find group ARN by name."""
        for arn, group in self.graph.groups.items():
            if group.name == group_name:
                return arn
        return None

    def save_graph(self, filename: str):
        """Save the graph to a pickle file."""
        try:
            with open(filename, 'wb') as f:
                pickle.dump(self.graph, f)
            logger.info(f"Graph saved to {filename}")
        except Exception as e:
            logger.error(f"Error saving graph to {filename}: {e}")
            raise

    def load_graph(self, filename: str) -> IAMGraph:
        """Load a graph from a pickle file."""
        try:
            with open(filename, 'rb') as f:
                self.graph = pickle.load(f)
            logger.info(f"Graph loaded from {filename}")
            return self.graph
        except Exception as e:
            logger.error(f"Error loading graph from {filename}: {e}")
            raise
