"""
Tests for the graph builder module.
"""

import pytest
from unittest.mock import patch, mock_open
import json
from datetime import datetime

from iam_explorer.graph_builder import GraphBuilder
from iam_explorer.models import IAMUser, IAMRole, IAMGroup, IAMPolicy, IAMGraph


class TestGraphBuilder:
    """Test cases for GraphBuilder class."""

    def setup_method(self):
        """Set up test fixtures."""
        self.builder = GraphBuilder()

        # Sample IAM data
        self.sample_data = {
            "users": [
                {
                    "UserName": "alice",
                    "UserId": "AIDACKCEVSQ6C2EXAMPLE",
                    "Arn": "arn:aws:iam::123456789012:user/alice",
                    "CreateDate": datetime(2023, 1, 1),
                    "Path": "/",
                }
            ],
            "roles": [
                {
                    "RoleName": "test-role",
                    "RoleId": "AROA123456789EXAMPLE",
                    "Arn": "arn:aws:iam::123456789012:role/test-role",
                    "CreateDate": datetime(2023, 1, 1),
                    "AssumeRolePolicyDocument": json.dumps(
                        {
                            "Version": "2012-10-17",
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Principal": {"AWS": "arn:aws:iam::123456789012:user/alice"},
                                    "Action": "sts:AssumeRole",
                                }
                            ],
                        }
                    ),
                    "Path": "/",
                }
            ],
            "groups": [
                {
                    "GroupName": "developers",
                    "GroupId": "AGPA123456789EXAMPLE",
                    "Arn": "arn:aws:iam::123456789012:group/developers",
                    "CreateDate": datetime(2023, 1, 1),
                    "Path": "/",
                }
            ],
            "policies": [
                {
                    "PolicyName": "TestPolicy",
                    "PolicyId": "ANPA123456789EXAMPLE",
                    "Arn": "arn:aws:iam::123456789012:policy/TestPolicy",
                    "CreateDate": datetime(2023, 1, 1),
                    "DefaultVersionId": "v1",
                    "IsAttachable": True,
                }
            ],
            "user_policies": {
                "alice": {
                    "attached_policies": [
                        {"PolicyName": "TestPolicy", "PolicyArn": "arn:aws:iam::123456789012:policy/TestPolicy"}
                    ],
                    "inline_policies": [
                        {
                            "PolicyName": "InlinePolicy",
                            "PolicyDocument": json.dumps(
                                {
                                    "Version": "2012-10-17",
                                    "Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}],
                                }
                            ),
                        }
                    ],
                }
            },
            "role_policies": {"test-role": {"attached_policies": [], "inline_policies": []}},
            "group_policies": {"developers": {"attached_policies": [], "inline_policies": []}},
            "group_memberships": [{"GroupName": "developers", "UserName": "alice"}],
        }

    def test_graph_builder_initialization(self):
        """Test GraphBuilder initialization."""
        builder = GraphBuilder()
        assert isinstance(builder.graph, IAMGraph)
        assert len(builder.graph.graph.nodes) == 0
        assert len(builder.graph.graph.edges) == 0

    def test_build_from_data_complete(self):
        """Test building graph from complete data."""
        # First, let's create proper test data that matches the expected format
        test_data = {
            "users": [
                {
                    "arn": "arn:aws:iam::123456789012:user/alice",
                    "name": "alice",
                    "user_id": "AIDACKCEVSQ6C2EXAMPLE",
                    "create_date": "2023-01-01T00:00:00",
                    "attached_policies": [],
                    "groups": [],
                }
            ],
            "roles": [
                {
                    "arn": "arn:aws:iam::123456789012:role/test-role",
                    "name": "test-role",
                    "role_id": "AROA123456789EXAMPLE",
                    "create_date": "2023-01-01T00:00:00",
                    "assume_role_policy": {},
                    "attached_policies": [],
                }
            ],
            "groups": [
                {
                    "arn": "arn:aws:iam::123456789012:group/developers",
                    "name": "developers",
                    "group_id": "AGPA123456789EXAMPLE",
                    "create_date": "2023-01-01T00:00:00",
                    "attached_policies": [],
                }
            ],
            "policies": [
                {
                    "arn": "arn:aws:iam::123456789012:policy/TestPolicy",
                    "name": "TestPolicy",
                    "policy_document": {},
                    "create_date": "2023-01-01T00:00:00",
                }
            ],
        }

        graph = self.builder.build_from_data(test_data)

        # Check that all entities were added
        assert isinstance(graph, IAMGraph)

        # Check that entities were created
        assert len(graph.users) > 0
        assert len(graph.roles) > 0
        assert len(graph.groups) > 0
        assert len(graph.policies) > 0

    def test_create_users(self):
        """Test creating users."""
        users_data = [
            {
                "arn": "arn:aws:iam::123456789012:user/alice",
                "name": "alice",
                "user_id": "AIDACKCEVSQ6C2EXAMPLE",
                "create_date": "2023-01-01T00:00:00",
            }
        ]

        self.builder._create_users(users_data)

        # Check user was added
        assert "arn:aws:iam::123456789012:user/alice" in self.builder.graph.users

        # Check user data
        user = self.builder.graph.users["arn:aws:iam::123456789012:user/alice"]
        assert isinstance(user, IAMUser)
        assert user.name == "alice"

    def test_add_roles_to_graph(self):
        """Test adding roles to graph."""
        self.builder._add_roles_to_graph(self.sample_data["roles"])

        # Check role was added
        assert "test-role" in self.builder.graph.nodes

        # Check role data
        role_data = self.builder.graph.nodes["test-role"]
        assert role_data["type"] == "role"
        assert isinstance(role_data["data"], IAMRole)
        assert role_data["data"].name == "test-role"

    def test_add_groups_to_graph(self):
        """Test adding groups to graph."""
        self.builder._add_groups_to_graph(self.sample_data["groups"])

        # Check group was added
        assert "developers" in self.builder.graph.nodes

        # Check group data
        group_data = self.builder.graph.nodes["developers"]
        assert group_data["type"] == "group"
        assert isinstance(group_data["data"], IAMGroup)
        assert group_data["data"].name == "developers"

    def test_add_policies_to_graph(self):
        """Test adding policies to graph."""
        self.builder._add_policies_to_graph(self.sample_data["policies"])

        # Check policy was added
        assert "TestPolicy" in self.builder.graph.nodes

        # Check policy data
        policy_data = self.builder.graph.nodes["TestPolicy"]
        assert policy_data["type"] == "policy"
        assert isinstance(policy_data["data"], IAMPolicy)
        assert policy_data["data"].name == "TestPolicy"

    def test_add_policy_attachments(self):
        """Test adding policy attachments."""
        # First add entities
        self.builder._add_users_to_graph(self.sample_data["users"])
        self.builder._add_policies_to_graph(self.sample_data["policies"])

        # Add policy attachments
        self.builder._add_policy_attachments(
            self.sample_data["user_policies"], self.sample_data["role_policies"], self.sample_data["group_policies"]
        )

        # Check that policy attachment edge exists
        assert self.builder.graph.has_edge("alice", "TestPolicy")

        # Check edge data
        edge_data = self.builder.graph.edges["alice", "TestPolicy"]
        assert edge_data["type"] == "attached_policy"

    def test_add_group_memberships(self):
        """Test adding group memberships."""
        # First add entities
        self.builder._add_users_to_graph(self.sample_data["users"])
        self.builder._add_groups_to_graph(self.sample_data["groups"])

        # Add group memberships
        self.builder._add_group_memberships(self.sample_data["group_memberships"])

        # Check that membership edge exists
        assert self.builder.graph.has_edge("alice", "developers")

        # Check edge data
        edge_data = self.builder.graph.edges["alice", "developers"]
        assert edge_data["type"] == "member_of"

    def test_add_trust_relationships(self):
        """Test adding trust relationships."""
        # First add entities
        self.builder._add_users_to_graph(self.sample_data["users"])
        self.builder._add_roles_to_graph(self.sample_data["roles"])

        # Add trust relationships
        self.builder._add_trust_relationships()

        # Check that trust relationship edge exists
        assert self.builder.graph.has_edge("alice", "test-role")

        # Check edge data
        edge_data = self.builder.graph.edges["alice", "test-role"]
        assert edge_data["type"] == "can_assume"

    def test_parse_trust_policy_valid(self):
        """Test parsing valid trust policy."""
        trust_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": "arn:aws:iam::123456789012:user/alice"},
                    "Action": "sts:AssumeRole",
                }
            ],
        }

        trusted_entities = self.builder._parse_trust_policy(trust_policy)
        assert "alice" in trusted_entities

    def test_parse_trust_policy_multiple_principals(self):
        """Test parsing trust policy with multiple principals."""
        trust_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {
                        "AWS": ["arn:aws:iam::123456789012:user/alice", "arn:aws:iam::123456789012:user/bob"]
                    },
                    "Action": "sts:AssumeRole",
                }
            ],
        }

        trusted_entities = self.builder._parse_trust_policy(trust_policy)
        assert "alice" in trusted_entities
        assert "bob" in trusted_entities

    def test_parse_trust_policy_service_principal(self):
        """Test parsing trust policy with service principal."""
        trust_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
            ],
        }

        trusted_entities = self.builder._parse_trust_policy(trust_policy)
        assert "lambda.amazonaws.com" in trusted_entities

    def test_parse_trust_policy_invalid_json(self):
        """Test parsing invalid trust policy."""
        invalid_policy = "invalid json"
        trusted_entities = self.builder._parse_trust_policy(invalid_policy)
        assert trusted_entities == []

    def test_extract_entity_name_from_arn_user(self):
        """Test extracting entity name from user ARN."""
        arn = "arn:aws:iam::123456789012:user/alice"
        name = self.builder._extract_entity_name_from_arn(arn)
        assert name == "alice"

    def test_extract_entity_name_from_arn_role(self):
        """Test extracting entity name from role ARN."""
        arn = "arn:aws:iam::123456789012:role/test-role"
        name = self.builder._extract_entity_name_from_arn(arn)
        assert name == "test-role"

    def test_extract_entity_name_from_arn_invalid(self):
        """Test extracting entity name from invalid ARN."""
        invalid_arn = "not-an-arn"
        name = self.builder._extract_entity_name_from_arn(invalid_arn)
        assert name is None

    def test_save_graph(self):
        """Test saving graph to file."""
        # Build a simple graph
        graph = self.builder.build_from_data(self.sample_data)

        with patch("builtins.open", mock_open()) as mock_file:
            with patch("pickle.dump") as mock_pickle:
                self.builder.save_graph(graph, "test_graph.pkl")

                mock_file.assert_called_once_with("test_graph.pkl", "wb")
                mock_pickle.assert_called_once()

    def test_load_graph(self):
        """Test loading graph from file."""
        # Create a mock graph
        mock_graph = IAMGraph()

        with patch("builtins.open", mock_open()) as mock_file:
            with patch("pickle.load", return_value=mock_graph) as mock_pickle:
                loaded_graph = self.builder.load_graph("test_graph.pkl")

                mock_file.assert_called_once_with("test_graph.pkl", "rb")
                mock_pickle.assert_called_once()
                assert loaded_graph == mock_graph

    def test_load_graph_file_not_found(self):
        """Test loading graph when file doesn't exist."""
        with patch("builtins.open", side_effect=FileNotFoundError()):
            with pytest.raises(Exception) as exc_info:
                self.builder.load_graph("nonexistent.pkl")

            assert "Error loading graph" in str(exc_info.value)

    def test_build_from_file(self):
        """Test building graph from JSON file."""
        with patch("builtins.open", mock_open(read_data=json.dumps(self.sample_data))):
            with patch("json.load", return_value=self.sample_data):
                graph = self.builder.build_from_file("test_data.json")

                assert isinstance(graph, IAMGraph)
                assert len(graph.graph.nodes) > 0

    def test_build_from_file_not_found(self):
        """Test building graph when file doesn't exist."""
        with patch("builtins.open", side_effect=FileNotFoundError()):
            with pytest.raises(Exception) as exc_info:
                self.builder.build_from_file("nonexistent.json")

            assert "Error loading data" in str(exc_info.value)

    def test_get_graph_statistics(self):
        """Test getting graph statistics."""
        graph = self.builder.build_from_data(self.sample_data)
        stats = self.builder.get_graph_statistics(graph)

        assert "total_nodes" in stats
        assert "total_edges" in stats
        assert "node_types" in stats
        assert "edge_types" in stats

        assert stats["total_nodes"] > 0
        assert isinstance(stats["node_types"], dict)
        assert isinstance(stats["edge_types"], dict)

    def test_validate_graph_structure(self):
        """Test graph structure validation."""
        graph = self.builder.build_from_data(self.sample_data)

        # Should not raise any exceptions for valid graph
        try:
            self.builder._validate_graph_structure(graph)
        except Exception as e:
            pytest.fail(f"Graph validation failed: {e}")

    def test_handle_missing_data_gracefully(self):
        """Test handling missing data sections gracefully."""
        incomplete_data = {
            "users": self.sample_data["users"],
            # Missing other sections
        }

        # Should not raise exceptions
        graph = self.builder.build_from_data(incomplete_data)
        assert isinstance(graph, IAMGraph)
        assert len(graph.graph.nodes) > 0  # Should have at least the user
