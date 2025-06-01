"""
Tests for IAM Explorer query engine.
"""

import pytest
from iam_explorer.models import IAMUser, IAMRole, IAMPolicy, IAMGraph
from iam_explorer.query_engine import QueryEngine


class TestQueryEngine:
    """Test QueryEngine functionality."""

    @pytest.fixture
    def sample_graph(self):
        """Create a sample IAM graph for testing."""
        graph = IAMGraph()

        # Create a policy that allows S3 access
        s3_policy = IAMPolicy(
            arn="arn:aws:iam::123456789012:policy/s3-access",
            name="s3-access",
            policy_document={
                "Version": "2012-10-17",
                "Statement": [{"Effect": "Allow", "Action": ["s3:GetObject", "s3:PutObject"], "Resource": "*"}],
            },
        )
        graph.add_policy(s3_policy)

        # Create a policy that denies S3 delete
        s3_deny_policy = IAMPolicy(
            arn="arn:aws:iam::123456789012:policy/s3-deny-delete",
            name="s3-deny-delete",
            policy_document={
                "Version": "2012-10-17",
                "Statement": [{"Effect": "Deny", "Action": "s3:DeleteObject", "Resource": "*"}],
            },
        )
        graph.add_policy(s3_deny_policy)

        # Create a user with S3 access
        user = IAMUser(arn="arn:aws:iam::123456789012:user/test-user", name="test-user", user_id="AIDAEXAMPLE123456789")
        graph.add_user(user)

        # Create a role that can be assumed by the user
        role = IAMRole(
            arn="arn:aws:iam::123456789012:role/test-role",
            name="test-role",
            role_id="AROAEXAMPLE123456789",
            assume_role_policy={
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"AWS": "arn:aws:iam::123456789012:user/test-user"},
                        "Action": "sts:AssumeRole",
                    }
                ],
            },
        )
        graph.add_role(role)

        # Add relationships
        graph.add_relationship(user.arn, s3_policy.arn, "attached_policy")
        graph.add_relationship(role.arn, s3_policy.arn, "attached_policy")
        graph.add_relationship(role.arn, s3_deny_policy.arn, "attached_policy")
        graph.add_relationship(user.arn, role.arn, "can_assume")

        return graph

    def test_query_engine_creation(self, sample_graph):
        """Test creating a query engine."""
        engine = QueryEngine(sample_graph)
        assert engine.graph == sample_graph

    def test_who_can_do_basic(self, sample_graph):
        """Test basic who-can-do query."""
        engine = QueryEngine(sample_graph)

        results = engine.who_can_do("s3:GetObject")

        # Should find both user and role
        assert len(results) == 2

        # Check that we found the user
        user_result = next((r for r in results if r["type"] == "user"), None)
        assert user_result is not None
        assert user_result["name"] == "test-user"

        # Check that we found the role
        role_result = next((r for r in results if r["type"] == "role"), None)
        assert role_result is not None
        assert role_result["name"] == "test-role"

    def test_who_can_do_with_deny(self, sample_graph):
        """Test who-can-do query with deny policy."""
        engine = QueryEngine(sample_graph)

        # User should be able to do GetObject (allowed, not denied)
        results = engine.who_can_do("s3:GetObject")
        user_result = next((r for r in results if r["type"] == "user"), None)
        assert user_result is not None

        # Role should NOT be able to do DeleteObject (denied)
        results = engine.who_can_do("s3:DeleteObject")
        role_result = next((r for r in results if r["type"] == "role"), None)
        assert role_result is None  # Should not be found due to deny policy

    def test_what_can_entity_do(self, sample_graph):
        """Test what-can-entity-do query."""
        engine = QueryEngine(sample_graph)

        result = engine.what_can_entity_do("test-user")

        assert result["entity_name"] == "test-user"
        assert result["entity_type"] == "user"
        assert "s3:GetObject" in result["allowed_actions"]
        assert "s3:PutObject" in result["allowed_actions"]
        assert len(result["denied_actions"]) == 0  # User has no deny policies

    def test_what_can_entity_do_with_deny(self, sample_graph):
        """Test what-can-entity-do query with deny policies."""
        engine = QueryEngine(sample_graph)

        result = engine.what_can_entity_do("test-role")

        assert result["entity_name"] == "test-role"
        assert result["entity_type"] == "role"
        assert "s3:GetObject" in result["allowed_actions"]
        assert "s3:PutObject" in result["allowed_actions"]
        assert "s3:DeleteObject" in result["denied_actions"]

        # Effective actions should not include denied actions
        assert "s3:DeleteObject" not in result["effective_actions"]
        assert "s3:GetObject" in result["effective_actions"]

    def test_entity_not_found(self, sample_graph):
        """Test querying non-existent entity."""
        engine = QueryEngine(sample_graph)

        result = engine.what_can_entity_do("non-existent-user")

        assert "error" in result
        assert "not found" in result["error"]

    def test_action_matching(self, sample_graph):
        """Test action pattern matching."""
        engine = QueryEngine(sample_graph)

        # Test wildcard matching
        results = engine.who_can_do("s3:*")
        assert len(results) >= 1  # Should match s3:GetObject and s3:PutObject

        # Test exact matching
        results = engine.who_can_do("s3:GetObject")
        assert len(results) >= 1

        # Test non-matching action
        results = engine.who_can_do("ec2:DescribeInstances")
        assert len(results) == 0  # No entities have EC2 permissions

    def test_get_permission_path(self, sample_graph):
        """Test getting permission paths."""
        engine = QueryEngine(sample_graph)

        paths = engine.get_permission_path("test-user", "s3:GetObject")

        assert len(paths) > 0
        assert any("s3-access" in path for path in paths)

    def test_role_assumption_tracking(self, sample_graph):
        """Test tracking who can assume roles."""
        engine = QueryEngine(sample_graph)

        results = engine.who_can_do("s3:GetObject")
        role_result = next((r for r in results if r["type"] == "role"), None)

        assert role_result is not None
        assert "can_be_assumed_by" in role_result
        assert len(role_result["can_be_assumed_by"]) > 0
        assert any("test-user" in assumer for assumer in role_result["can_be_assumed_by"])
