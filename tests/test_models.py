"""
Tests for IAM Explorer models.
"""

import pytest
from datetime import datetime

from iam_explorer.models import IAMUser, IAMRole, IAMGroup, IAMPolicy, IAMGraph


class TestIAMPolicy:
    """Test IAMPolicy model."""
    
    def test_policy_creation(self):
        """Test basic policy creation."""
        policy_doc = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "s3:GetObject",
                    "Resource": "*"
                }
            ]
        }
        
        policy = IAMPolicy(
            arn="arn:aws:iam::123456789012:policy/test-policy",
            name="test-policy",
            policy_document=policy_doc
        )
        
        assert policy.arn == "arn:aws:iam::123456789012:policy/test-policy"
        assert policy.name == "test-policy"
        assert policy.policy_document == policy_doc
        assert not policy.is_aws_managed
    
    def test_get_allowed_actions(self):
        """Test extracting allowed actions from policy."""
        policy_doc = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": ["s3:GetObject", "s3:PutObject"],
                    "Resource": "*"
                },
                {
                    "Effect": "Allow",
                    "Action": "ec2:DescribeInstances",
                    "Resource": "*"
                }
            ]
        }
        
        policy = IAMPolicy(
            arn="arn:aws:iam::123456789012:policy/test-policy",
            name="test-policy",
            policy_document=policy_doc
        )
        
        allowed_actions = policy.get_allowed_actions()
        expected_actions = {"s3:GetObject", "s3:PutObject", "ec2:DescribeInstances"}
        
        assert allowed_actions == expected_actions
    
    def test_get_denied_actions(self):
        """Test extracting denied actions from policy."""
        policy_doc = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "s3:*",
                    "Resource": "*"
                },
                {
                    "Effect": "Deny",
                    "Action": "s3:DeleteObject",
                    "Resource": "*"
                }
            ]
        }
        
        policy = IAMPolicy(
            arn="arn:aws:iam::123456789012:policy/test-policy",
            name="test-policy",
            policy_document=policy_doc
        )
        
        denied_actions = policy.get_denied_actions()
        assert "s3:DeleteObject" in denied_actions


class TestIAMRole:
    """Test IAMRole model."""
    
    def test_role_creation(self):
        """Test basic role creation."""
        assume_role_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {
                        "Service": "ec2.amazonaws.com"
                    },
                    "Action": "sts:AssumeRole"
                }
            ]
        }
        
        role = IAMRole(
            arn="arn:aws:iam::123456789012:role/test-role",
            name="test-role",
            role_id="AROAEXAMPLE123456789",
            assume_role_policy=assume_role_policy
        )
        
        assert role.arn == "arn:aws:iam::123456789012:role/test-role"
        assert role.name == "test-role"
        assert role.assume_role_policy == assume_role_policy
    
    def test_get_trusted_entities(self):
        """Test extracting trusted entities from assume role policy."""
        assume_role_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {
                        "AWS": [
                            "arn:aws:iam::123456789012:user/test-user",
                            "arn:aws:iam::123456789012:role/another-role"
                        ],
                        "Service": "ec2.amazonaws.com"
                    },
                    "Action": "sts:AssumeRole"
                }
            ]
        }
        
        role = IAMRole(
            arn="arn:aws:iam::123456789012:role/test-role",
            name="test-role",
            role_id="AROAEXAMPLE123456789",
            assume_role_policy=assume_role_policy
        )
        
        trusted_entities = role.get_trusted_entities()
        expected_entities = {
            "arn:aws:iam::123456789012:user/test-user",
            "arn:aws:iam::123456789012:role/another-role",
            "ec2.amazonaws.com"
        }
        
        assert trusted_entities == expected_entities


class TestIAMGraph:
    """Test IAMGraph model."""
    
    def test_graph_creation(self):
        """Test basic graph creation."""
        graph = IAMGraph()
        
        assert len(graph.users) == 0
        assert len(graph.roles) == 0
        assert len(graph.groups) == 0
        assert len(graph.policies) == 0
        assert len(graph.graph.nodes) == 0
    
    def test_add_entities(self):
        """Test adding entities to graph."""
        graph = IAMGraph()
        
        # Add user
        user = IAMUser(
            arn="arn:aws:iam::123456789012:user/test-user",
            name="test-user",
            user_id="AIDAEXAMPLE123456789"
        )
        graph.add_user(user)
        
        # Add role
        role = IAMRole(
            arn="arn:aws:iam::123456789012:role/test-role",
            name="test-role",
            role_id="AROAEXAMPLE123456789"
        )
        graph.add_role(role)
        
        # Add policy
        policy = IAMPolicy(
            arn="arn:aws:iam::123456789012:policy/test-policy",
            name="test-policy",
            policy_document={"Version": "2012-10-17", "Statement": []}
        )
        graph.add_policy(policy)
        
        assert len(graph.users) == 1
        assert len(graph.roles) == 1
        assert len(graph.policies) == 1
        assert len(graph.graph.nodes) == 3
    
    def test_add_relationships(self):
        """Test adding relationships to graph."""
        graph = IAMGraph()
        
        # Add entities
        user = IAMUser(
            arn="arn:aws:iam::123456789012:user/test-user",
            name="test-user",
            user_id="AIDAEXAMPLE123456789"
        )
        graph.add_user(user)
        
        policy = IAMPolicy(
            arn="arn:aws:iam::123456789012:policy/test-policy",
            name="test-policy",
            policy_document={"Version": "2012-10-17", "Statement": []}
        )
        graph.add_policy(policy)
        
        # Add relationship
        graph.add_relationship(user.arn, policy.arn, "attached_policy")
        
        assert len(graph.graph.edges) == 1
        
        # Check relationship exists
        edge_data = graph.graph.get_edge_data(user.arn, policy.arn)
        assert edge_data['type'] == "attached_policy"
    
    def test_get_entity_by_name(self):
        """Test finding entities by name."""
        graph = IAMGraph()
        
        user = IAMUser(
            arn="arn:aws:iam::123456789012:user/test-user",
            name="test-user",
            user_id="AIDAEXAMPLE123456789"
        )
        graph.add_user(user)
        
        found_entity = graph.get_entity_by_name("test-user")
        assert found_entity is not None
        assert found_entity.name == "test-user"
        assert found_entity.arn == user.arn
        
        # Test non-existent entity
        not_found = graph.get_entity_by_name("non-existent")
        assert not_found is None
