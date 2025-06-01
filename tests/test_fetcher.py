"""
Tests for the IAM fetcher module.
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
from botocore.exceptions import ClientError, NoCredentialsError

from iam_explorer.fetcher import IAMFetcher


class TestIAMFetcher:
    """Test cases for IAMFetcher class."""

    def setup_method(self):
        """Set up test fixtures."""
        # Don't initialize fetcher here to avoid AWS calls
        pass

    @patch("iam_explorer.fetcher.IAMFetcher._initialize_session")
    def test_fetcher_initialization_default(self, mock_init):
        """Test fetcher initialization with default parameters."""
        fetcher = IAMFetcher()
        assert fetcher.profile_name is None
        assert fetcher.region_name == "us-east-1"
        assert fetcher.include_aws_managed is False
        mock_init.assert_called_once()

    @patch("iam_explorer.fetcher.IAMFetcher._initialize_session")
    def test_fetcher_initialization_custom(self, mock_init):
        """Test fetcher initialization with custom parameters."""
        fetcher = IAMFetcher(profile_name="test-profile", region_name="us-west-2", include_aws_managed=True)
        assert fetcher.profile_name == "test-profile"
        assert fetcher.region_name == "us-west-2"
        assert fetcher.include_aws_managed is True
        mock_init.assert_called_once()

    @patch("boto3.Session")
    def test_get_iam_client_with_profile(self, mock_session):
        """Test IAM client creation with profile."""
        mock_session_instance = Mock()
        mock_session.return_value = mock_session_instance
        mock_client = Mock()
        mock_session_instance.client.return_value = mock_client

        fetcher = IAMFetcher(profile_name="test-profile")
        client = fetcher._get_iam_client()

        mock_session.assert_called_once_with(profile_name="test-profile")
        mock_session_instance.client.assert_called_once_with("iam", region_name="us-east-1")
        assert client == mock_client

    @patch("boto3.client")
    def test_get_iam_client_without_profile(self, mock_client):
        """Test IAM client creation without profile."""
        mock_iam_client = Mock()
        mock_client.return_value = mock_iam_client

        fetcher = IAMFetcher()
        client = fetcher._get_iam_client()

        mock_client.assert_called_once_with("iam", region_name="us-east-1")
        assert client == mock_iam_client

    @patch("boto3.client")
    def test_get_iam_client_credentials_error(self, mock_client):
        """Test IAM client creation with credentials error."""
        mock_client.side_effect = NoCredentialsError()

        fetcher = IAMFetcher()

        with pytest.raises(Exception) as exc_info:
            fetcher._get_iam_client()

        assert "AWS credentials not found" in str(exc_info.value)

    @patch("iam_explorer.fetcher.IAMFetcher._initialize_session")
    def test_fetch_users_success(self, mock_init):
        """Test successful user fetching."""
        fetcher = IAMFetcher()
        mock_client = Mock()
        mock_client.list_users.return_value = {
            "Users": [
                {
                    "UserName": "alice",
                    "UserId": "AIDACKCEVSQ6C2EXAMPLE",
                    "Arn": "arn:aws:iam::123456789012:user/alice",
                    "CreateDate": "2023-01-01T00:00:00Z",
                    "Path": "/",
                }
            ],
            "IsTruncated": False,
        }

        with patch.object(fetcher, "_get_iam_client", return_value=mock_client):
            users = fetcher.fetch_users()

        assert len(users) == 1
        assert users[0]["UserName"] == "alice"
        mock_client.list_users.assert_called_once()

    def test_fetch_users_paginated(self):
        """Test user fetching with pagination."""
        mock_client = Mock()

        # First page
        mock_client.list_users.side_effect = [
            {
                "Users": [
                    {
                        "UserName": "alice",
                        "UserId": "ID1",
                        "Arn": "arn1",
                        "CreateDate": "2023-01-01T00:00:00Z",
                        "Path": "/",
                    }
                ],
                "IsTruncated": True,
                "Marker": "marker1",
            },
            # Second page
            {
                "Users": [
                    {
                        "UserName": "bob",
                        "UserId": "ID2",
                        "Arn": "arn2",
                        "CreateDate": "2023-01-01T00:00:00Z",
                        "Path": "/",
                    }
                ],
                "IsTruncated": False,
            },
        ]

        with patch.object(self.fetcher, "_get_iam_client", return_value=mock_client):
            users = self.fetcher.fetch_users()

        assert len(users) == 2
        assert users[0]["UserName"] == "alice"
        assert users[1]["UserName"] == "bob"
        assert mock_client.list_users.call_count == 2

    def test_fetch_users_client_error(self):
        """Test user fetching with client error."""
        mock_client = Mock()
        mock_client.list_users.side_effect = ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "Access denied"}}, "ListUsers"
        )

        with patch.object(self.fetcher, "_get_iam_client", return_value=mock_client):
            with pytest.raises(Exception) as exc_info:
                self.fetcher.fetch_users()

        assert "Error fetching users" in str(exc_info.value)

    def test_fetch_roles_success(self):
        """Test successful role fetching."""
        mock_client = Mock()
        mock_client.list_roles.return_value = {
            "Roles": [
                {
                    "RoleName": "test-role",
                    "RoleId": "AROA123456789EXAMPLE",
                    "Arn": "arn:aws:iam::123456789012:role/test-role",
                    "CreateDate": "2023-01-01T00:00:00Z",
                    "AssumeRolePolicyDocument": "%7B%22Version%22%3A%222012-10-17%22%7D",
                    "Path": "/",
                }
            ],
            "IsTruncated": False,
        }

        with patch.object(self.fetcher, "_get_iam_client", return_value=mock_client):
            roles = self.fetcher.fetch_roles()

        assert len(roles) == 1
        assert roles[0]["RoleName"] == "test-role"
        mock_client.list_roles.assert_called_once()

    def test_fetch_groups_success(self):
        """Test successful group fetching."""
        mock_client = Mock()
        mock_client.list_groups.return_value = {
            "Groups": [
                {
                    "GroupName": "developers",
                    "GroupId": "AGPA123456789EXAMPLE",
                    "Arn": "arn:aws:iam::123456789012:group/developers",
                    "CreateDate": "2023-01-01T00:00:00Z",
                    "Path": "/",
                }
            ],
            "IsTruncated": False,
        }

        with patch.object(self.fetcher, "_get_iam_client", return_value=mock_client):
            groups = self.fetcher.fetch_groups()

        assert len(groups) == 1
        assert groups[0]["GroupName"] == "developers"
        mock_client.list_groups.assert_called_once()

    def test_fetch_policies_customer_managed_only(self):
        """Test fetching customer managed policies only."""
        mock_client = Mock()
        mock_client.list_policies.return_value = {
            "Policies": [
                {
                    "PolicyName": "CustomPolicy",
                    "PolicyId": "ANPA123456789EXAMPLE",
                    "Arn": "arn:aws:iam::123456789012:policy/CustomPolicy",
                    "CreateDate": "2023-01-01T00:00:00Z",
                    "IsAttachable": True,
                    "DefaultVersionId": "v1",
                }
            ],
            "IsTruncated": False,
        }

        fetcher = IAMFetcher(include_aws_managed=False)
        with patch.object(fetcher, "_get_iam_client", return_value=mock_client):
            policies = fetcher.fetch_policies()

        assert len(policies) == 1
        assert policies[0]["PolicyName"] == "CustomPolicy"
        mock_client.list_policies.assert_called_once_with(Scope="Local")

    def test_fetch_policies_include_aws_managed(self):
        """Test fetching policies including AWS managed."""
        mock_client = Mock()
        mock_client.list_policies.return_value = {
            "Policies": [
                {
                    "PolicyName": "AWSManagedPolicy",
                    "PolicyId": "ANPA123456789EXAMPLE",
                    "Arn": "arn:aws:iam::aws:policy/AWSManagedPolicy",
                    "CreateDate": "2023-01-01T00:00:00Z",
                    "IsAttachable": True,
                    "DefaultVersionId": "v1",
                }
            ],
            "IsTruncated": False,
        }

        fetcher = IAMFetcher(include_aws_managed=True)
        with patch.object(fetcher, "_get_iam_client", return_value=mock_client):
            policies = fetcher.fetch_policies()

        assert len(policies) == 1
        assert policies[0]["PolicyName"] == "AWSManagedPolicy"
        mock_client.list_policies.assert_called_once_with(Scope="All")

    def test_fetch_user_policies_success(self):
        """Test fetching user policies."""
        mock_client = Mock()

        # Mock attached managed policies
        mock_client.list_attached_user_policies.return_value = {
            "AttachedPolicies": [
                {
                    "PolicyName": "ManagedPolicy",
                    "PolicyArn": "arn:aws:iam::123456789012:policy/ManagedPolicy",
                }
            ],
            "IsTruncated": False,
        }

        # Mock inline policies
        mock_client.list_user_policies.return_value = {
            "PolicyNames": ["InlinePolicy"],
            "IsTruncated": False,
        }

        mock_client.get_user_policy.return_value = {
            "PolicyDocument": "%7B%22Version%22%3A%222012-10-17%22%7D"
        }

        with patch.object(self.fetcher, "_get_iam_client", return_value=mock_client):
            policies = self.fetcher.fetch_user_policies("alice")

        assert "attached_policies" in policies
        assert "inline_policies" in policies
        assert len(policies["attached_policies"]) == 1
        assert len(policies["inline_policies"]) == 1

    @patch("iam_explorer.fetcher.IAMFetcher._initialize_session")
    def test_fetch_all_data_success(self, mock_init):
        """Test fetching all IAM data."""
        fetcher = IAMFetcher()

        with patch.object(fetcher, "fetch_users", return_value=[{"UserName": "alice"}]):
            with patch.object(fetcher, "fetch_roles", return_value=[{"RoleName": "test-role"}]):
                with patch.object(fetcher, "fetch_groups", return_value=[{"GroupName": "developers"}]):
                    with patch.object(fetcher, "fetch_policies", return_value=[{"PolicyName": "CustomPolicy"}]):
                        with patch.object(
                            fetcher,
                            "fetch_user_policies",
                            return_value={"attached_policies": [], "inline_policies": []},
                        ):
                            with patch.object(
                                fetcher,
                                "fetch_role_policies",
                                return_value={"attached_policies": [], "inline_policies": []},
                            ):
                                with patch.object(
                                    fetcher,
                                    "fetch_group_policies",
                                    return_value={"attached_policies": [], "inline_policies": []},
                                ):
                                    with patch.object(fetcher, "fetch_group_memberships", return_value=[]):
                                        data = fetcher.fetch_all_data()

        assert "users" in data
        assert "roles" in data
        assert "groups" in data
        assert "policies" in data
        assert "user_policies" in data
        assert "role_policies" in data
        assert "group_policies" in data
        assert "group_memberships" in data
        assert len(data["users"]) == 1
        assert len(data["roles"]) == 1
        assert len(data["groups"]) == 1
        assert len(data["policies"]) == 1

    def test_save_data_to_file(self):
        """Test saving data to file."""
        test_data = {"users": [{"UserName": "alice"}]}

        with patch("builtins.open", create=True) as mock_open:
            with patch("json.dump") as mock_json_dump:
                mock_file = MagicMock()
                mock_open.return_value.__enter__.return_value = mock_file

                self.fetcher.save_data_to_file(test_data, "test.json")

                mock_open.assert_called_once_with("test.json", "w")
                mock_json_dump.assert_called_once_with(test_data, mock_file, indent=2, default=str)

    def test_load_data_from_file(self):
        """Test loading data from file."""
        test_data = {"users": [{"UserName": "alice"}]}

        with patch("builtins.open", create=True) as mock_open:
            with patch("json.load", return_value=test_data) as mock_json_load:
                mock_file = MagicMock()
                mock_open.return_value.__enter__.return_value = mock_file

                data = self.fetcher.load_data_from_file("test.json")

                mock_open.assert_called_once_with("test.json", "r")
                mock_json_load.assert_called_once_with(mock_file)
                assert data == test_data
