import unittest
from moto import mock_iam
import boto3
from iam_explorer.fetch import IAMFetcher


@mock_iam
class TestIAMFetcher(unittest.TestCase):
    def setUp(self):
        """Set up IAMFetcher with mocked AWS session."""
        self.fetcher = IAMFetcher()

        # Create mock users, roles, and policies in IAM
        self.iam_client = boto3.client("iam")
        self.iam_client.create_user(UserName="Alice")
        self.iam_client.create_user(UserName="Bob")
        self.iam_client.create_role(RoleName="LambdaExecution", AssumeRolePolicyDocument="{}")
        self.iam_client.create_policy(PolicyName="ReadOnlyAccess", PolicyDocument="{}")

    def test_get_users(self):
        """Test fetching IAM users with Moto."""
        users = self.fetcher.get_users()
        usernames = {user["UserName"] for user in users}
        self.assertEqual(usernames, {"Alice", "Bob"})

    def test_get_roles(self):
        """Test fetching IAM roles with Moto."""
        roles = self.fetcher.get_roles()
        role_names = {role["RoleName"] for role in roles}
        self.assertIn("LambdaExecution", role_names)

    def test_get_policies(self):
        """Test fetching IAM policies with Moto."""
        policies = self.fetcher.get_policies()
        policy_names = {policy["PolicyName"] for policy in policies}
        self.assertIn("ReadOnlyAccess", policy_names)

    def test_fetch_all(self):
        """Test fetching all IAM data."""
        iam_data = self.fetcher.fetch_all()
        self.assertEqual(len(iam_data["users"]), 2)
        self.assertEqual(len(iam_data["roles"]), 1)
        self.assertEqual(len(iam_data["policies"]), 1)


if __name__ == "__main__":
    unittest.main()
