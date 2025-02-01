import unittest
from moto import mock_iam
import boto3
from iam_explorer.graph import IAMGraph


@mock_iam
class TestIAMGraph(unittest.TestCase):
    def setUp(self):
        """Set up IAMGraph and mock IAM entities."""
        self.graph = IAMGraph()
        self.iam_client = boto3.client("iam")

        # Create IAM entities
        self.iam_client.create_user(UserName="Alice")
        self.iam_client.create_role(RoleName="LambdaExecution", AssumeRolePolicyDocument="{}")
        self.iam_client.create_group(GroupName="Developers")
        self.iam_client.create_policy(PolicyName="ReadOnlyAccess", PolicyDocument="{}")

        # Fetch IAM data
        iam_data = {
            "users": self.iam_client.list_users()["Users"],
            "roles": self.iam_client.list_roles()["Roles"],
            "groups": self.iam_client.list_groups()["Groups"],
            "policies": self.iam_client.list_policies(Scope="All")["Policies"],
        }

        self.graph.build_graph(iam_data)

    def test_build_graph(self):
        """Ensure IAMGraph correctly structures relationships."""
        graph = self.graph.get_graph()

        self.assertIn("User:Alice", graph)
        self.assertIn("Role:LambdaExecution", graph)
        self.assertIn("Group:Developers", graph)
        self.assertIn("Policy:ReadOnlyAccess", graph)


if __name__ == "__main__":
    unittest.main()
