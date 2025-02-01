import unittest
from unittest.mock import patch
from moto import mock_iam
import boto3
from iam_explorer.utils import check_aws_credentials


@mock_iam
class TestAWSCheckDecorator(unittest.TestCase):
    def setUp(self):
        """Create a mock IAM user to simulate valid credentials."""
        self.iam_client = boto3.client("iam")
        self.iam_client.create_user(UserName="valid-user")

    def test_valid_credentials(self):
        """Test execution when AWS credentials are valid."""
        @check_aws_credentials
        def test_func():
            return "Executed"

        self.assertEqual(test_func(), "Executed")

    @patch("boto3.Session.client")
    def test_missing_credentials(self, mock_client):
        """Test exit when credentials are missing."""
        mock_client.side_effect = Exception("NoCredentialsError")

        @check_aws_credentials
        def test_func():
            return "Executed"

        with self.assertRaises(SystemExit):
            test_func()

    @patch("boto3.Session.client")
    def test_invalid_credentials(self, mock_client):
        """Test exit when AWS credentials are invalid."""
        mock_client.side_effect = Exception("InvalidClientTokenId")

        @check_aws_credentials
        def test_func():
            return "Executed"

        with self.assertRaises(SystemExit):
            test_func()


if __name__ == "__main__":
    unittest.main()
