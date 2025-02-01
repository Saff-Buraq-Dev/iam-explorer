# tests/test_fetch.py

import json
import boto3
from moto import mock_aws

from iam_explorer.fetch import fetch_iam_data, save_iam_data_to_json


@mock_aws
def test_fetch_iam_data():
    """
    Verify fetch_iam_data() returns Users and Roles,
    using moto's mock_aws to simulate IAM service.
    """
    iam_client = boto3.client("iam", region_name="us-east-1")

    # Create a test user
    iam_client.create_user(UserName="TestUser")

    # Create a test role
    assume_role_policy_doc = """{
        "Version":"2012-10-17",
        "Statement":[
            {
                "Effect":"Allow",
                "Principal":{"Service":"ec2.amazonaws.com"},
                "Action":"sts:AssumeRole"
            }
        ]
    }"""
    iam_client.create_role(
        RoleName="TestRole",
        AssumeRolePolicyDocument=assume_role_policy_doc
    )

    # Now call our fetch function
    data = fetch_iam_data(profile_name=None, region_name="us-east-1")

    # Check that "Users" and "Roles" keys exist
    assert "Users" in data, "Expected 'Users' key in returned data"
    assert "Roles" in data, "Expected 'Roles' key in returned data"

    # Validate that our test user is in the fetched data
    usernames = [user["UserName"] for user in data["Users"]]
    assert "TestUser" in usernames, "TestUser should be in the fetched Users list"

    # Validate that our test role is in the fetched data
    rolenames = [role["RoleName"] for role in data["Roles"]]
    assert "TestRole" in rolenames, "TestRole should be in the fetched Roles list"


@mock_aws
def test_save_iam_data_to_json(tmp_path):
    """
    Verify save_iam_data_to_json() properly writes the IAM data to a JSON file.
    """
    sample_data = {
        "Users": [{"UserName": "SampleUser"}],
        "Roles": [{"RoleName": "SampleRole"}],
    }

    output_file = tmp_path / "iam_data.json"

    # Use the save function
    save_iam_data_to_json(sample_data, output_path=str(output_file))

    # Read back the file to confirm it was written correctly
    with open(output_file, "r", encoding="utf-8") as f:
        loaded_data = json.load(f)

    # Validate the written contents
    assert "Users" in loaded_data, "Expected 'Users' key in saved data"
    assert "Roles" in loaded_data, "Expected 'Roles' key in saved data"
    assert loaded_data["Users"][0]["UserName"] == "SampleUser"
    assert loaded_data["Roles"][0]["RoleName"] == "SampleRole"
