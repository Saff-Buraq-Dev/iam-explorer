import boto3
import json


def fetch_iam_data(profile_name=None, region_name=None):
    """
    Fetch a minimal set of IAM data from AWS:
    - Users
    - Roles
    Returns a dictionary with keys "Users" and "Roles".
    """

    session_args = {}
    if profile_name:
        session_args["profile_name"] = profile_name
    if region_name:
        session_args["region_name"] = region_name

    # Create a session, then an IAM client
    session = boto3.Session(**session_args)
    iam_client = session.client("iam")

    # Fetch all IAM users (paginated)
    users_response = []
    paginator = iam_client.get_paginator("list_users")
    for page in paginator.paginate():
        users_response.extend(page.get("Users", []))

    # Fetch all IAM roles (paginated)
    roles_response = []
    paginator = iam_client.get_paginator("list_roles")
    for page in paginator.paginate():
        roles_response.extend(page.get("Roles", []))

    data = {
        "Users": users_response,
        "Roles": roles_response,
    }
    return data


def save_iam_data_to_json(data, output_path="iam_data.json"):
    """
    Save the fetched IAM data as a JSON file.
    """
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, default=str)
        print(f"IAM data saved to {output_path}")
