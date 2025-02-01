import boto3
import logging
from typing import Dict, List

logging.basicConfig(level=logging.INFO)


class IAMFetcher:
    def __init__(self, aws_profile: str = None):
        """Initialize IAMFetcher with optional AWS profile."""
        session = boto3.Session(profile_name=aws_profile) if aws_profile else boto3.Session()
        self.iam_client = session.client("iam")

    def get_users(self) -> List[Dict]:
        """Retrieve all IAM users."""
        users = []
        paginator = self.iam_client.get_paginator("list_users")
        for page in paginator.paginate():
            users.extend(page["Users"])
        return users

    def get_roles(self) -> List[Dict]:
        """Retrieve all IAM roles."""
        roles = []
        paginator = self.iam_client.get_paginator("list_roles")
        for page in paginator.paginate():
            roles.extend(page["Roles"])
        return roles

    def get_groups(self) -> List[Dict]:
        """Retrieve all IAM groups."""
        groups = []
        paginator = self.iam_client.get_paginator("list_groups")
        for page in paginator.paginate():
            groups.extend(page["Groups"])
        return groups

    def get_policies(self) -> List[Dict]:
        """Retrieve all IAM policies."""
        policies = []
        paginator = self.iam_client.get_paginator("list_policies")
        for page in paginator.paginate(Scope="All"):
            policies.extend(page["Policies"])
        return policies

    def fetch_all(self) -> Dict[str, List[Dict]]:
        """Fetch all IAM data and return as a dictionary."""
        logging.info("Fetching IAM users, roles, groups, and policies...")
        return {
            "users": self.get_users(),
            "roles": self.get_roles(),
            "groups": self.get_groups(),
            "policies": self.get_policies(),
        }
