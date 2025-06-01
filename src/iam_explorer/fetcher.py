"""
AWS IAM data fetcher using boto3.
"""

import json
import logging
from typing import Dict, List, Optional, Any
from datetime import datetime
import boto3
from botocore.exceptions import ClientError, NoCredentialsError

from .models import IAMUser, IAMRole, IAMGroup, IAMPolicy

logger = logging.getLogger(__name__)


class IAMFetcher:
    """Fetches IAM data from AWS using boto3."""

    def __init__(self, profile_name: Optional[str] = None, region_name: str = "us-east-1"):
        """
        Initialize the IAM fetcher.

        Args:
            profile_name: AWS profile name to use
            region_name: AWS region name
        """
        self.profile_name = profile_name
        self.region_name = region_name
        self.session = None
        self.iam_client = None
        self._initialize_session()

    def _initialize_session(self):
        """Initialize boto3 session and IAM client."""
        try:
            if self.profile_name:
                self.session = boto3.Session(profile_name=self.profile_name)
            else:
                self.session = boto3.Session()

            self.iam_client = self.session.client('iam', region_name=self.region_name)

            # Test credentials by trying to list users (safer than get_user)
            try:
                self.iam_client.list_users(MaxItems=1)
                logger.info(f"Successfully initialized AWS session with profile: {self.profile_name}")
            except ClientError as e:
                if e.response['Error']['Code'] in ['AccessDenied', 'ValidationError']:
                    # Try a different test - get account summary
                    try:
                        self.iam_client.get_account_summary()
                        logger.info("Successfully initialized AWS session with role-based credentials")
                    except ClientError:
                        logger.error(f"Error testing AWS credentials: {e}")
                        raise
                else:
                    logger.error(f"Error testing AWS credentials: {e}")
                    raise

        except NoCredentialsError:
            logger.error("No AWS credentials found. Please configure your credentials.")
            raise

    def fetch_all_data(self) -> Dict[str, Any]:
        """
        Fetch all IAM data.

        Returns:
            Dictionary containing all IAM data
        """
        logger.info("Starting to fetch all IAM data...")

        data = {
            "users": self.fetch_users(),
            "roles": self.fetch_roles(),
            "groups": self.fetch_groups(),
            "policies": self.fetch_policies(),
            "metadata": {
                "fetch_time": datetime.now().isoformat(),
                "profile": self.profile_name,
                "region": self.region_name
            }
        }

        logger.info(f"Fetched {len(data['users'])} users, {len(data['roles'])} roles, "
                    f"{len(data['groups'])} groups, {len(data['policies'])} policies")

        return data

    def fetch_users(self) -> List[Dict[str, Any]]:
        """Fetch all IAM users."""
        logger.info("Fetching IAM users...")
        users = []

        try:
            paginator = self.iam_client.get_paginator('list_users')

            for page in paginator.paginate():
                for user_data in page['Users']:
                    user = self._process_user(user_data)
                    users.append(user)

            logger.info(f"Fetched {len(users)} users")
            return users

        except ClientError as e:
            logger.error(f"Error fetching users: {e}")
            raise

    def fetch_roles(self) -> List[Dict[str, Any]]:
        """Fetch all IAM roles."""
        logger.info("Fetching IAM roles...")
        roles = []

        try:
            paginator = self.iam_client.get_paginator('list_roles')

            for page in paginator.paginate():
                for role_data in page['Roles']:
                    role = self._process_role(role_data)
                    roles.append(role)

            logger.info(f"Fetched {len(roles)} roles")
            return roles

        except ClientError as e:
            logger.error(f"Error fetching roles: {e}")
            raise

    def fetch_groups(self) -> List[Dict[str, Any]]:
        """Fetch all IAM groups."""
        logger.info("Fetching IAM groups...")
        groups = []

        try:
            paginator = self.iam_client.get_paginator('list_groups')

            for page in paginator.paginate():
                for group_data in page['Groups']:
                    group = self._process_group(group_data)
                    groups.append(group)

            logger.info(f"Fetched {len(groups)} groups")
            return groups

        except ClientError as e:
            logger.error(f"Error fetching groups: {e}")
            raise

    def fetch_policies(self) -> List[Dict[str, Any]]:
        """Fetch all IAM policies (customer managed only by default)."""
        logger.info("Fetching IAM policies...")
        policies = []

        try:
            # Fetch customer managed policies
            paginator = self.iam_client.get_paginator('list_policies')

            for page in paginator.paginate(Scope='Local'):  # Only customer managed
                for policy_data in page['Policies']:
                    policy = self._process_policy(policy_data)
                    policies.append(policy)

            logger.info(f"Fetched {len(policies)} customer managed policies")
            return policies

        except ClientError as e:
            logger.error(f"Error fetching policies: {e}")
            raise

    def _process_user(self, user_data: Dict[str, Any]) -> Dict[str, Any]:
        """Process user data and fetch additional details."""
        user_name = user_data['UserName']

        # Get attached policies
        attached_policies = self._get_attached_user_policies(user_name)

        # Get inline policies
        inline_policies = self._get_inline_user_policies(user_name)

        # Get groups
        groups = self._get_user_groups(user_name)

        return {
            "arn": user_data['Arn'],
            "name": user_name,
            "user_id": user_data['UserId'],
            "path": user_data['Path'],
            "create_date": user_data['CreateDate'].isoformat(),
            "password_last_used": user_data.get('PasswordLastUsed', {}).isoformat() if user_data.get('PasswordLastUsed') else None,
            "attached_policies": attached_policies,
            "inline_policies": inline_policies,
            "groups": groups,
            "tags": user_data.get('Tags', [])
        }

    def _process_role(self, role_data: Dict[str, Any]) -> Dict[str, Any]:
        """Process role data and fetch additional details."""
        role_name = role_data['RoleName']

        # Get attached policies
        attached_policies = self._get_attached_role_policies(role_name)

        # Get inline policies
        inline_policies = self._get_inline_role_policies(role_name)

        return {
            "arn": role_data['Arn'],
            "name": role_name,
            "role_id": role_data['RoleId'],
            "path": role_data['Path'],
            "assume_role_policy": role_data['AssumeRolePolicyDocument'],
            "create_date": role_data['CreateDate'].isoformat(),
            "max_session_duration": role_data.get('MaxSessionDuration', 3600),
            "attached_policies": attached_policies,
            "inline_policies": inline_policies,
            "permission_boundary": role_data.get('PermissionsBoundary', {}).get('PermissionsBoundaryArn'),
            "tags": role_data.get('Tags', [])
        }

    def _process_group(self, group_data: Dict[str, Any]) -> Dict[str, Any]:
        """Process group data and fetch additional details."""
        group_name = group_data['GroupName']

        # Get attached policies
        attached_policies = self._get_attached_group_policies(group_name)

        # Get inline policies
        inline_policies = self._get_inline_group_policies(group_name)

        return {
            "arn": group_data['Arn'],
            "name": group_name,
            "group_id": group_data['GroupId'],
            "path": group_data['Path'],
            "create_date": group_data['CreateDate'].isoformat(),
            "attached_policies": attached_policies,
            "inline_policies": inline_policies
        }

    def _process_policy(self, policy_data: Dict[str, Any]) -> Dict[str, Any]:
        """Process policy data and fetch policy document."""
        policy_arn = policy_data['Arn']

        # Get policy document
        policy_document = self._get_policy_document(policy_arn, policy_data['DefaultVersionId'])

        return {
            "arn": policy_arn,
            "name": policy_data['PolicyName'],
            "policy_document": policy_document,
            "is_aws_managed": policy_data.get('Arn', '').startswith('arn:aws:iam::aws:'),
            "description": policy_data.get('Description'),
            "create_date": policy_data['CreateDate'].isoformat(),
            "update_date": policy_data['UpdateDate'].isoformat()
        }

    def _get_attached_user_policies(self, user_name: str) -> List[str]:
        """Get attached policies for a user."""
        try:
            response = self.iam_client.list_attached_user_policies(UserName=user_name)
            return [policy['PolicyArn'] for policy in response['AttachedPolicies']]
        except ClientError as e:
            logger.warning(f"Error fetching attached policies for user {user_name}: {e}")
            return []

    def _get_inline_user_policies(self, user_name: str) -> Dict[str, Dict]:
        """Get inline policies for a user."""
        try:
            response = self.iam_client.list_user_policies(UserName=user_name)
            policies = {}

            for policy_name in response['PolicyNames']:
                policy_response = self.iam_client.get_user_policy(
                    UserName=user_name, PolicyName=policy_name
                )
                policies[policy_name] = policy_response['PolicyDocument']

            return policies
        except ClientError as e:
            logger.warning(f"Error fetching inline policies for user {user_name}: {e}")
            return {}

    def _get_user_groups(self, user_name: str) -> List[str]:
        """Get groups for a user."""
        try:
            response = self.iam_client.list_groups_for_user(UserName=user_name)
            return [group['GroupName'] for group in response['Groups']]
        except ClientError as e:
            logger.warning(f"Error fetching groups for user {user_name}: {e}")
            return []

    def _get_attached_role_policies(self, role_name: str) -> List[str]:
        """Get attached policies for a role."""
        try:
            response = self.iam_client.list_attached_role_policies(RoleName=role_name)
            return [policy['PolicyArn'] for policy in response['AttachedPolicies']]
        except ClientError as e:
            logger.warning(f"Error fetching attached policies for role {role_name}: {e}")
            return []

    def _get_inline_role_policies(self, role_name: str) -> Dict[str, Dict]:
        """Get inline policies for a role."""
        try:
            response = self.iam_client.list_role_policies(RoleName=role_name)
            policies = {}

            for policy_name in response['PolicyNames']:
                policy_response = self.iam_client.get_role_policy(
                    RoleName=role_name, PolicyName=policy_name
                )
                policies[policy_name] = policy_response['PolicyDocument']

            return policies
        except ClientError as e:
            logger.warning(f"Error fetching inline policies for role {role_name}: {e}")
            return {}

    def _get_attached_group_policies(self, group_name: str) -> List[str]:
        """Get attached policies for a group."""
        try:
            response = self.iam_client.list_attached_group_policies(GroupName=group_name)
            return [policy['PolicyArn'] for policy in response['AttachedPolicies']]
        except ClientError as e:
            logger.warning(f"Error fetching attached policies for group {group_name}: {e}")
            return []

    def _get_inline_group_policies(self, group_name: str) -> Dict[str, Dict]:
        """Get inline policies for a group."""
        try:
            response = self.iam_client.list_group_policies(GroupName=group_name)
            policies = {}

            for policy_name in response['PolicyNames']:
                policy_response = self.iam_client.get_group_policy(
                    GroupName=group_name, PolicyName=policy_name
                )
                policies[policy_name] = policy_response['PolicyDocument']

            return policies
        except ClientError as e:
            logger.warning(f"Error fetching inline policies for group {group_name}: {e}")
            return {}

    def _get_policy_document(self, policy_arn: str, version_id: str) -> Dict[str, Any]:
        """Get policy document for a policy."""
        try:
            response = self.iam_client.get_policy_version(
                PolicyArn=policy_arn, VersionId=version_id
            )
            return response['PolicyVersion']['Document']
        except ClientError as e:
            logger.warning(f"Error fetching policy document for {policy_arn}: {e}")
            return {}

    def fetch_aws_managed_policies(self) -> List[Dict[str, Any]]:
        """Fetch AWS managed policies (warning: this can be slow and large)."""
        logger.info("Fetching AWS managed policies...")
        policies = []

        try:
            paginator = self.iam_client.get_paginator('list_policies')

            for page in paginator.paginate(Scope='AWS'):  # AWS managed policies
                for policy_data in page['Policies']:
                    policy = self._process_policy(policy_data)
                    policies.append(policy)

            logger.info(f"Fetched {len(policies)} AWS managed policies")
            return policies

        except ClientError as e:
            logger.error(f"Error fetching AWS managed policies: {e}")
            raise

    def save_data(self, data: Dict[str, Any], filename: str):
        """Save fetched data to a JSON file."""
        try:
            with open(filename, 'w') as f:
                json.dump(data, f, indent=2, default=str)
            logger.info(f"Data saved to {filename}")
        except Exception as e:
            logger.error(f"Error saving data to {filename}: {e}")
            raise
