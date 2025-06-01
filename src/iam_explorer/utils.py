"""
Utility functions for IAM Explorer.
"""

import re
import json
import requests
import logging
from typing import Dict, List, Any, Optional
from datetime import datetime
from functools import lru_cache

logger = logging.getLogger(__name__)


def parse_arn(arn: str) -> Dict[str, str]:
    """
    Parse an AWS ARN into its components.

    Args:
        arn: AWS ARN string

    Returns:
        Dictionary with ARN components
    """
    if not arn or not arn.startswith('arn:'):
        return {}

    parts = arn.split(':')
    if len(parts) < 6:
        return {}

    return {
        'arn': arn,
        'partition': parts[1],
        'service': parts[2],
        'region': parts[3],
        'account': parts[4],
        'resource': ':'.join(parts[5:])
    }


def extract_account_id(arn: str) -> Optional[str]:
    """Extract account ID from ARN."""
    parsed = parse_arn(arn)
    return parsed.get('account')


def is_aws_service_principal(principal: str) -> bool:
    """Check if a principal is an AWS service."""
    service_patterns = [
        r'.*\.amazonaws\.com$',
        r'.*\.aws\.internal$',
        r'^ec2\.amazonaws\.com$',
        r'^lambda\.amazonaws\.com$',
        r'^s3\.amazonaws\.com$'
    ]

    for pattern in service_patterns:
        if re.match(pattern, principal):
            return True

    return False


def normalize_action(action: str) -> str:
    """Normalize an AWS action string."""
    return action.lower().strip()


@lru_cache(maxsize=1)
def fetch_aws_service_actions() -> Dict[str, List[str]]:
    """
    Fetch AWS service actions from the AWS Policy Generator.

    Returns:
        Dictionary mapping service names to lists of actions

    Example:
        {
            's3': ['GetObject', 'PutObject', 'DeleteObject', ...],
            'ec2': ['DescribeInstances', 'RunInstances', ...],
            ...
        }
    """
    try:
        logger.info("Fetching AWS service actions from AWS Policy Generator...")

        # Fetch the policies.js file from AWS Policy Generator
        url = "https://awspolicygen.s3.amazonaws.com/js/policies.js"
        response = requests.get(url, timeout=30)
        response.raise_for_status()

        # Find the start of PolicyEditorConfig using regex
        start_match = re.search(r'app\.PolicyEditorConfig\s*=\s*', response.text)

        if not start_match:
            logger.warning("Could not find app.PolicyEditorConfig in AWS policies.js")
            return _get_fallback_service_actions()

        # Extract the JSON object by counting braces
        start_pos = start_match.end()
        brace_count = 0
        end_pos = start_pos

        for i, char in enumerate(response.text[start_pos:], start_pos):
            if char == '{':
                brace_count += 1
            elif char == '}':
                brace_count -= 1
                if brace_count == 0:
                    end_pos = i + 1
                    break

        # Extract and parse the JSON
        json_content = response.text[start_pos:end_pos]

        try:
            policy_config = json.loads(json_content)
        except json.JSONDecodeError as e:
            logger.warning(f"Failed to parse PolicyEditorConfig JSON: {e}")
            return _get_fallback_service_actions()

        # Extract serviceMap from the config
        services = policy_config.get('serviceMap', {})
        if not services:
            logger.warning("No serviceMap found in PolicyEditorConfig")
            return _get_fallback_service_actions()

        # Extract service actions with proper handling
        service_actions = {}

        for service_key, service_data in services.items():
            if isinstance(service_data, dict) and 'Actions' in service_data:
                # Use StringPrefix if available, otherwise use the key
                service_name = service_data.get('StringPrefix', service_key).lower()

                actions = []
                action_list = service_data['Actions']

                if isinstance(action_list, list):
                    for action in action_list:
                        if isinstance(action, str):
                            actions.append(action)
                        elif isinstance(action, dict):
                            # Handle different possible action formats
                            action_name = action.get('action', action.get('name', action.get('Action', '')))
                            if action_name:
                                actions.append(action_name)

                if actions:
                    service_actions[service_name] = sorted(actions)

        logger.info(f"Successfully fetched {len(service_actions)} AWS services with actions")
        return service_actions

    except requests.RequestException as e:
        logger.warning(f"Failed to fetch AWS service actions: {e}")
        return _get_fallback_service_actions()
    except Exception as e:
        logger.warning(f"Unexpected error fetching AWS service actions: {e}")
        return _get_fallback_service_actions()


def _get_fallback_service_actions() -> Dict[str, List[str]]:
    """
    Fallback service actions when dynamic fetching fails.

    Returns:
        Dictionary with common AWS service actions
    """
    logger.info("Using fallback service actions")

    return {
        's3': [
            'GetObject', 'PutObject', 'DeleteObject', 'ListBucket', 'GetBucketLocation',
            'GetBucketPolicy', 'PutBucketPolicy', 'DeleteBucketPolicy', 'GetBucketAcl',
            'PutBucketAcl', 'CreateBucket', 'DeleteBucket', 'ListAllMyBuckets'
        ],
        'ec2': [
            'DescribeInstances', 'RunInstances', 'TerminateInstances', 'StopInstances',
            'StartInstances', 'RebootInstances', 'DescribeImages', 'CreateImage',
            'DescribeSecurityGroups', 'AuthorizeSecurityGroupIngress', 'CreateSecurityGroup'
        ],
        'iam': [
            'GetUser', 'CreateUser', 'DeleteUser', 'ListUsers', 'GetRole', 'CreateRole',
            'DeleteRole', 'ListRoles', 'AttachUserPolicy', 'DetachUserPolicy',
            'AttachRolePolicy', 'DetachRolePolicy', 'CreatePolicy', 'DeletePolicy'
        ],
        'lambda': [
            'InvokeFunction', 'CreateFunction', 'DeleteFunction', 'UpdateFunctionCode',
            'UpdateFunctionConfiguration', 'GetFunction', 'ListFunctions',
            'AddPermission', 'RemovePermission'
        ],
        'dynamodb': [
            'GetItem', 'PutItem', 'DeleteItem', 'Query', 'Scan', 'UpdateItem',
            'CreateTable', 'DeleteTable', 'DescribeTable', 'ListTables'
        ],
        'rds': [
            'CreateDBInstance', 'DeleteDBInstance', 'DescribeDBInstances',
            'ModifyDBInstance', 'RebootDBInstance', 'CreateDBSnapshot'
        ],
        'cloudformation': [
            'CreateStack', 'DeleteStack', 'UpdateStack', 'DescribeStacks',
            'ListStacks', 'GetTemplate'
        ],
        'kms': [
            'Encrypt', 'Decrypt', 'GenerateDataKey', 'CreateKey', 'DeleteKey',
            'DescribeKey', 'ListKeys'
        ],
        'secretsmanager': [
            'GetSecretValue', 'CreateSecret', 'DeleteSecret', 'UpdateSecret',
            'DescribeSecret', 'ListSecrets'
        ],
        'sns': [
            'Publish', 'Subscribe', 'Unsubscribe', 'CreateTopic', 'DeleteTopic',
            'ListTopics', 'GetTopicAttributes'
        ],
        'sqs': [
            'SendMessage', 'ReceiveMessage', 'DeleteMessage', 'CreateQueue',
            'DeleteQueue', 'ListQueues', 'GetQueueAttributes'
        ]
    }


def expand_action_wildcards(action: str) -> List[str]:
    """
    Expand action wildcards using dynamic AWS service data.

    Args:
        action: AWS action pattern (e.g., 's3:*', 'ec2:Describe*', '*')

    Returns:
        List of expanded actions
    """
    if '*' not in action:
        return [action]

    # Get service actions (cached)
    service_actions = fetch_aws_service_actions()

    if action == '*':
        # Return all actions from all services
        all_actions = []
        for service, actions in service_actions.items():
            all_actions.extend([f"{service}:{act}" for act in actions])
        return all_actions

    # Service-specific wildcards
    if ':' in action:
        service, action_pattern = action.split(':', 1)

        if service == '*':
            # Cross-service pattern matching
            pattern = action_pattern.replace('*', '.*')
            regex = re.compile(f"^{pattern}$", re.IGNORECASE)

            matching_actions = []
            for svc, actions in service_actions.items():
                for act in actions:
                    if regex.match(act):
                        matching_actions.append(f"{svc}:{act}")

            return matching_actions

        service = service.lower()

        if service in service_actions:
            service_action_list = service_actions[service]

            if action_pattern == '*':
                # Return all actions for this service
                return [f"{service}:{act}" for act in service_action_list]
            else:
                # Pattern matching within service actions
                pattern = action_pattern.replace('*', '.*')
                regex = re.compile(f"^{pattern}$", re.IGNORECASE)

                matching_actions = []
                for act in service_action_list:
                    if regex.match(act):
                        matching_actions.append(f"{service}:{act}")

                return matching_actions

    return [action]


def format_datetime(dt: Optional[datetime]) -> str:
    """Format datetime for display."""
    if not dt:
        return "Never"

    return dt.strftime("%Y-%m-%d %H:%M:%S UTC")


def truncate_string(text: str, max_length: int = 50) -> str:
    """Truncate string with ellipsis."""
    if len(text) <= max_length:
        return text

    return text[:max_length - 3] + "..."


def sanitize_filename(filename: str) -> str:
    """Sanitize filename for safe file operations."""
    # Remove or replace invalid characters
    invalid_chars = '<>:"/\\|?*'
    for char in invalid_chars:
        filename = filename.replace(char, '_')

    return filename


def deep_merge_dicts(dict1: Dict, dict2: Dict) -> Dict:
    """Deep merge two dictionaries."""
    result = dict1.copy()

    for key, value in dict2.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = deep_merge_dicts(result[key], value)
        else:
            result[key] = value

    return result


def extract_policy_conditions(statement: Dict[str, Any]) -> Dict[str, Any]:
    """Extract conditions from a policy statement."""
    return statement.get('Condition', {})


def evaluate_condition(condition: Dict[str, Any], context: Dict[str, Any]) -> bool:
    """
    Evaluate a policy condition against a context.

    This is a simplified implementation - real AWS condition evaluation is much more complex.
    """
    if not condition:
        return True

    # Simple string equality check
    for condition_type, condition_values in condition.items():
        if condition_type == 'StringEquals':
            for key, expected_value in condition_values.items():
                actual_value = context.get(key)
                if actual_value != expected_value:
                    return False
        elif condition_type == 'StringLike':
            for key, pattern in condition_values.items():
                actual_value = context.get(key, '')
                if not re.match(pattern.replace('*', '.*'), actual_value):
                    return False

    return True


def get_resource_type_from_arn(arn: str) -> str:
    """Extract resource type from ARN."""
    parsed = parse_arn(arn)
    resource = parsed.get('resource', '')

    if '/' in resource:
        return resource.split('/')[0]
    elif ':' in resource:
        return resource.split(':')[0]

    return resource


def is_cross_account_access(principal_arn: str, resource_arn: str) -> bool:
    """Check if access is cross-account."""
    principal_account = extract_account_id(principal_arn)
    resource_account = extract_account_id(resource_arn)

    if not principal_account or not resource_account:
        return False

    return principal_account != resource_account


def calculate_permission_risk_score(permissions: List[str]) -> int:
    """
    Calculate a risk score for a set of permissions.

    Returns a score from 0-100 where higher is more risky.
    """
    high_risk_patterns = [
        r'\*:\*',  # Full admin
        r'iam:.*',  # IAM permissions
        r'.*:Delete.*',  # Delete permissions
        r'.*:Create.*',  # Create permissions
        r's3:.*',  # S3 permissions (data access)
        r'ec2:.*Instance.*'  # EC2 instance control
    ]

    risk_score = 0

    for permission in permissions:
        for pattern in high_risk_patterns:
            if re.match(pattern, permission, re.IGNORECASE):
                if pattern == r'\*:\*':
                    risk_score += 50  # Very high risk
                elif 'iam:' in pattern.lower():
                    risk_score += 30  # High risk
                elif 'delete' in pattern.lower() or 'create' in pattern.lower():
                    risk_score += 20  # Medium-high risk
                else:
                    risk_score += 10  # Medium risk
                break

    return min(risk_score, 100)  # Cap at 100


def find_privilege_escalation_paths(graph, start_entity: str) -> List[List[str]]:
    """
    Find potential privilege escalation paths from a starting entity.

    This is a simplified implementation that looks for paths to high-privilege roles.
    """
    import networkx as nx

    paths = []

    # Find high-privilege entities (those with admin-like permissions)
    high_privilege_entities = []

    for node, data in graph.nodes(data=True):
        if data.get('type') in ['user', 'role']:
            entity_data = data.get('data')
            if entity_data:
                # Check if entity has high-risk permissions
                # This would need to be implemented based on actual policy analysis
                pass

    # Use NetworkX to find paths
    try:
        for target in high_privilege_entities:
            if start_entity != target:
                try:
                    path = nx.shortest_path(graph, start_entity, target)
                    if len(path) > 1:  # Exclude direct access
                        paths.append(path)
                except nx.NetworkXNoPath:
                    continue
    except Exception:
        pass

    return paths


def generate_security_report(graph) -> Dict[str, Any]:
    """Generate a security analysis report."""
    report = {
        'timestamp': datetime.now().isoformat(),
        'summary': {
            'total_entities': len(graph.nodes),
            'users': 0,
            'roles': 0,
            'groups': 0,
            'policies': 0
        },
        'findings': [],
        'recommendations': []
    }

    # Count entity types
    for node, data in graph.nodes(data=True):
        entity_type = data.get('type', 'unknown')
        if entity_type in report['summary']:
            report['summary'][entity_type] += 1

    # Add basic findings
    if report['summary']['users'] > 50:
        report['findings'].append({
            'severity': 'medium',
            'type': 'user_count',
            'message': f"High number of users ({report['summary']['users']}) - consider using roles instead"
        })

    if report['summary']['policies'] > 100:
        report['findings'].append({
            'severity': 'low',
            'type': 'policy_count',
            'message': f"High number of policies ({report['summary']['policies']}) - consider consolidation"
        })

    return report
