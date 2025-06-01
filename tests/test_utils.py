"""
Tests for the utils module.
"""

from unittest.mock import Mock, patch
from datetime import datetime
import requests

from iam_explorer.utils import (
    parse_arn, extract_account_id, normalize_action,
    expand_action_wildcards, fetch_aws_service_actions, _get_fallback_service_actions,
    format_datetime, truncate_string, sanitize_filename, deep_merge_dicts,
    extract_policy_conditions, evaluate_condition, get_resource_type_from_arn,
    is_cross_account_access, calculate_permission_risk_score
)


class TestUtilityFunctions:
    """Test cases for utility functions."""

    def test_parse_arn_valid(self):
        """Test parsing valid ARN."""
        arn = "arn:aws:iam::123456789012:user/alice"
        parsed = parse_arn(arn)

        assert parsed['partition'] == 'aws'
        assert parsed['service'] == 'iam'
        assert parsed['region'] == ''
        assert parsed['account'] == '123456789012'
        assert parsed['resource'] == 'user/alice'

    def test_parse_arn_with_region(self):
        """Test parsing ARN with region."""
        arn = "arn:aws:s3:us-east-1:123456789012:bucket/my-bucket"
        parsed = parse_arn(arn)

        assert parsed['partition'] == 'aws'
        assert parsed['service'] == 's3'
        assert parsed['region'] == 'us-east-1'
        assert parsed['account'] == '123456789012'
        assert parsed['resource'] == 'bucket/my-bucket'

    def test_parse_arn_invalid(self):
        """Test parsing invalid ARN."""
        invalid_arn = "not-an-arn"
        parsed = parse_arn(invalid_arn)

        assert all(value == '' for value in parsed.values())

    def test_extract_account_id_from_arn(self):
        """Test extracting account ID from ARN."""
        arn = "arn:aws:iam::123456789012:user/alice"
        account_id = extract_account_id(arn)
        assert account_id == "123456789012"

    def test_extract_account_id_invalid_arn(self):
        """Test extracting account ID from invalid ARN."""
        invalid_arn = "not-an-arn"
        account_id = extract_account_id(invalid_arn)
        assert account_id is None

    def test_parse_arn_empty(self):
        """Test parsing empty ARN."""
        empty_arn = ""
        parsed = parse_arn(empty_arn)
        assert parsed == {}

    def test_normalize_action(self):
        """Test action normalization."""
        action = "S3:GetObject"
        normalized = normalize_action(action)
        assert normalized == "s3:getobject"

    def test_format_datetime_valid(self):
        """Test datetime formatting."""
        dt = datetime(2023, 1, 1, 12, 0, 0)
        formatted = format_datetime(dt)
        assert formatted == "2023-01-01 12:00:00 UTC"

    def test_format_datetime_none(self):
        """Test datetime formatting with None."""
        formatted = format_datetime(None)
        assert formatted == "Never"

    def test_truncate_string_short(self):
        """Test string truncation with short string."""
        text = "short"
        truncated = truncate_string(text, 10)
        assert truncated == "short"

    def test_truncate_string_long(self):
        """Test string truncation with long string."""
        text = "this is a very long string that should be truncated"
        truncated = truncate_string(text, 20)
        assert len(truncated) == 20
        assert truncated.endswith("...")

    def test_sanitize_filename(self):
        """Test filename sanitization."""
        filename = "file<name>with:invalid/chars"
        sanitized = sanitize_filename(filename)
        assert "<" not in sanitized
        assert ">" not in sanitized
        assert ":" not in sanitized
        assert "/" not in sanitized

    def test_deep_merge_dicts(self):
        """Test deep dictionary merging."""
        dict1 = {"a": 1, "b": {"c": 2}}
        dict2 = {"b": {"d": 3}, "e": 4}

        merged = deep_merge_dicts(dict1, dict2)

        assert merged["a"] == 1
        assert merged["b"]["c"] == 2
        assert merged["b"]["d"] == 3
        assert merged["e"] == 4

    def test_extract_policy_conditions(self):
        """Test extracting policy conditions."""
        statement = {
            "Effect": "Allow",
            "Action": "s3:GetObject",
            "Condition": {
                "StringEquals": {
                    "aws:userid": "AIDACKCEVSQ6C2EXAMPLE"
                }
            }
        }

        conditions = extract_policy_conditions(statement)
        assert "StringEquals" in conditions
        assert conditions["StringEquals"]["aws:userid"] == "AIDACKCEVSQ6C2EXAMPLE"

    def test_extract_policy_conditions_no_condition(self):
        """Test extracting conditions from statement without conditions."""
        statement = {
            "Effect": "Allow",
            "Action": "s3:GetObject"
        }

        conditions = extract_policy_conditions(statement)
        assert conditions == {}

    def test_evaluate_condition_string_equals_true(self):
        """Test condition evaluation with StringEquals (true case)."""
        condition = {
            "StringEquals": {
                "aws:userid": "AIDACKCEVSQ6C2EXAMPLE"
            }
        }
        context = {
            "aws:userid": "AIDACKCEVSQ6C2EXAMPLE"
        }

        result = evaluate_condition(condition, context)
        assert result is True

    def test_evaluate_condition_string_equals_false(self):
        """Test condition evaluation with StringEquals (false case)."""
        condition = {
            "StringEquals": {
                "aws:userid": "AIDACKCEVSQ6C2EXAMPLE"
            }
        }
        context = {
            "aws:userid": "DIFFERENT_USER_ID"
        }

        result = evaluate_condition(condition, context)
        assert result is False

    def test_evaluate_condition_string_like_true(self):
        """Test condition evaluation with StringLike (true case)."""
        condition = {
            "StringLike": {
                "s3:prefix": "documents/*"
            }
        }
        context = {
            "s3:prefix": "documents/file.txt"
        }

        result = evaluate_condition(condition, context)
        assert result is True

    def test_evaluate_condition_empty(self):
        """Test condition evaluation with empty condition."""
        result = evaluate_condition({}, {})
        assert result is True

    def test_get_resource_type_from_arn_with_slash(self):
        """Test extracting resource type from ARN with slash."""
        arn = "arn:aws:s3:::bucket/object"
        resource_type = get_resource_type_from_arn(arn)
        assert resource_type == "bucket"

    def test_get_resource_type_from_arn_with_colon(self):
        """Test extracting resource type from ARN with colon."""
        arn = "arn:aws:iam::123456789012:user:alice"
        resource_type = get_resource_type_from_arn(arn)
        assert resource_type == "user"

    def test_is_cross_account_access_true(self):
        """Test cross-account access detection (true case)."""
        principal_arn = "arn:aws:iam::111111111111:user/alice"
        resource_arn = "arn:aws:s3:::bucket-in-222222222222"

        # Mock extract_account_id to return different account IDs
        with patch('iam_explorer.utils.extract_account_id') as mock_extract:
            mock_extract.side_effect = ["111111111111", "222222222222"]
            result = is_cross_account_access(principal_arn, resource_arn)
            assert result is True

    def test_is_cross_account_access_false(self):
        """Test cross-account access detection (false case)."""
        principal_arn = "arn:aws:iam::123456789012:user/alice"
        resource_arn = "arn:aws:s3:::bucket-in-123456789012"

        # Mock extract_account_id to return same account ID
        with patch('iam_explorer.utils.extract_account_id') as mock_extract:
            mock_extract.side_effect = ["123456789012", "123456789012"]
            result = is_cross_account_access(principal_arn, resource_arn)
            assert result is False

    def test_calculate_permission_risk_score_admin(self):
        """Test risk score calculation for admin permissions."""
        permissions = ["*:*"]
        score = calculate_permission_risk_score(permissions)
        assert score >= 50  # Admin access should have high risk

    def test_calculate_permission_risk_score_iam(self):
        """Test risk score calculation for IAM permissions."""
        permissions = ["iam:CreateUser", "iam:AttachUserPolicy"]
        score = calculate_permission_risk_score(permissions)
        assert score >= 30  # IAM permissions should have high risk

    def test_calculate_permission_risk_score_low(self):
        """Test risk score calculation for low-risk permissions."""
        permissions = ["s3:ListBucket"]
        score = calculate_permission_risk_score(permissions)
        assert score < 50  # Should have lower risk

    def test_get_fallback_service_actions(self):
        """Test fallback service actions."""
        actions = _get_fallback_service_actions()

        assert isinstance(actions, dict)
        assert 's3' in actions
        assert 'ec2' in actions
        assert 'iam' in actions
        assert isinstance(actions['s3'], list)
        assert len(actions['s3']) > 0

    @patch('requests.get')
    def test_fetch_aws_service_actions_success(self, mock_get):
        """Test successful AWS service actions fetching."""
        # Mock response with valid JavaScript content
        mock_response = Mock()
        mock_response.text = '''
        app.PolicyEditorConfig = {
            "serviceMap": {
                "Amazon S3": {
                    "StringPrefix": "s3",
                    "Actions": ["GetObject", "PutObject", "DeleteObject"]
                },
                "Amazon EC2": {
                    "StringPrefix": "ec2",
                    "Actions": ["DescribeInstances", "RunInstances"]
                }
            }
        };
        '''
        mock_response.raise_for_status.return_value = None
        mock_get.return_value = mock_response

        # Clear the cache
        fetch_aws_service_actions.cache_clear()

        actions = fetch_aws_service_actions()

        assert isinstance(actions, dict)
        assert 's3' in actions
        assert 'ec2' in actions
        assert 'GetObject' in actions['s3']
        assert 'DescribeInstances' in actions['ec2']

    @patch('requests.get')
    def test_fetch_aws_service_actions_request_error(self, mock_get):
        """Test AWS service actions fetching with request error."""
        mock_get.side_effect = requests.RequestException("Network error")

        # Clear the cache
        fetch_aws_service_actions.cache_clear()

        actions = fetch_aws_service_actions()

        # Should return fallback actions
        assert isinstance(actions, dict)
        assert 's3' in actions
        assert 'ec2' in actions

    @patch('requests.get')
    def test_fetch_aws_service_actions_parse_error(self, mock_get):
        """Test AWS service actions fetching with parse error."""
        mock_response = Mock()
        mock_response.text = "invalid javascript content"
        mock_response.raise_for_status.return_value = None
        mock_get.return_value = mock_response

        # Clear the cache
        fetch_aws_service_actions.cache_clear()

        actions = fetch_aws_service_actions()

        # Should return fallback actions
        assert isinstance(actions, dict)
        assert 's3' in actions

    def test_expand_action_wildcards_no_wildcard(self):
        """Test action expansion without wildcards."""
        action = "s3:GetObject"
        expanded = expand_action_wildcards(action)
        assert expanded == ["s3:GetObject"]

    @patch('iam_explorer.utils.fetch_aws_service_actions')
    def test_expand_action_wildcards_service_specific(self, mock_fetch):
        """Test service-specific wildcard expansion."""
        mock_fetch.return_value = {
            's3': ['GetObject', 'PutObject', 'DeleteObject']
        }

        action = "s3:*"
        expanded = expand_action_wildcards(action)

        expected = ['s3:GetObject', 's3:PutObject', 's3:DeleteObject']
        assert expanded == expected

    @patch('iam_explorer.utils.fetch_aws_service_actions')
    def test_expand_action_wildcards_pattern_matching(self, mock_fetch):
        """Test pattern matching in action expansion."""
        mock_fetch.return_value = {
            's3': ['GetObject', 'GetBucketPolicy', 'PutObject', 'ListBucket']
        }

        action = "s3:Get*"
        expanded = expand_action_wildcards(action)

        expected = ['s3:GetObject', 's3:GetBucketPolicy']
        assert expanded == expected

    @patch('iam_explorer.utils.fetch_aws_service_actions')
    def test_expand_action_wildcards_cross_service(self, mock_fetch):
        """Test cross-service wildcard expansion."""
        mock_fetch.return_value = {
            's3': ['CreateBucket', 'GetObject'],
            'ec2': ['CreateInstance', 'DescribeInstances']
        }

        action = "*:Create*"
        expanded = expand_action_wildcards(action)

        expected = ['s3:CreateBucket', 'ec2:CreateInstance']
        assert expanded == expected

    @patch('iam_explorer.utils.fetch_aws_service_actions')
    def test_expand_action_wildcards_all_actions(self, mock_fetch):
        """Test expansion of all actions wildcard."""
        mock_fetch.return_value = {
            's3': ['GetObject', 'PutObject'],
            'ec2': ['DescribeInstances']
        }

        action = "*"
        expanded = expand_action_wildcards(action)

        expected = ['s3:GetObject', 's3:PutObject', 'ec2:DescribeInstances']
        assert expanded == expected
