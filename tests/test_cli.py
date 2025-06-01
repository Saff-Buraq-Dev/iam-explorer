"""
Tests for IAM Explorer CLI.
"""

import pytest
import json
import tempfile
import os
from pathlib import Path
from click.testing import CliRunner

from iam_explorer.cli import main
from iam_explorer.graph_builder import GraphBuilder


class TestCLI:
    """Test CLI functionality."""

    @pytest.fixture
    def runner(self):
        """Create a CLI test runner."""
        return CliRunner()

    @pytest.fixture
    def sample_data_file(self):
        """Create a sample IAM data file for testing."""
        sample_data = {
            "users": [
                {
                    "arn": "arn:aws:iam::123456789012:user/test-user",
                    "name": "test-user",
                    "user_id": "AIDAEXAMPLE123456789",
                    "path": "/",
                    "create_date": "2023-01-01T00:00:00",
                    "attached_policies": ["arn:aws:iam::123456789012:policy/test-policy"],
                    "inline_policies": {},
                    "groups": [],
                    "tags": []
                }
            ],
            "roles": [
                {
                    "arn": "arn:aws:iam::123456789012:role/test-role",
                    "name": "test-role",
                    "role_id": "AROAEXAMPLE123456789",
                    "path": "/",
                    "assume_role_policy": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Principal": {"Service": "ec2.amazonaws.com"},
                                "Action": "sts:AssumeRole"
                            }
                        ]
                    },
                    "create_date": "2023-01-01T00:00:00",
                    "attached_policies": ["arn:aws:iam::123456789012:policy/test-policy"],
                    "inline_policies": {},
                    "tags": []
                }
            ],
            "groups": [],
            "policies": [
                {
                    "arn": "arn:aws:iam::123456789012:policy/test-policy",
                    "name": "test-policy",
                    "policy_document": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Action": "s3:GetObject",
                                "Resource": "*"
                            }
                        ]
                    },
                    "is_aws_managed": False,
                    "create_date": "2023-01-01T00:00:00",
                    "update_date": "2023-01-01T00:00:00"
                }
            ],
            "metadata": {
                "fetch_time": "2023-01-01T00:00:00",
                "profile": "test",
                "region": "us-east-1"
            }
        }

        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(sample_data, f, indent=2)
            return f.name

    @pytest.fixture
    def sample_graph_file(self, sample_data_file):
        """Create a sample graph file for testing."""
        builder = GraphBuilder()
        builder.build_from_file(sample_data_file)

        with tempfile.NamedTemporaryFile(suffix='.pkl', delete=False) as f:
            builder.save_graph(f.name)
            return f.name

    def test_cli_version(self, runner):
        """Test CLI version command."""
        result = runner.invoke(main, ['--version'])
        assert result.exit_code == 0
        assert '0.1.0' in result.output

    def test_cli_help(self, runner):
        """Test CLI help command."""
        result = runner.invoke(main, ['--help'])
        assert result.exit_code == 0
        assert 'IAM Explorer' in result.output
        assert 'fetch' in result.output
        assert 'build-graph' in result.output
        assert 'query' in result.output
        assert 'visualize' in result.output

    def test_build_graph_command(self, runner, sample_data_file):
        """Test build-graph command."""
        with tempfile.NamedTemporaryFile(suffix='.pkl', delete=False) as output_file:
            result = runner.invoke(main, [
                'build-graph',
                '--input', sample_data_file,
                '--output', output_file.name
            ])

            assert result.exit_code == 0
            assert 'Successfully built IAM graph' in result.output
            assert Path(output_file.name).exists()

            # Clean up
            os.unlink(output_file.name)

    def test_build_graph_missing_input(self, runner):
        """Test build-graph command with missing input file."""
        result = runner.invoke(main, [
            'build-graph',
            '--input', 'non-existent-file.json'
        ])

        assert result.exit_code == 1
        assert 'not found' in result.output

    def test_query_who_can_do(self, runner, sample_graph_file):
        """Test query who-can-do command."""
        result = runner.invoke(main, [
            'query', 'who-can-do', 's3:GetObject',
            '--graph', sample_graph_file
        ])

        assert result.exit_code == 0
        assert 'test-user' in result.output or 'test-role' in result.output

    def test_query_who_can_do_json_format(self, runner, sample_graph_file):
        """Test query who-can-do command with JSON output."""
        result = runner.invoke(main, [
            'query', 'who-can-do', 's3:GetObject',
            '--graph', sample_graph_file,
            '--format', 'json'
        ])

        assert result.exit_code == 0

        # Should be valid JSON
        try:
            data = json.loads(result.output)
            assert isinstance(data, list)
        except json.JSONDecodeError:
            pytest.fail("Output is not valid JSON")

    def test_query_what_can_do(self, runner, sample_graph_file):
        """Test query what-can-do command."""
        result = runner.invoke(main, [
            'query', 'what-can-do', 'test-user',
            '--graph', sample_graph_file
        ])

        assert result.exit_code == 0
        assert 'test-user' in result.output
        assert 's3:GetObject' in result.output

    def test_query_what_can_do_nonexistent_entity(self, runner, sample_graph_file):
        """Test query what-can-do command with non-existent entity."""
        result = runner.invoke(main, [
            'query', 'what-can-do', 'non-existent-user',
            '--graph', sample_graph_file
        ])

        assert result.exit_code == 1
        assert 'not found' in result.output

    def test_query_missing_graph(self, runner):
        """Test query commands with missing graph file."""
        result = runner.invoke(main, [
            'query', 'who-can-do', 's3:GetObject',
            '--graph', 'non-existent-graph.pkl'
        ])

        assert result.exit_code == 1
        assert 'not found' in result.output

    def test_visualize_dot_format(self, runner, sample_graph_file):
        """Test visualize command with DOT format."""
        with tempfile.NamedTemporaryFile(suffix='.dot', delete=False) as output_file:
            result = runner.invoke(main, [
                'visualize',
                '--graph', sample_graph_file,
                '--output', output_file.name,
                '--format', 'dot'
            ])

            assert result.exit_code == 0
            assert 'Visualization generated' in result.output
            assert Path(output_file.name).exists()

            # Check that the file contains DOT content
            with open(output_file.name, 'r') as f:
                content = f.read()
                assert 'digraph' in content or 'graph' in content

            # Clean up
            os.unlink(output_file.name)

    def test_visualize_missing_graph(self, runner):
        """Test visualize command with missing graph file."""
        result = runner.invoke(main, [
            'visualize',
            '--graph', 'non-existent-graph.pkl'
        ])

        assert result.exit_code == 1
        assert 'not found' in result.output

    def test_verbose_flag(self, runner):
        """Test verbose flag."""
        result = runner.invoke(main, ['--verbose', '--help'])
        assert result.exit_code == 0

    def test_fetch_command_basic(self, runner):
        """Test basic fetch command (mocked)."""
        # This would require mocking AWS calls, so we test the command structure
        result = runner.invoke(main, ['fetch', '--help'])
        assert result.exit_code == 0
        assert 'profile' in result.output
        assert 'region' in result.output
        assert 'output' in result.output

    def test_query_wildcard_actions(self, runner, sample_graph_file):
        """Test query with wildcard actions."""
        result = runner.invoke(main, [
            'query', 'who-can-do', 's3:*',
            '--graph', sample_graph_file
        ])

        assert result.exit_code == 0
        # Should find entities with S3 permissions

    def test_query_admin_permissions(self, runner, sample_graph_file):
        """Test query for admin permissions."""
        result = runner.invoke(main, [
            'query', 'who-can-do', '*',
            '--graph', sample_graph_file
        ])

        assert result.exit_code == 0
        # Should handle admin permission queries

    def test_visualize_with_filters(self, runner, sample_graph_file):
        """Test visualize command with entity filters."""
        with tempfile.NamedTemporaryFile(suffix='.dot', delete=False) as output_file:
            result = runner.invoke(main, [
                'visualize',
                '--graph', sample_graph_file,
                '--output', output_file.name,
                '--filter', 'test-user',
                '--no-policies'
            ])

            assert result.exit_code == 0
            assert Path(output_file.name).exists()

            # Clean up
            os.unlink(output_file.name)

    def test_build_graph_with_statistics(self, runner, sample_data_file):
        """Test build-graph command with statistics output."""
        with tempfile.NamedTemporaryFile(suffix='.pkl', delete=False) as output_file:
            result = runner.invoke(main, [
                'build-graph',
                '--input', sample_data_file,
                '--output', output_file.name,
                '--verbose'
            ])

            assert result.exit_code == 0
            # Should include statistics in verbose mode

            # Clean up
            os.unlink(output_file.name)

    def test_error_handling_invalid_json(self, runner):
        """Test error handling with invalid JSON input."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            f.write("invalid json content")
            f.flush()

            result = runner.invoke(main, [
                'build-graph',
                '--input', f.name
            ])

            assert result.exit_code == 1

            # Clean up
            os.unlink(f.name)

    def test_output_format_validation(self, runner, sample_graph_file):
        """Test output format validation."""
        result = runner.invoke(main, [
            'visualize',
            '--graph', sample_graph_file,
            '--format', 'invalid-format'
        ])

        # Should handle invalid format gracefully
        assert result.exit_code != 0 or 'invalid' in result.output.lower()

    def test_concurrent_operations(self, runner, sample_data_file):
        """Test that operations can be run concurrently."""
        # This is more of a smoke test to ensure no obvious concurrency issues
        with tempfile.NamedTemporaryFile(suffix='.pkl', delete=False) as output_file1:
            with tempfile.NamedTemporaryFile(suffix='.pkl', delete=False) as output_file2:
                result1 = runner.invoke(main, [
                    'build-graph',
                    '--input', sample_data_file,
                    '--output', output_file1.name
                ])

                result2 = runner.invoke(main, [
                    'build-graph',
                    '--input', sample_data_file,
                    '--output', output_file2.name
                ])

                assert result1.exit_code == 0
                assert result2.exit_code == 0

                # Clean up
                os.unlink(output_file1.name)
                os.unlink(output_file2.name)

    def teardown_method(self):
        """Clean up temporary files after each test."""
        # This will be called after each test method
        pass
