"""
Simple CLI tests that focus on command structure and basic functionality.
"""

from click.testing import CliRunner
from iam_explorer.cli import main


class TestCLIBasic:
    """Basic CLI tests."""

    def test_main_help(self):
        """Test main help command."""
        runner = CliRunner()
        result = runner.invoke(main, ["--help"])
        assert result.exit_code == 0
        assert "IAM Explorer" in result.output
        assert "fetch" in result.output
        assert "build-graph" in result.output
        assert "query" in result.output
        assert "visualize" in result.output

    def test_fetch_help(self):
        """Test fetch command help."""
        runner = CliRunner()
        result = runner.invoke(main, ["fetch", "--help"])
        assert result.exit_code == 0
        assert "profile" in result.output
        assert "region" in result.output
        assert "output" in result.output

    def test_build_graph_help(self):
        """Test build-graph command help."""
        runner = CliRunner()
        result = runner.invoke(main, ["build-graph", "--help"])
        assert result.exit_code == 0
        assert "input" in result.output
        assert "output" in result.output

    def test_query_help(self):
        """Test query command help."""
        runner = CliRunner()
        result = runner.invoke(main, ["query", "--help"])
        assert result.exit_code == 0
        assert "who-can-do" in result.output
        assert "what-can-do" in result.output

    def test_visualize_help(self):
        """Test visualize command help."""
        runner = CliRunner()
        result = runner.invoke(main, ["visualize", "--help"])
        assert result.exit_code == 0
        assert "output" in result.output
        assert "format" in result.output

    def test_who_can_do_help(self):
        """Test who-can-do subcommand help."""
        runner = CliRunner()
        result = runner.invoke(main, ["query", "who-can-do", "--help"])
        assert result.exit_code == 0
        assert "action" in result.output

    def test_what_can_do_help(self):
        """Test what-can-do subcommand help."""
        runner = CliRunner()
        result = runner.invoke(main, ["query", "what-can-do", "--help"])
        assert result.exit_code == 0
        assert "ENTITY_NAME" in result.output

    def test_invalid_command(self):
        """Test invalid command."""
        runner = CliRunner()
        result = runner.invoke(main, ["invalid-command"])
        assert result.exit_code != 0

    def test_missing_required_args(self):
        """Test commands with missing required arguments."""
        runner = CliRunner()

        # fetch without output
        result = runner.invoke(main, ["fetch"])
        assert result.exit_code != 0

        # build-graph without input
        result = runner.invoke(main, ["build-graph"])
        assert result.exit_code != 0

        # query who-can-do without action
        result = runner.invoke(main, ["query", "who-can-do"])
        assert result.exit_code != 0

        # query what-can-do without entity
        result = runner.invoke(main, ["query", "what-can-do"])
        assert result.exit_code != 0

        # visualize without output
        result = runner.invoke(main, ["visualize"])
        assert result.exit_code != 0
