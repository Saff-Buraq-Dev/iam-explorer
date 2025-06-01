"""
Command-line interface for IAM Explorer.
"""

import json
import logging
import sys
from pathlib import Path
from typing import Optional

import click

from . import __version__
from .fetcher import IAMFetcher
from .graph_builder import GraphBuilder
from .query_engine import QueryEngine
from .visualizer import GraphVisualizer

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


@click.group()
@click.version_option(version=__version__)
@click.option('--verbose', '-v', is_flag=True, help='Enable verbose logging')
def main(verbose: bool):
    """
    IAM Explorer - A CLI tool to visualize AWS IAM relationships and answer permission queries.

    This tool helps you understand complex IAM relationships by building a graph of users,
    roles, groups, and policies, then allows you to query permissions and visualize relationships.
    """
    if verbose:
        logging.getLogger().setLevel(logging.DEBUG)
        logger.debug("Verbose logging enabled")


@main.command()
@click.option('--profile', '-p', help='AWS profile to use')
@click.option('--region', '-r', default='us-east-1', help='AWS region')
@click.option('--output', '-o', default='iam_data.json', help='Output file for IAM data')
@click.option('--include-aws-managed', is_flag=True,
              help='Include AWS managed policies (warning: large output)')
def fetch(profile: Optional[str], region: str, output: str, include_aws_managed: bool):
    """
    Fetch IAM data from AWS.

    This command connects to AWS and fetches all IAM users, roles, groups, and policies
    from your account. The data is saved to a JSON file for later processing.
    """
    try:
        click.echo(f"Fetching IAM data from AWS (profile: {profile or 'default'}, region: {region})...")

        fetcher = IAMFetcher(profile_name=profile, region_name=region)
        data = fetcher.fetch_all_data()

        # Add AWS managed policies if requested
        if include_aws_managed:
            click.echo("Fetching AWS managed policies (this may take a while)...")
            aws_policies = fetcher.fetch_aws_managed_policies()
            data['policies'].extend(aws_policies)

        fetcher.save_data(data, output)

        click.echo("✅ Successfully fetched IAM data:")
        click.echo(f"   - Users: {len(data['users'])}")
        click.echo(f"   - Roles: {len(data['roles'])}")
        click.echo(f"   - Groups: {len(data['groups'])}")
        click.echo(f"   - Policies: {len(data['policies'])}")
        click.echo(f"   - Saved to: {output}")

    except Exception as e:
        click.echo(f"❌ Error fetching IAM data: {e}", err=True)
        sys.exit(1)


@main.command()
@click.option('--input', '-i', default='iam_data.json', help='Input JSON file with IAM data')
@click.option('--output', '-o', default='iam_graph.pkl', help='Output file for the graph')
def build_graph(input: str, output: str):
    """
    Build a graph from fetched IAM data.

    This command processes the JSON data from the fetch command and builds a graph
    representation of all IAM relationships, including trust relationships,
    policy attachments, and group memberships.
    """
    try:
        if not Path(input).exists():
            click.echo(f"❌ Input file '{input}' not found. Run 'iam-explorer fetch' first.", err=True)
            sys.exit(1)

        click.echo(f"Building graph from {input}...")

        builder = GraphBuilder()
        graph = builder.build_from_file(input)
        builder.save_graph(output)

        click.echo("✅ Successfully built IAM graph:")
        click.echo(f"   - Nodes: {len(graph.graph.nodes)}")
        click.echo(f"   - Edges: {len(graph.graph.edges)}")
        click.echo(f"   - Saved to: {output}")

    except Exception as e:
        click.echo(f"❌ Error building graph: {e}", err=True)
        sys.exit(1)


@main.group()
def query():
    """Query IAM permissions and relationships."""
    pass


@query.command('who-can-do')
@click.argument('action')
@click.option('--resource', '-r', default='*', help='Resource ARN or pattern')
@click.option('--graph', '-g', default='iam_graph.pkl', help='Graph file to use')
@click.option('--format', '-f', type=click.Choice(['table', 'json']), default='table',
              help='Output format')
def who_can_do(action: str, resource: str, graph: str, format: str):
    """
    Find who can perform a specific action.

    ACTION: AWS action to query (e.g., 's3:GetObject', 'ec2:*')

    Examples:
      iam-explorer query who-can-do s3:GetObject
      iam-explorer query who-can-do ec2:DescribeInstances --resource "arn:aws:ec2:*:*:instance/*"
    """
    try:
        if not Path(graph).exists():
            click.echo(f"❌ Graph file '{graph}' not found. Run 'iam-explorer build-graph' first.", err=True)
            sys.exit(1)

        builder = GraphBuilder()
        iam_graph = builder.load_graph(graph)

        engine = QueryEngine(iam_graph)
        results = engine.who_can_do(action, resource)

        if format == 'json':
            click.echo(json.dumps(results, indent=2))
        else:
            _display_who_can_do_table(results, action, resource)

    except Exception as e:
        click.echo(f"❌ Error querying permissions: {e}", err=True)
        sys.exit(1)


@query.command('what-can-do')
@click.argument('entity_name')
@click.option('--graph', '-g', default='iam_graph.pkl', help='Graph file to use')
@click.option('--format', '-f', type=click.Choice(['table', 'json']), default='table',
              help='Output format')
def what_can_do(entity_name: str, graph: str, format: str):
    """
    Find what an entity (user/role/group) can do.

    ENTITY_NAME: Name of the user, role, or group to query

    Examples:
      iam-explorer query what-can-do my-user
      iam-explorer query what-can-do my-role
    """
    try:
        if not Path(graph).exists():
            click.echo(f"❌ Graph file '{graph}' not found. Run 'iam-explorer build-graph' first.", err=True)
            sys.exit(1)

        builder = GraphBuilder()
        iam_graph = builder.load_graph(graph)

        engine = QueryEngine(iam_graph)
        result = engine.what_can_entity_do(entity_name)

        if 'error' in result:
            click.echo(f"❌ {result['error']}", err=True)
            sys.exit(1)

        if format == 'json':
            click.echo(json.dumps(result, indent=2))
        else:
            _display_what_can_do_table(result)

    except Exception as e:
        click.echo(f"❌ Error querying permissions: {e}", err=True)
        sys.exit(1)


@main.command()
@click.option('--graph', '-g', default='iam_graph.pkl', help='Graph file to use')
@click.option('--output', '-o', default='iam_graph.dot', help='Output DOT file')
@click.option('--format', '-f', type=click.Choice(['dot', 'png', 'svg']), default='dot',
              help='Output format')
@click.option('--include-policies/--no-policies', default=True,
              help='Include policy nodes in visualization')
@click.option('--filter', multiple=True, help='Filter to specific entities (can be used multiple times)')
def visualize(graph: str, output: str, format: str, include_policies: bool, filter: tuple):
    """
    Generate a visual representation of the IAM graph.

    This command creates a visual representation of IAM relationships that can be
    viewed in various formats. The DOT format can be converted to images using Graphviz.

    Examples:
      iam-explorer visualize --format png --output iam_graph.png
      iam-explorer visualize --filter my-user --filter my-role
    """
    try:
        if not Path(graph).exists():
            click.echo(f"❌ Graph file '{graph}' not found. Run 'iam-explorer build-graph' first.", err=True)
            sys.exit(1)

        builder = GraphBuilder()
        iam_graph = builder.load_graph(graph)

        visualizer = GraphVisualizer(iam_graph)
        filter_entities = list(filter) if filter else None

        click.echo(f"Generating {format} visualization...")

        if format == 'dot':
            visualizer.generate_dot(output, include_policies, filter_entities)
        elif format in ['png', 'svg']:
            # Use matplotlib for image formats
            visualizer.generate_matplotlib(output, include_policies=include_policies,
                                           filter_entities=filter_entities)

        # Display stats
        stats = visualizer.get_graph_stats()
        click.echo("✅ Visualization generated:")
        click.echo(f"   - Nodes: {stats['total_nodes']}")
        click.echo(f"   - Edges: {stats['total_edges']}")
        click.echo(f"   - Output: {output}")

        if format == 'dot':
            click.echo(f"\n💡 To convert to PNG: dot -Tpng {output} -o {output.replace('.dot', '.png')}")

    except Exception as e:
        click.echo(f"❌ Error generating visualization: {e}", err=True)
        sys.exit(1)


def _display_who_can_do_table(results, action: str, resource: str):
    """Display who-can-do results in table format."""
    click.echo(f"\n🔍 Who can perform '{action}' on '{resource}':\n")

    if not results:
        click.echo("   No entities found with this permission.")
        return

    for result in results:
        entity_type = result['type'].upper()
        name = result['name']
        arn = result['arn']

        click.echo(f"   {entity_type}: {name}")
        click.echo(f"   ARN: {arn}")

        if result['type'] == 'role' and result.get('can_be_assumed_by'):
            click.echo(f"   Can be assumed by: {', '.join(result['can_be_assumed_by'])}")

        if result.get('path'):
            click.echo(f"   Permission path: {', '.join(result['path'])}")

        click.echo()


def _display_what_can_do_table(result):
    """Display what-can-do results in table format."""
    entity_name = result['entity_name']
    entity_type = result['entity_type'].upper()

    click.echo(f"\n🔍 Permissions for {entity_type}: {entity_name}\n")
    click.echo(f"   ARN: {result['entity_arn']}")
    click.echo(f"   Policies applied: {result['policies_applied']}")

    if result.get('assumable_roles'):
        click.echo(f"   Can assume: {', '.join(result['assumable_roles'])}")

    effective_actions = result.get('effective_actions', [])
    denied_actions = result.get('denied_actions', [])

    click.echo(f"\n   Effective permissions ({len(effective_actions)} actions):")
    for action in effective_actions[:10]:  # Show first 10
        click.echo(f"     ✅ {action}")

    if len(effective_actions) > 10:
        click.echo(f"     ... and {len(effective_actions) - 10} more")

    if denied_actions:
        click.echo(f"\n   Denied actions ({len(denied_actions)}):")
        for action in denied_actions[:5]:  # Show first 5
            click.echo(f"     ❌ {action}")

        if len(denied_actions) > 5:
            click.echo(f"     ... and {len(denied_actions) - 5} more")


if __name__ == '__main__':
    main()
