import click
import json
from iam_explorer.fetch import IAMFetcher
from iam_explorer.graph import IAMGraph
from iam_explorer.utils import check_aws_credentials


@click.group()
def cli():
    """IAM Explorer CLI tool."""
    pass


@click.command()
@click.option("--profile", default=None, help="AWS profile to use")
@check_aws_credentials
def scan(profile):
    """Scan AWS IAM and build a permission graph."""
    fetcher = IAMFetcher(aws_profile=profile)
    iam_data = fetcher.fetch_all()

    graph = IAMGraph()
    graph.build_graph(iam_data)

    click.echo(json.dumps(graph.get_graph(), indent=2))


cli.add_command(scan)

if __name__ == "__main__":
    cli()
