from iam_explorer.fetch import fetch_iam_data, save_iam_data_to_json
import click


@click.group()
def main():
    """
    iam-explorer CLI tool.
    """
    pass


@main.command()
@click.option("--profile", default=None, help="AWS CLI profile name.")
@click.option("--region", default=None, help="AWS region (e.g. us-east-1).")
@click.option("--output", default="iam_data.json", help="Output JSON file.")
def fetch(profile, region, output):
    """
    Fetch AWS IAM data (users, roles, etc.) and save to JSON.
    """
    click.echo("Fetching IAM data from AWS...")
    data = fetch_iam_data(profile_name=profile, region_name=region)
    save_iam_data_to_json(data, output_path=output)


if __name__ == "__main__":
    main()
