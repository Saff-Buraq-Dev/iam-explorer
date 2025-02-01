import boto3
import botocore
import logging
import functools

logging.basicConfig(level=logging.INFO)


def check_aws_credentials(func):
    """Decorator to check AWS credentials before running any command."""
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        try:
            session = boto3.Session(profile_name=kwargs.get("profile"))
            iam_client = session.client("iam")
            iam_client.get_user()  # Check if credentials are valid
        except botocore.exceptions.NoCredentialsError:
            logging.error("AWS credentials not found. Please configure them using `aws configure`.")
            exit(1)
        except botocore.exceptions.ProfileNotFound:
            logging.error(f"AWS profile '{kwargs.get('profile')}' not found. Check your AWS credentials.")
            exit(1)
        except botocore.exceptions.ClientError as e:
            if e.response["Error"]["Code"] in ["InvalidClientTokenId", "AccessDenied"]:
                logging.error("Invalid AWS credentials or insufficient permissions.")
            else:
                logging.error(f"AWS error: {e}")
            exit(1)

        return func(*args, **kwargs)

    return wrapper
