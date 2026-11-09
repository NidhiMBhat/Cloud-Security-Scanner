import boto3
from botocore.exceptions import BotoCoreError, ClientError

def get_s3_client(region_name="us-east-1"):
    """
    Initializes and returns a boto3 S3 client.
    Catch exceptions if credentials are missing or invalid.
    """
    try:
        s3_client = boto3.client("s3", region_name=region_name)
        return s3_client
    except (BotoCoreError, ClientError) as e:
        print(f"[-] Error initializing AWS S3 client: {e}")
        return None

def list_s3_buckets(s3_client):
    """
    Discovers all S3 buckets accessible by the current credentials.
    """
    try:
        response = s3_client.list_buckets()
        return [bucket["Name"] for bucket in response.get("Buckets", [])]
    except ClientError as e:
        print(f"[-] Failed to list S3 buckets: {e}")
        return []