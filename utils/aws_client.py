import boto3
from botocore.exceptions import NoCredentialsError, ProfileNotFound

_session = None

def init_session(profile: str = None, region: str = "us-east-1"):
    global _session
    try:
        _session = boto3.Session(profile_name=profile, region_name=region)
    except ProfileNotFound:
        raise SystemExit(f"[ERROR] AWS profile '{profile}' not found.")

def get_client(service: str, region: str = None):
    global _session
    if _session is None:
        _session = boto3.Session()
    try:
        return _session.client(service, region_name=region)
    except NoCredentialsError:
        raise SystemExit("[ERROR] No AWS credentials found. Run `aws configure`.")

def get_account_id() -> str:
    sts = get_client("sts")
    return sts.get_caller_identity()["Account"]
