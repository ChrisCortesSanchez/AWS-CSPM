import sys
sys.path.insert(0, '.')

from utils.aws_client import init_session, get_account_id
from scanners.s3 import S3Scanner

init_session(region="us-east-1")
print(f"Account: {get_account_id()}")
print("Running S3 scanner...\n")

scanner = S3Scanner(region="us-east-1")
findings = scanner.run()

if not findings:
    print("No S3 buckets found.")
else:
    for f in findings:
        status = "PASS" if f.passed else "FAIL"
        print(f"[{status}] {f.check_id} | {f.severity.value} | {f.title} | {f.resource}")

print(f"\nDone. {len([f for f in findings if not f.passed])} findings.")
