import sys
sys.path.insert(0, '.')

from utils.aws_client import init_session, get_account_id
from scanners.iam import IAMScanner

init_session(region="us-east-1")
print(f"Account: {get_account_id()}")
print("Running IAM scanner...\n")

scanner = IAMScanner(region="us-east-1")
findings = scanner.run()

for f in findings:
    status = "PASS" if f.passed else "FAIL"
    print(f"[{status}] {f.check_id} | {f.severity.value} | {f.title}")

print(f"\nDone. {len([f for f in findings if not f.passed])} findings.")