"""
Pytest configuration and shared fixtures for CSPM test suite.
Runs automatically before any test — no need to import it manually.
"""
import sys
import os

# Ensure project root is on the path so imports work from any directory
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

# Set dummy AWS credentials for moto — prevents real API calls during tests
os.environ.setdefault("AWS_ACCESS_KEY_ID", "testing")
os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "testing")
os.environ.setdefault("AWS_SECURITY_TOKEN", "testing")
os.environ.setdefault("AWS_SESSION_TOKEN", "testing")
os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")