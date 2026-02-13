"""
Sample client script to test the QA Agent API
"""
import httpx
import time
import sys

API_URL = "http://localhost:8000"


def run_test(url: str, objective: str, credentials: dict = None):
    """Run a QA test and wait for results"""

    print(f"\n{'='*60}")
    print(f"Starting QA Test")
    print(f"URL: {url}")
    print(f"Objective: {objective}")
    print(f"{'='*60}\n")

    # Start the test
    payload = {
        "url": url,
        "objective": objective
    }
    if credentials:
        payload["credentials"] = credentials

    response = httpx.post(f"{API_URL}/test", json=payload)
    result = response.json()
    test_id = result["test_id"]

    print(f"Test started with ID: {test_id}")
    print("Waiting for completion...")

    # Poll for results
    while True:
        response = httpx.get(f"{API_URL}/test/{test_id}")
        status = response.json()

        if status["status"] == "completed":
            print("\n" + "="*60)
            print("TEST COMPLETED")
            print("="*60)
            print(f"Passed: {status['summary'].get('passed', 0)}")
            print(f"Failed: {status['summary'].get('failed', 0)}")

            if status['summary'].get('errors'):
                print("\nErrors found:")
                for error in status['summary']['errors']:
                    print(f"  - {error}")

            print(f"\nReport: {status.get('report_path')}")
            break

        elif status["status"] == "failed":
            print("\nTEST FAILED")
            print(f"Error: {status['summary']}")
            break

        else:
            print(".", end="", flush=True)
            time.sleep(2)

    return status


# Example tests
if __name__ == "__main__":
    # Test 1: Check a login flow
    # run_test(
    #     url="https://example.com",
    #     objective="login",
    #     credentials={
    #         "username": "test@example.com",
    #         "password": "testpass123"
    #     }
    # )

    # Test 2: Check a signup flow
    # run_test(
    #     url="https://example.com",
    #     objective="signup"
    # )

    # Test 3: Check a checkout flow
    # run_test(
    #     url="https://shop.example.com",
    #     objective="checkout"
    # )

    if len(sys.argv) > 1:
        url = sys.argv[1]
        objective = sys.argv[2] if len(sys.argv) > 2 else "login"
        run_test(url, objective)
    else:
        print("Usage: python test_client.py <url> [objective]")
        print("Objectives: login, signup, checkout, full_flow")
        print("\nExample:")
        print("  python test_client.py https://app.example.com login")
