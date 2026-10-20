import csv
import requests

BASE_URL = "http://localhost:3000"
TIMEOUT = 5

# Define test cases: list of dictionaries containing endpoint, method, and optional input/payload
test_cases = [
    {"endpoint": "/", "method": "GET", "params": None, "data": None},
    {
        "endpoint": "/rest/products/search",
        "method": "GET",
        "params": {"q": "apple"},
        "data": None,
    },
    {
        "endpoint": "/rest/products/search",
        "method": "GET",
        "params": {"q": "banana"},
        "data": None,
    },
    {
        "endpoint": "/rest/products/search",
        "method": "POST",
        "params": None,
        "data": {"q": "apple"},
    },
]

records = []

print("Starting HTTP Scan on local Juice Shop instance...\n")

for case in test_cases:
  url = BASE_URL + case["endpoint"]
  try:
    if case["method"] == "GET":
      response = requests.get(
          url, params=case["params"], timeout=TIMEOUT
      )
      payload_used = str(case["params"])
    elif case["method"] == "POST":
      response = requests.post(url, data=case["data"], timeout=TIMEOUT)
      payload_used = str(case["data"])

    # Extract required fields
    observation = {
        "endpoint": case["endpoint"],
        "method": case["method"],
        "payload": payload_used,
        "status_code": response.status_code,
        "response_length": len(response.content),
        "content_type": response.headers.get("Content-Type", "N/A"),
        "server": response.headers.get("Server", "N/A"),
    }

    records.append(observation)

    # Print easy-to-read record for each request
    print(
        f"[{observation['method']}] {observation['endpoint']} | Input:"
        f" {observation['payload']} | Status: {observation['status_code']} |"
        f" Length: {observation['response_length']} bytes"
    )

  except requests.RequestException as error:
    print(
        f"[-] Error connecting to {url} using {case['method']}: {error}"
    )
    records.append({
        "endpoint": case["endpoint"],
        "method": case["method"],
        "payload": str(case.get("params") or case.get("data")),
        "status_code": "CONNECTION_FAILED",
        "response_length": 0,
        "content_type": "N/A",
        "server": "N/A",
    })

# Save results as http_scan_results.csv
csv_filename = "http_scan_results.csv"
fieldnames = [
    "endpoint",
    "method",
    "payload",
    "status_code",
    "response_length",
    "content_type",
    "server",
]

with open(csv_filename, "w", newline="", encoding="utf-8") as file:
  writer = csv.DictWriter(file, fieldnames=fieldnames)
  writer.writeheader()
  writer.writerows(records)

print(f"\nScan complete. Results successfully saved to {csv_filename}.")