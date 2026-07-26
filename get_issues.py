import argparse
import json
import sys

import requests

API_PATH = "/public_api/v1/issue/search"


def load_config(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def headers(cfg):
    return {
        "Authorization": cfg["api_key"],
        "x-xdr-auth-id": str(cfg["key_id"]),
        "Content-Type": "application/json",
        "Accept": "application/json",
    }


def build_url(cfg):
    return f"https://{cfg['fqdn'].rstrip('/')}{API_PATH}"


def main():
    parser = argparse.ArgumentParser(description="Cortex Cloud Issues Exporter")
    parser.add_argument("--config", required=True)
    args = parser.parse_args()

    cfg = load_config(args.config)
    url = build_url(cfg)

    print("=" * 60)
    print(" Cortex Cloud Issues Exporter")
    print("=" * 60)
    print(f"Endpoint : {url}")
    print(f"Page Size: {cfg.get('page_size', 1000)}")
    print(f"Output   : {cfg.get('output', 'issues.csv')}")
    print()

    body = {
        "request_data": {
            "filters": cfg.get("filters", []),
            "search_from": 0,
            "search_to": cfg.get("page_size", 1000),
            "sort": [
                {
                    "field": "id",
                    "keyword": "desc"
                }
            ]
        }
    }

    print("Headers:")
    debug_headers = headers(cfg).copy()
    debug_headers["Authorization"] = "***REDACTED***"
    print(json.dumps(debug_headers, indent=2))

    print("\nRequest Body:")
    print(json.dumps(body, indent=2))

    print("\nSending request...\n")

    try:
        response = requests.post(
            url=url,
            headers=headers(cfg),
            json=body,
            timeout=60,
        )

        print(f"HTTP Status: {response.status_code}\n")

        try:
            data = response.json()
        except Exception:
            print(response.text)
            sys.exit(1)

        if response.status_code != 200:
            print(json.dumps(data, indent=2))
            sys.exit(1)

        reply = data.get("reply", {})

        print("=" * 60)
        print("Request Successful")
        print("=" * 60)

        print(f"Total Issues    : {reply.get('total_count')}")
        print(f"Returned Issues : {reply.get('result_count')}")

        issues = reply.get("issues", [])

        if issues:
            print("\nFirst Issue:\n")
            print(json.dumps(issues[0], indent=2))
        else:
            print("\nNo issues returned.")

    except requests.exceptions.RequestException as e:
        print(f"Request failed:\n{e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
