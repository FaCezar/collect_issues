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
    print(f"Page Size: {cfg.get('page_size', 100)}")
    print(f"Output   : {cfg.get('output', 'issues.csv')}")
    print()

    body = {
        "request_data": {
            "filters": cfg.get("filters", []),
            "search_from": 0,
            "search_to": cfg.get("page_size", 100)
        }
    }

    print("Headers:")
    dbg = headers(cfg).copy()
    dbg["Authorization"] = "***REDACTED***"
    print(json.dumps(dbg, indent=2))

    print("\nBody:")
    print(json.dumps(body, indent=2))

    print("\nSending request...\n")

    try:
        response = requests.post(
            url,
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

        print(json.dumps(data, indent=2))

        if response.status_code != 200:
            sys.exit(1)

    except requests.exceptions.RequestException as e:
        print(f"\nRequest failed:\n{e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
