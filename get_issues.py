import argparse
import csv
import json
import os
import sys
import time
from typing import Any

import requests

API_PATH = "/public_api/v1/issue/search"
MAX_PAGE_SIZE = 100


def load_config(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as file:
        return json.load(file)


def build_headers(cfg: dict) -> dict:
    return {
        "Authorization": cfg["api_key"],
        "x-xdr-auth-id": str(cfg["key_id"]),
        "Content-Type": "application/json",
        "Accept": "application/json",
    }


def build_url(cfg: dict) -> str:
    fqdn = cfg["fqdn"].strip()

    if fqdn.startswith("https://"):
        fqdn = fqdn[len("https://"):]

    return f"https://{fqdn.rstrip('/')}{API_PATH}"


def flatten_json(
    value: Any,
    parent_key: str = "",
    separator: str = ".",
) -> dict:
    flattened = {}

    if isinstance(value, dict):
        for key, child_value in value.items():
            new_key = (
                f"{parent_key}{separator}{key}"
                if parent_key
                else str(key)
            )

            flattened.update(
                flatten_json(
                    child_value,
                    parent_key=new_key,
                    separator=separator,
                )
            )

    elif isinstance(value, list):
        # Preserve arrays inside one CSV cell as valid JSON.
        flattened[parent_key] = json.dumps(
            value,
            ensure_ascii=False,
        )

    else:
        flattened[parent_key] = value

    return flattened


def request_page(
    session: requests.Session,
    url: str,
    headers: dict,
    filters: list,
    search_from: int,
    search_to: int,
    max_retries: int,
    timeout: int,
) -> dict:
    body = {
        "request_data": {
            "filters": filters,
            "search_from": search_from,
            "search_to": search_to,
        }
    }

    for attempt in range(1, max_retries + 1):
        try:
            response = session.post(
                url,
                headers=headers,
                json=body,
                timeout=timeout,
            )

            if response.status_code == 200:
                return response.json()

            # Retry temporary server and throttling errors.
            if response.status_code == 429 or response.status_code >= 500:
                wait_seconds = min(2 ** attempt, 30)

                print(
                    f"\nTemporary HTTP {response.status_code}. "
                    f"Retrying in {wait_seconds}s "
                    f"({attempt}/{max_retries})..."
                )

                time.sleep(wait_seconds)
                continue

            print(f"\nHTTP Status: {response.status_code}")

            try:
                print(json.dumps(response.json(), indent=2))
            except ValueError:
                print(response.text)

            sys.exit(1)

        except requests.exceptions.RequestException as error:
            if attempt == max_retries:
                raise

            wait_seconds = min(2 ** attempt, 30)

            print(
                f"\nRequest error: {error}\n"
                f"Retrying in {wait_seconds}s "
                f"({attempt}/{max_retries})..."
            )

            time.sleep(wait_seconds)

    raise RuntimeError("Maximum retries reached.")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Export all Cortex Cloud issues to CSV"
    )

    parser.add_argument(
        "--config",
        required=True,
        help="Path to config.json",
    )

    args = parser.parse_args()
    cfg = load_config(args.config)

    url = build_url(cfg)
    headers = build_headers(cfg)

    page_size = min(
        int(cfg.get("page_size", MAX_PAGE_SIZE)),
        MAX_PAGE_SIZE,
    )

    output_file = cfg.get("output", "issues.csv")
    filters = cfg.get("filters", [])
    max_retries = int(cfg.get("retry_count", 5))
    timeout = int(cfg.get("timeout", 60))

    search_from = 0
    downloaded = 0
    page_number = 0
    writer = None
    csv_file = None
    fieldnames = None
    started_at = time.time()

    print("=" * 64)
    print(" Cortex Cloud Issues Exporter")
    print("=" * 64)
    print(f"Endpoint : {url}")
    print(f"Page size: {page_size}")
    print(f"Output   : {output_file}")
    print("=" * 64)

    if page_size <= 0:
        print("page_size must be greater than zero.")
        sys.exit(1)

    # Start a new export.
    if os.path.exists(output_file):
        os.remove(output_file)

    session = requests.Session()

    try:
        while True:
            search_to = search_from + page_size
            page_number += 1

            data = request_page(
                session=session,
                url=url,
                headers=headers,
                filters=filters,
                search_from=search_from,
                search_to=search_to,
                max_retries=max_retries,
                timeout=timeout,
            )

            reply = data.get("reply", {})
            issues = reply.get("DATA", [])

            if not isinstance(issues, list):
                print(
                    "\nUnexpected response format: "
                    "reply.DATA is not a list."
                )
                print(json.dumps(data, indent=2))
                sys.exit(1)

            if not issues:
                break

            flattened_issues = [
                flatten_json(issue)
                for issue in issues
            ]

            if writer is None:
                # Use all columns found on the first page.
                fieldnames = sorted(
                    {
                        key
                        for issue in flattened_issues
                        for key in issue.keys()
                    }
                )

                csv_file = open(
                    output_file,
                    "w",
                    encoding="utf-8-sig",
                    newline="",
                )

                writer = csv.DictWriter(
                    csv_file,
                    fieldnames=fieldnames,
                    extrasaction="ignore",
                )

                writer.writeheader()

            for issue in flattened_issues:
                writer.writerow(issue)

            csv_file.flush()

            downloaded += len(issues)
            elapsed = time.time() - started_at
            rate = downloaded / elapsed if elapsed > 0 else 0

            print(
                f"\rPage {page_number:>5} | "
                f"Downloaded {downloaded:>8} issues | "
                f"{rate:>7.1f} issues/sec",
                end="",
                flush=True,
            )

            search_from += len(issues)

            # A partial page means there are no more records.
            if len(issues) < page_size:
                break

    except KeyboardInterrupt:
        print("\n\nExport interrupted by the user.")
        print(f"Records already saved: {downloaded}")
        sys.exit(130)

    except requests.exceptions.RequestException as error:
        print(f"\n\nExport failed: {error}")
        sys.exit(1)

    finally:
        session.close()

        if csv_file is not None:
            csv_file.close()

    elapsed = time.time() - started_at
    file_size_mb = (
        os.path.getsize(output_file) / 1024 / 1024
        if os.path.exists(output_file)
        else 0
    )

    print("\n")
    print("=" * 64)
    print(" Export complete")
    print("=" * 64)
    print(f"Downloaded : {downloaded} issues")
    print(f"Pages      : {page_number}")
    print(f"Output     : {output_file}")
    print(f"File size  : {file_size_mb:.2f} MB")
    print(f"Elapsed    : {elapsed:.1f} seconds")
    print("=" * 64)


if __name__ == "__main__":
    main()
