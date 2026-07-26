#!/usr/bin/env python3
"""Export Cortex Cloud issues to CSV using API-side filters from config.json."""

from __future__ import annotations

import argparse
import csv
import gzip
import json
import os
import sys
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, TextIO

import requests

API_PATH = "/public_api/v1/issue/search"
MAX_PAGE_SIZE = 100


def load_config(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as file:
        config = json.load(file)

    required = ("fqdn", "key_id", "api_key")
    missing = [field for field in required if not config.get(field)]

    if missing:
        raise ValueError(
            "Missing required configuration field(s): "
            + ", ".join(missing)
        )

    filters = config.get("api_filters", [])
    if not isinstance(filters, list):
        raise ValueError("api_filters must be a JSON array.")

    return config


def build_url(config: Dict[str, Any]) -> str:
    fqdn = str(config["fqdn"]).strip()

    for prefix in ("https://", "http://"):
        if fqdn.startswith(prefix):
            fqdn = fqdn[len(prefix):]

    return f"https://{fqdn.rstrip('/')}{API_PATH}"


def build_headers(config: Dict[str, Any]) -> Dict[str, str]:
    return {
        "Authorization": str(config["api_key"]),
        "x-xdr-auth-id": str(config["key_id"]),
        "Content-Type": "application/json",
        "Accept": "application/json",
    }


def flatten_json(
    value: Any,
    parent_key: str = "",
    separator: str = ".",
) -> Dict[str, Any]:
    flattened: Dict[str, Any] = {}

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
        flattened[parent_key] = json.dumps(
            value,
            ensure_ascii=False,
            separators=(",", ":"),
        )
    else:
        flattened[parent_key] = value

    return flattened


def request_page(
    session: requests.Session,
    url: str,
    headers: Dict[str, str],
    api_filters: List[Dict[str, Any]],
    search_from: int,
    search_to: int,
    max_retries: int,
    timeout: int,
    debug: bool,
) -> Dict[str, Any]:
    body = {
        "request_data": {
            "filters": api_filters,
            "search_from": search_from,
            "search_to": search_to,
        }
    }

    if debug:
        print("\nRequest body:")
        print(json.dumps(body, indent=2))

    for attempt in range(1, max_retries + 1):
        try:
            response = session.post(
                url,
                headers=headers,
                json=body,
                timeout=timeout,
            )

            if response.status_code == 200:
                payload = response.json()

                if debug:
                    reply = payload.get("reply", {})
                    data = reply.get("DATA", [])
                    print(
                        "Response metadata: "
                        f"TOTAL_COUNT={reply.get('TOTAL_COUNT')}, "
                        f"FILTER_COUNT={reply.get('FILTER_COUNT')}, "
                        f"DATA={len(data) if isinstance(data, list) else 'invalid'}"
                    )

                return payload

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

            raise RuntimeError(
                f"Non-retryable API error: HTTP {response.status_code}"
            )

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


def open_output(path: str, compress: bool) -> TextIO:
    if compress:
        return gzip.open(
            path,
            "wt",
            encoding="utf-8-sig",
            newline="",
        )

    return open(
        path,
        "w",
        encoding="utf-8-sig",
        newline="",
    )


def print_filters(filters: List[Dict[str, Any]]) -> None:
    print("API filters:")

    if not filters:
        print("  None")
        return

    for rule in filters:
        print(
            f"  {rule.get('field')} "
            f"{rule.get('operator')} "
            f"{rule.get('value')}"
        )


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Export Cortex Cloud issues to CSV"
    )
    parser.add_argument(
        "--config",
        required=True,
        help="Path to config.json",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Print request bodies and response metadata",
    )
    args = parser.parse_args()

    try:
        config = load_config(args.config)
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(f"Configuration error: {error}")
        sys.exit(1)

    url = build_url(config)
    headers = build_headers(config)
    api_filters = config.get("api_filters", [])

    page_size = min(
        max(int(config.get("page_size", MAX_PAGE_SIZE)), 1),
        MAX_PAGE_SIZE,
    )
    output_file = str(config.get("output", "issues.csv"))
    max_retries = int(config.get("retry_count", 5))
    timeout = int(config.get("timeout", 60))
    compress = bool(config.get("gzip", False))

    if compress and not output_file.endswith(".gz"):
        output_file += ".gz"

    if os.path.exists(output_file):
        os.remove(output_file)

    search_from = 0
    exported = 0
    page_number = 0
    filtered_count: Optional[int] = None
    writer: Optional[csv.DictWriter] = None
    csv_file: Optional[TextIO] = None
    started_at = time.time()
    session = requests.Session()

    print("=" * 72)
    print(" Cortex Cloud Issues Exporter")
    print("=" * 72)
    print(f"Endpoint       : {url}")
    print(f"Page size      : {page_size}")
    print(f"Output         : {output_file}")
    print(f"Started        : {datetime.now(timezone.utc).isoformat()}")
    print_filters(api_filters)
    print("=" * 72)

    try:
        while True:
            search_to = search_from + page_size
            page_number += 1

            payload = request_page(
                session=session,
                url=url,
                headers=headers,
                api_filters=api_filters,
                search_from=search_from,
                search_to=search_to,
                max_retries=max_retries,
                timeout=timeout,
                debug=args.debug,
            )

            reply = payload.get("reply", {})
            issues = reply.get("DATA", [])

            if not isinstance(issues, list):
                raise RuntimeError(
                    "Unexpected API response: reply.DATA is not a list."
                )

            api_filter_count = reply.get("FILTER_COUNT")
            if isinstance(api_filter_count, int):
                filtered_count = api_filter_count

            if not issues:
                break

            flattened_issues = [
                flatten_json(issue)
                for issue in issues
            ]

            if writer is None:
                fieldnames = sorted(
                    {
                        key
                        for issue in flattened_issues
                        for key in issue.keys()
                    }
                )

                csv_file = open_output(output_file, compress)
                writer = csv.DictWriter(
                    csv_file,
                    fieldnames=fieldnames,
                    extrasaction="ignore",
                )
                writer.writeheader()

            for issue in flattened_issues:
                writer.writerow(issue)

            if csv_file is not None:
                csv_file.flush()

            exported += len(issues)
            elapsed = time.time() - started_at
            rate = exported / elapsed if elapsed > 0 else 0
            target = (
                str(filtered_count)
                if filtered_count is not None
                else "unknown"
            )

            print(
                f"\rPage {page_number:>5} | "
                f"Exported {exported:>8}/{target:<8} | "
                f"{rate:>7.1f} issues/sec",
                end="",
                flush=True,
            )

            search_from += len(issues)

            if filtered_count is not None and exported >= filtered_count:
                break

            if len(issues) < page_size:
                break

    except KeyboardInterrupt:
        print("\n\nExport interrupted by the user.")
        print(f"Exported before interruption: {exported}")
        sys.exit(130)

    except Exception as error:
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
    print("=" * 72)
    print(" Export complete")
    print("=" * 72)
    print(f"Filtered count : {filtered_count}")
    print(f"Exported       : {exported} issues")
    print(f"Pages          : {page_number}")
    print(f"Output         : {output_file}")
    print(f"File size      : {file_size_mb:.2f} MB")
    print(f"Elapsed        : {elapsed:.1f} seconds")
    print("=" * 72)


if __name__ == "__main__":
    main()

