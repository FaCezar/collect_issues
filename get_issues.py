"""Export Cortex Cloud issues to CSV with API-side category/severity filters."""

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

CATEGORY_OPTIONS = [
    "ATTACK PATH",
    "CODE",
    "CONFIGURATION",
    "DATA",
    "IDENTITY",
    "POSTURE",
    "VULNERABILITY",
]

SEVERITY_OPTIONS = [
    "LOW",
    "MEDIUM",
    "HIGH",
    "CRITICAL",
]


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


def choose_multiple(
    title: str,
    options: List[str],
) -> List[str]:
    while True:
        print(f"\n{title}\n")

        for index, value in enumerate(options, start=1):
            print(f"  {index}. {value}")

        all_index = len(options) + 1
        print(f"  {all_index}. ALL")

        raw = input(
            f"\nEnter selections separated by commas [{all_index}]: "
        ).strip()

        if not raw:
            return []

        try:
            selected_numbers = {
                int(item.strip())
                for item in raw.split(",")
                if item.strip()
            }
        except ValueError:
            print("Invalid input. Use numbers separated by commas.")
            continue

        if all_index in selected_numbers:
            return []

        if not selected_numbers:
            print("Select at least one option or ALL.")
            continue

        if any(
            number < 1 or number > len(options)
            for number in selected_numbers
        ):
            print("One or more selections are invalid.")
            continue

        return [
            options[number - 1]
            for number in sorted(selected_numbers)
        ]


def build_interactive_api_filters() -> List[Dict[str, Any]]:
    print("\n" + "=" * 72)
    print(" Interactive filter selection")
    print("=" * 72)

    categories = choose_multiple(
        "Select one or more categories:",
        CATEGORY_OPTIONS,
    )

    severities = choose_multiple(
        "Select one or more severities:",
        SEVERITY_OPTIONS,
    )

    filters: List[Dict[str, Any]] = []

    if categories:
        filters.append(
            {
                "field": "category",
                "operator": "in",
                "value": categories,
            }
        )

    if severities:
        filters.append(
            {
                "field": "severity",
                "operator": "in",
                "value": severities,
            }
        )

    return filters


def values_for_filter(
    filters: List[Dict[str, Any]],
    field: str,
) -> List[str]:
    for rule in filters:
        if rule.get("field") == field:
            value = rule.get("value", [])
            return value if isinstance(value, list) else [str(value)]

    return []


def default_output_name(filters: List[Dict[str, Any]]) -> str:
    categories = values_for_filter(filters, "category")
    severities = values_for_filter(filters, "severity")

    category_part = (
        "-".join(
            value.lower().replace(" ", "_")
            for value in categories
        )
        if categories
        else "all_categories"
    )

    severity_part = (
        "-".join(value.lower() for value in severities)
        if severities
        else "all_severities"
    )

    return f"issues_{category_part}_{severity_part}.csv"


def confirm_export(
    filters: List[Dict[str, Any]],
    output_file: str,
) -> bool:
    categories = values_for_filter(filters, "category")
    severities = values_for_filter(filters, "severity")

    print("\n" + "-" * 72)
    print("Export summary")
    print("-" * 72)
    print(
        "Categories : "
        + (", ".join(categories) if categories else "ALL")
    )
    print(
        "Severities : "
        + (", ".join(severities) if severities else "ALL")
    )
    print(f"Output     : {output_file}")
    print("-" * 72)

    answer = input("Start export? [Y/n]: ").strip().lower()
    return answer in ("", "y", "yes")


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
            "sort": {
                "field": "observation_time",
                "keyword": "desc",
            },
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
                    print(
                        "Response metadata: "
                        f"TOTAL_COUNT={reply.get('TOTAL_COUNT')}, "
                        f"FILTER_COUNT={reply.get('FILTER_COUNT')}, "
                        f"DATA={len(reply.get('DATA', []))}"
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


def print_filter_summary(
    filters: List[Dict[str, Any]],
) -> None:
    print("API filters:")

    if not filters:
        print("  None — all categories and severities")
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
        "--interactive",
        action="store_true",
        help="Select category and severity through a terminal menu",
    )
    parser.add_argument(
        "--non-interactive",
        action="store_true",
        help="Use api_filters and output from config.json",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Print request bodies and response metadata",
    )
    args = parser.parse_args()

    if args.interactive and args.non_interactive:
        print(
            "Use either --interactive or --non-interactive, not both."
        )
        sys.exit(2)

    try:
        config = load_config(args.config)
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(f"Configuration error: {error}")
        sys.exit(1)

    url = build_url(config)
    headers = build_headers(config)
    page_size = min(
        max(int(config.get("page_size", MAX_PAGE_SIZE)), 1),
        MAX_PAGE_SIZE,
    )
    max_retries = int(config.get("retry_count", 5))
    timeout = int(config.get("timeout", 60))
    compress = bool(config.get("gzip", False))

    use_menu = (
        args.interactive
        or (
            not args.non_interactive
            and sys.stdin.isatty()
        )
    )

    if use_menu:
        api_filters = build_interactive_api_filters()
        suggested_output = default_output_name(api_filters)
        output_answer = input(
            f"\nOutput filename [{suggested_output}]: "
        ).strip()
        output_file = output_answer or suggested_output

        if not confirm_export(api_filters, output_file):
            print("Export cancelled.")
            return
    else:
        api_filters = config.get("api_filters", [])
        output_file = str(config.get("output", "issues.csv"))

    if compress and not output_file.endswith(".gz"):
        output_file += ".gz"

    if os.path.exists(output_file):
        os.remove(output_file)

    search_from = 0
    downloaded = 0
    page_number = 0
    filtered_count: Optional[int] = None
    writer: Optional[csv.DictWriter] = None
    csv_file: Optional[TextIO] = None
    started_at = time.time()
    session = requests.Session()

    print("\n" + "=" * 72)
    print(" Cortex Cloud Issues Exporter")
    print("=" * 72)
    print(f"Endpoint       : {url}")
    print(f"Page size      : {page_size}")
    print(f"Output         : {output_file}")
    print(f"Started        : {datetime.now(timezone.utc).isoformat()}")
    print_filter_summary(api_filters)
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

            downloaded += len(issues)
            elapsed = time.time() - started_at
            rate = downloaded / elapsed if elapsed > 0 else 0
            target = (
                str(filtered_count)
                if filtered_count is not None
                else "unknown"
            )

            print(
                f"\rPage {page_number:>5} | "
                f"Exported {downloaded:>8}/{target:<8} | "
                f"{rate:>7.1f} issues/sec",
                end="",
                flush=True,
            )

            search_from += len(issues)

            if filtered_count is not None and downloaded >= filtered_count:
                break

            if len(issues) < page_size:
                break

    except KeyboardInterrupt:
        print("\n\nExport interrupted by the user.")
        print(f"Exported before interruption: {downloaded}")
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
    print(f"Exported       : {downloaded} issues")
    print(f"Pages          : {page_number}")
    print(f"Output         : {output_file}")
    print(f"File size      : {file_size_mb:.2f} MB")
    print(f"Elapsed        : {elapsed:.1f} seconds")
    print("=" * 72)


if __name__ == "__main__":
    main()

