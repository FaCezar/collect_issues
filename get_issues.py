import argparse
import csv
import gzip
import json
import os
import sys
import time
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional

import requests

API_PATH = "/public_api/v1/issue/search"
MAX_PAGE_SIZE = 100

CATEGORY_OPTIONS = [
    "ATTACK PATH",
    "CODE",
    "CONFIGURATION",
    "DATA",
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
        cfg = json.load(file)

    required = ("fqdn", "key_id", "api_key")
    missing = [key for key in required if not cfg.get(key)]

    if missing:
        raise ValueError(
            "Missing required configuration field(s): "
            + ", ".join(missing)
        )

    return cfg


def build_headers(cfg: Dict[str, Any]) -> Dict[str, str]:
    return {
        "Authorization": str(cfg["api_key"]),
        "x-xdr-auth-id": str(cfg["key_id"]),
        "Content-Type": "application/json",
        "Accept": "application/json",
    }


def build_url(cfg: Dict[str, Any]) -> str:
    fqdn = str(cfg["fqdn"]).strip()

    if fqdn.startswith("https://"):
        fqdn = fqdn[len("https://"):]

    if fqdn.startswith("http://"):
        fqdn = fqdn[len("http://"):]

    return f"https://{fqdn.rstrip('/')}{API_PATH}"


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


def get_nested_value(data: Dict[str, Any], field: str) -> Any:
    if field in data:
        return data[field]

    current: Any = data

    for part in field.split("."):
        if not isinstance(current, dict) or part not in current:
            return None
        current = current[part]

    return current


def matches_local_filter(issue: Dict[str, Any], rule: Dict[str, Any]) -> bool:
    field = str(rule.get("field", ""))
    operator = str(rule.get("operator", "in")).lower()
    expected = rule.get("value")
    actual = get_nested_value(issue, field)

    if operator == "eq":
        return actual == expected

    if operator == "neq":
        return actual != expected

    if operator == "in":
        values = expected if isinstance(expected, list) else [expected]

        if isinstance(actual, list):
            return any(item in values for item in actual)

        return actual in values

    if operator == "not_in":
        values = expected if isinstance(expected, list) else [expected]

        if isinstance(actual, list):
            return all(item not in values for item in actual)

        return actual not in values

    if operator == "contains":
        if actual is None:
            return False

        if isinstance(actual, list):
            return expected in actual

        return str(expected).lower() in str(actual).lower()

    raise ValueError(
        f"Unsupported local filter operator '{operator}' "
        f"for field '{field}'."
    )


def apply_local_filters(
    issues: Iterable[Dict[str, Any]],
    filters: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    if not filters:
        return list(issues)

    return [
        issue
        for issue in issues
        if all(matches_local_filter(issue, rule) for rule in filters)
    ]


def choose_multiple(
    title: str,
    options: List[str],
    default_all: bool = True,
) -> List[str]:
    while True:
        print(f"\n{title}\n")

        for index, value in enumerate(options, start=1):
            print(f"  {index}. {value}")

        all_index = len(options) + 1
        print(f"  {all_index}. ALL")

        default = str(all_index) if default_all else ""
        prompt = (
            f"\nEnter selections separated by commas [{default}]: "
            if default
            else "\nEnter selections separated by commas: "
        )

        raw = input(prompt).strip()

        if not raw and default:
            raw = default

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


def build_interactive_filters() -> List[Dict[str, Any]]:
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


def default_output_name(filters: List[Dict[str, Any]]) -> str:
    category_values: List[str] = []
    severity_values: List[str] = []

    for rule in filters:
        if rule.get("field") == "category":
            category_values = rule.get("value", [])
        elif rule.get("field") == "severity":
            severity_values = rule.get("value", [])

    category_part = (
        "-".join(value.lower().replace(" ", "_") for value in category_values)
        if category_values
        else "all_categories"
    )

    severity_part = (
        "-".join(value.lower() for value in severity_values)
        if severity_values
        else "all_severities"
    )

    return f"issues_{category_part}_{severity_part}.csv"


def confirm_export(
    filters: List[Dict[str, Any]],
    output_file: str,
) -> bool:
    print("\n" + "-" * 72)
    print("Export summary")
    print("-" * 72)

    categories = next(
        (
            rule["value"]
            for rule in filters
            if rule.get("field") == "category"
        ),
        [],
    )

    severities = next(
        (
            rule["value"]
            for rule in filters
            if rule.get("field") == "severity"
        ),
        [],
    )

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
                return response.json()

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


def open_output(path: str, compress: bool):
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
    title: str,
    filters: List[Dict[str, Any]],
) -> None:
    print(title)

    if not filters:
        print("  None")
        return

    for rule in filters:
        field = rule.get("field", "?")
        operator = rule.get("operator", "in")
        value = rule.get("value")
        print(f"  {field} {operator} {value}")


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
        help="Use filters and output from config.json without showing a menu",
    )

    parser.add_argument(
        "--debug",
        action="store_true",
        help="Print request bodies and additional diagnostics",
    )

    args = parser.parse_args()

    if args.interactive and args.non_interactive:
        print(
            "Use either --interactive or --non-interactive, not both."
        )
        sys.exit(2)

    try:
        cfg = load_config(args.config)
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(f"Configuration error: {error}")
        sys.exit(1)

    url = build_url(cfg)
    headers = build_headers(cfg)

    page_size = min(
        max(int(cfg.get("page_size", MAX_PAGE_SIZE)), 1),
        MAX_PAGE_SIZE,
    )

    api_filters = cfg.get("api_filters", [])
    max_retries = int(cfg.get("retry_count", 5))
    timeout = int(cfg.get("timeout", 60))
    compress = bool(cfg.get("gzip", False))

    should_use_menu = (
        args.interactive
        or (
            not args.non_interactive
            and sys.stdin.isatty()
        )
    )

    if should_use_menu:
        local_filters = build_interactive_filters()
        suggested_output = default_output_name(local_filters)
        output_answer = input(
            f"\nOutput filename [{suggested_output}]: "
        ).strip()
        output_file = output_answer or suggested_output

        if not confirm_export(local_filters, output_file):
            print("Export cancelled.")
            return
    else:
        local_filters = cfg.get("local_filters", [])
        output_file = str(cfg.get("output", "issues.csv"))

    if compress and not output_file.endswith(".gz"):
        output_file += ".gz"

    search_from = 0
    downloaded = 0
    exported = 0
    page_number = 0
    writer: Optional[csv.DictWriter] = None
    csv_file = None
    started_at = time.time()

    print("\n" + "=" * 72)
    print(" Cortex Cloud Issues Exporter")
    print("=" * 72)
    print(f"Endpoint       : {url}")
    print(f"Page size      : {page_size}")
    print(f"Output         : {output_file}")
    print(f"Started        : {datetime.now(timezone.utc).isoformat()}")
    print_filter_summary("API filters:", api_filters)
    print_filter_summary("Local filters:", local_filters)
    print("=" * 72)

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
                api_filters=api_filters,
                search_from=search_from,
                search_to=search_to,
                max_retries=max_retries,
                timeout=timeout,
                debug=args.debug,
            )

            reply = data.get("reply", {})
            issues = reply.get("DATA", [])

            if not isinstance(issues, list):
                raise RuntimeError(
                    "Unexpected API response: reply.DATA is not a list."
                )

            if not issues:
                break

            downloaded += len(issues)

            selected_issues = apply_local_filters(
                issues,
                local_filters,
            )

            flattened_issues = [
                flatten_json(issue)
                for issue in selected_issues
            ]

            if flattened_issues and writer is None:
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

            if writer is not None:
                for issue in flattened_issues:
                    writer.writerow(issue)
                    exported += 1

                csv_file.flush()

            elapsed = time.time() - started_at
            rate = downloaded / elapsed if elapsed > 0 else 0

            print(
                f"\rPage {page_number:>6} | "
                f"Downloaded {downloaded:>9} | "
                f"Exported {exported:>9} | "
                f"{rate:>7.1f} issues/sec",
                end="",
                flush=True,
            )

            search_from += len(issues)

            if len(issues) < page_size:
                break

    except KeyboardInterrupt:
        print("\n\nExport interrupted by the user.")
        print(f"Downloaded before interruption: {downloaded}")
        print(f"Exported before interruption  : {exported}")
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
    print(f"Downloaded     : {downloaded} issues")
    print(f"Exported       : {exported} issues")
    print(f"Pages          : {page_number}")
    print(f"Output         : {output_file}")
    print(f"File size      : {file_size_mb:.2f} MB")
    print(f"Elapsed        : {elapsed:.1f} seconds")
    print("=" * 72)


if __name__ == "__main__":
    main()
