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


def load_config(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as file:
        cfg = json.load(file)

    required = ("fqdn", "key_id", "api_key")
    missing = [key for key in required if not cfg.get(key)]
    if missing:
        raise ValueError("Missing required configuration field(s): " + ", ".join(missing))
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
    for prefix in ("https://", "http://"):
        if fqdn.startswith(prefix):
            fqdn = fqdn[len(prefix):]
    return f"https://{fqdn.rstrip('/')}{API_PATH}"


def flatten_json(value: Any, parent_key: str = "", separator: str = ".") -> Dict[str, Any]:
    flattened: Dict[str, Any] = {}
    if isinstance(value, dict):
        for key, child_value in value.items():
            new_key = f"{parent_key}{separator}{key}" if parent_key else str(key)
            flattened.update(flatten_json(child_value, new_key, separator))
    elif isinstance(value, list):
        flattened[parent_key] = json.dumps(value, ensure_ascii=False, separators=(",", ":"))
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
        return any(item in values for item in actual) if isinstance(actual, list) else actual in values
    if operator == "not_in":
        values = expected if isinstance(expected, list) else [expected]
        return all(item not in values for item in actual) if isinstance(actual, list) else actual not in values
    if operator == "contains":
        if actual is None:
            return False
        return expected in actual if isinstance(actual, list) else str(expected).lower() in str(actual).lower()
    raise ValueError(f"Unsupported local filter operator '{operator}' for field '{field}'.")


def apply_local_filters(issues: Iterable[Dict[str, Any]], filters: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    if not filters:
        return list(issues)
    return [issue for issue in issues if all(matches_local_filter(issue, rule) for rule in filters)]


def request_page(session: requests.Session, url: str, headers: Dict[str, str], api_filters: List[Dict[str, Any]], search_from: int, search_to: int, max_retries: int, timeout: int, debug: bool) -> Dict[str, Any]:
    body = {"request_data": {"filters": api_filters, "search_from": search_from, "search_to": search_to}}
    if debug:
        print("\nRequest body:")
        print(json.dumps(body, indent=2))

    for attempt in range(1, max_retries + 1):
        try:
            response = session.post(url, headers=headers, json=body, timeout=timeout)
            if response.status_code == 200:
                return response.json()
            if response.status_code == 429 or response.status_code >= 500:
                wait_seconds = min(2 ** attempt, 30)
                print(f"\nTemporary HTTP {response.status_code}. Retrying in {wait_seconds}s ({attempt}/{max_retries})...")
                time.sleep(wait_seconds)
                continue
            print(f"\nHTTP Status: {response.status_code}")
            try:
                print(json.dumps(response.json(), indent=2))
            except ValueError:
                print(response.text)
            raise RuntimeError(f"Non-retryable API error: HTTP {response.status_code}")
        except requests.exceptions.RequestException as error:
            if attempt == max_retries:
                raise
            wait_seconds = min(2 ** attempt, 30)
            print(f"\nRequest error: {error}\nRetrying in {wait_seconds}s ({attempt}/{max_retries})...")
            time.sleep(wait_seconds)
    raise RuntimeError("Maximum retries reached.")


def open_output(path: str, compress: bool):
    if compress:
        return gzip.open(path, "wt", encoding="utf-8-sig", newline="")
    return open(path, "w", encoding="utf-8-sig", newline="")


def print_filter_summary(title: str, filters: List[Dict[str, Any]]) -> None:
    print(title)
    if not filters:
        print("  None")
        return
    for rule in filters:
        print(f"  {rule.get('field', '?')} {rule.get('operator', 'in')} {rule.get('value')}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Export Cortex Cloud issues to CSV")
    parser.add_argument("--config", required=True, help="Path to config.json")
    parser.add_argument("--debug", action="store_true", help="Print request bodies and diagnostics")
    args = parser.parse_args()

    try:
        cfg = load_config(args.config)
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(f"Configuration error: {error}")
        sys.exit(1)

    url = build_url(cfg)
    headers = build_headers(cfg)
    page_size = min(max(int(cfg.get("page_size", MAX_PAGE_SIZE)), 1), MAX_PAGE_SIZE)
    output_file = str(cfg.get("output", "issues.csv"))
    api_filters = cfg.get("api_filters", [])
    local_filters = cfg.get("local_filters", [])
    max_retries = int(cfg.get("retry_count", 5))
    timeout = int(cfg.get("timeout", 60))
    compress = bool(cfg.get("gzip", False))
    if compress and not output_file.endswith(".gz"):
        output_file += ".gz"

    search_from = downloaded = exported = page_number = 0
    writer: Optional[csv.DictWriter] = None
    csv_file = None
    started_at = time.time()

    print("=" * 72)
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
            data = request_page(session, url, headers, api_filters, search_from, search_to, max_retries, timeout, args.debug)
            issues = data.get("reply", {}).get("DATA", [])
            if not isinstance(issues, list):
                raise RuntimeError("Unexpected API response: reply.DATA is not a list.")
            if not issues:
                break

            downloaded += len(issues)
            selected = apply_local_filters(issues, local_filters)
            flattened = [flatten_json(issue) for issue in selected]

            if flattened and writer is None:
                fieldnames = sorted({key for issue in flattened for key in issue.keys()})
                csv_file = open_output(output_file, compress)
                writer = csv.DictWriter(csv_file, fieldnames=fieldnames, extrasaction="ignore")
                writer.writeheader()

            if writer is not None:
                for issue in flattened:
                    writer.writerow(issue)
                    exported += 1
                csv_file.flush()

            elapsed = time.time() - started_at
            rate = downloaded / elapsed if elapsed > 0 else 0
            print(f"\rPage {page_number:>6} | Downloaded {downloaded:>9} | Exported {exported:>9} | {rate:>7.1f} issues/sec", end="", flush=True)

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
    file_size_mb = os.path.getsize(output_file) / 1024 / 1024 if os.path.exists(output_file) else 0
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


