#!/usr/bin/env python3
"""
Cortex Cloud Issues CSV exporter.

Features:
- Standard API Key authentication
- API-side filtering through CLI arguments
- FILTER_COUNT-aware pagination
- Retry handling
- Full or summary CSV output
- Issue name included as the first summary column
- Optional open-only safety filter
- Optional gzip output
- Debug output for URL, headers, payload, and response structure
"""

from __future__ import annotations

import argparse
import csv
import gzip
import json
import sys
import time
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, TextIO, Tuple

import requests


DEFAULT_SUMMARY_FIELDS = [
    "name",
    "id",
    "severity",
    "status.progress",
    "category",
    "domain",
    "detection.method",
    "asset_providers",
    "asset_accounts",
    "asset_names",
    "asset_types",
    "asset_regions",
    "observation_time",
    "last_update_timestamp",
    "description",
    "remediation",
]

RESOLVED_STATES = {
    "resolved",
    "closed",
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Export Cortex Cloud issues to CSV.")
    parser.add_argument(
        "--config",
        default="config.json",
        help="Path to the JSON configuration file. Default: config.json",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Print request, response, and pagination diagnostics without exposing secrets.",
    )
    parser.add_argument(
        "--debug-payload",
        action="store_true",
        help="Print the exact JSON payload sent to Cortex.",
    )
    parser.add_argument(
        "--filter",
        action="append",
        default=[],
        metavar="FIELD=VALUE",
        help=(
            "Repeatable API filter. Example: "
            '--filter "category=IDENTITY" --filter "severity=CRITICAL"'
        ),
    )
    return parser.parse_args()


def load_config(path: str) -> Dict[str, Any]:
    config_path = Path(path)
    if not config_path.exists():
        raise FileNotFoundError(f"Configuration file not found: {config_path}")

    with config_path.open("r", encoding="utf-8") as handle:
        config = json.load(handle)

    required = ["fqdn", "key_id", "api_key"]
    missing = [key for key in required if not config.get(key)]
    if missing:
        raise ValueError(f"Missing required configuration value(s): {', '.join(missing)}")

    config.setdefault("page_size", 100)
    config.setdefault("output", "issues.csv")
    config.setdefault("retry_count", 5)
    config.setdefault("timeout", 60)
    config.setdefault("gzip", False)
    config.setdefault("output_mode", "summary")
    config.setdefault("summary_fields", DEFAULT_SUMMARY_FIELDS)
    config.setdefault("open_only", True)

    output_mode = str(config["output_mode"]).lower()
    if output_mode not in {"summary", "full"}:
        raise ValueError("output_mode must be either 'summary' or 'full'.")
    config["output_mode"] = output_mode

    page_size = int(config["page_size"])
    if page_size < 1:
        raise ValueError("page_size must be greater than zero.")
    config["page_size"] = page_size

    return config


def normalize_fqdn(fqdn: str) -> str:
    fqdn = fqdn.strip().rstrip("/")
    if not fqdn.startswith(("https://", "http://")):
        fqdn = f"https://{fqdn}"
    return fqdn


def build_cli_filters(values: Sequence[str]) -> List[Dict[str, Any]]:
    """
    Convert repeated FIELD=VALUE arguments into Cortex API filters.

    Multiple values for the same field can be passed as comma-separated values:
        --filter "severity=CRITICAL,HIGH"
    """
    filters: List[Dict[str, Any]] = []

    for item in values:
        if "=" not in item:
            raise ValueError(
                f"Invalid --filter value {item!r}. Expected FIELD=VALUE."
            )

        field, raw_value = item.split("=", 1)
        field = field.strip()
        values_list = [
            value.strip()
            for value in raw_value.split(",")
            if value.strip()
        ]

        if not field or not values_list:
            raise ValueError(
                f"Invalid --filter value {item!r}. Expected FIELD=VALUE."
            )

        filters.append(
            {
                "field": field,
                "operator": "in",
                "value": values_list,
            }
        )

    return filters


def build_auth_headers(api_key: str, key_id: str) -> Dict[str, str]:
    """Build headers for a Cortex Standard API Key."""
    return {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "Authorization": api_key,
        "x-xdr-auth-id": str(key_id),
    }


def mask_header_value(name: str, value: str) -> str:
    """Hide secrets in debug output."""
    if name.lower() == "authorization":
        if len(value) <= 12:
            return "***"
        return f"{value[:6]}...{value[-4:]}"
    return value


def unwrap_api_response(response_json: Dict[str, Any]) -> Dict[str, Any]:
    """
    Cortex returns issue-search data inside a top-level 'reply' object:

        {
          "reply": {
            "DATA": [...],
            "FILTER_COUNT": 21,
            "TOTAL_COUNT": 1131062
          }
        }

    Return that inner object while also accepting an already-unwrapped response.
    """
    nested_reply = response_json.get("reply")

    if isinstance(nested_reply, dict):
        return nested_reply

    return response_json


def post_with_retry(
    session: requests.Session,
    url: str,
    api_key: str,
    key_id: str,
    payload: Dict[str, Any],
    timeout: int,
    retry_count: int,
    debug: bool,
    debug_payload: bool,
) -> Dict[str, Any]:
    body = json.dumps(payload, separators=(",", ":"), ensure_ascii=False)
    last_error: Optional[Exception] = None

    for attempt in range(1, retry_count + 1):
        headers = build_auth_headers(api_key=api_key, key_id=key_id)

        try:
            if debug:
                request_data = payload.get("request_data", {})

                print("=" * 80)
                print(f"Request attempt: {attempt}/{retry_count}")
                print(f"URL: {url}")
                print("Headers:")
                for name, value in headers.items():
                    print(f"  {name}: {mask_header_value(name, value)}")
                print(
                    "Pagination:"
                    f" search_from={request_data.get('search_from')}"
                    f" search_to={request_data.get('search_to')}"
                )
                print(f"Filters: {request_data.get('filters', [])}")

            if debug_payload:
                print("Request payload:")
                print(json.dumps(payload, indent=2, ensure_ascii=False))

            response = session.post(
                url,
                headers=headers,
                data=body.encode("utf-8"),
                timeout=timeout,
            )

            if debug:
                print(f"HTTP status: {response.status_code}")
                print(f"Response preview: {response.text[:1000]}")
                print("=" * 80)

            if response.status_code in {429, 500, 502, 503, 504}:
                raise requests.HTTPError(
                    f"Retryable API response {response.status_code}: "
                    f"{response.text[:1000]}",
                    response=response,
                )

            response.raise_for_status()
            response_json = response.json()

            if not isinstance(response_json, dict):
                raise ValueError("The API returned a non-object JSON response.")

            reply = unwrap_api_response(response_json)

            if not isinstance(reply, dict):
                raise ValueError("The API reply field is not a JSON object.")

            return reply

        except (requests.RequestException, ValueError) as exc:
            last_error = exc

            if attempt >= retry_count:
                break

            delay = min(2 ** (attempt - 1), 30)
            print(
                f"Request attempt {attempt}/{retry_count} failed: {exc}. "
                f"Retrying in {delay}s...",
                file=sys.stderr,
            )
            time.sleep(delay)

    raise RuntimeError(
        f"API request failed after {retry_count} attempts: {last_error}"
    )


def flatten_json(
    value: Any,
    parent_key: str = "",
    separator: str = ".",
) -> Dict[str, Any]:
    """
    Flatten nested dictionaries.

    Lists are retained as JSON strings so a CSV row remains one issue per row.
    Keys that already contain dots, such as 'status.progress', are preserved.
    """
    flattened: Dict[str, Any] = {}

    if isinstance(value, Mapping):
        for key, child in value.items():
            key_text = str(key)
            new_key = f"{parent_key}{separator}{key_text}" if parent_key else key_text

            if isinstance(child, Mapping):
                flattened.update(flatten_json(child, new_key, separator))
            elif isinstance(child, list):
                flattened[new_key] = json.dumps(
                    child,
                    ensure_ascii=False,
                    separators=(",", ":"),
                )
            else:
                flattened[new_key] = child
    else:
        flattened[parent_key or "value"] = value

    return flattened


def get_status(issue: Mapping[str, Any]) -> str:
    direct = issue.get("status.progress")
    if direct is not None:
        return str(direct).strip()

    status = issue.get("status")
    if isinstance(status, Mapping):
        progress = status.get("progress")
        if progress is not None:
            return str(progress).strip()

    return ""


def is_open_issue(issue: Mapping[str, Any]) -> bool:
    status = get_status(issue).casefold()
    return status not in RESOLVED_STATES


def select_summary_fields(
    flattened_issue: Mapping[str, Any],
    summary_fields: Sequence[str],
) -> Dict[str, Any]:
    return {field: flattened_issue.get(field, "") for field in summary_fields}


def collect_issues(
    config: Mapping[str, Any],
    filters: Sequence[Mapping[str, Any]],
    debug: bool,
    debug_payload: bool,
) -> Tuple[List[Dict[str, Any]], int, int]:
    fqdn = normalize_fqdn(str(config["fqdn"]))
    path = "/public_api/v1/issue/search"
    url = f"{fqdn}{path}"

    page_size = int(config["page_size"])
    retry_count = int(config["retry_count"])
    timeout = int(config["timeout"])
    open_only = bool(config.get("open_only", True))

    issues: List[Dict[str, Any]] = []
    search_from = 0
    filter_count: Optional[int] = None
    skipped_resolved = 0

    with requests.Session() as session:
        while filter_count is None or search_from < filter_count:
            search_to = search_from + page_size

            payload = {
                "request_data": {
                    "filters": list(filters),
                    "search_from": search_from,
                    "search_to": search_to,
                }
            }

            reply = post_with_retry(
                session=session,
                url=url,
                api_key=str(config["api_key"]),
                key_id=str(config["key_id"]),
                payload=payload,
                timeout=timeout,
                retry_count=retry_count,
                debug=debug,
                debug_payload=debug_payload,
            )

            page = reply.get("DATA", [])
            if page is None:
                page = []

            if not isinstance(page, list):
                raise ValueError("The API DATA field is not an array.")

            if filter_count is None:
                raw_count = reply.get("FILTER_COUNT")
                filter_count = len(page) if raw_count is None else int(raw_count)
                print(f"API matched issues: {filter_count}")

            for issue in page:
                if not isinstance(issue, dict):
                    continue

                if open_only and not is_open_issue(issue):
                    skipped_resolved += 1
                    continue

                issues.append(issue)

            processed = min(search_from + len(page), filter_count)
            print(
                f"Processed {processed} / {filter_count}"
                f" | retained {len(issues)} open issue(s)"
            )

            if not page:
                break

            search_from += len(page)

            if len(page) < page_size:
                break

    return issues, int(filter_count or 0), skipped_resolved


def all_fieldnames(rows: Iterable[Mapping[str, Any]]) -> List[str]:
    fieldnames: List[str] = []
    seen = set()

    preferred = ["name", "id", "severity", "status.progress", "category"]

    materialized = list(rows)

    for field in preferred:
        if any(field in row for row in materialized):
            fieldnames.append(field)
            seen.add(field)

    for row in materialized:
        for field in row.keys():
            if field not in seen:
                seen.add(field)
                fieldnames.append(field)

    return fieldnames


def open_output_file(path: Path, gzip_enabled: bool) -> TextIO:
    path.parent.mkdir(parents=True, exist_ok=True)

    if gzip_enabled:
        return gzip.open(path, "wt", encoding="utf-8", newline="")

    return path.open("w", encoding="utf-8-sig", newline="")


def write_csv(
    issues: Sequence[Mapping[str, Any]],
    config: Mapping[str, Any],
) -> Path:
    output_mode = str(config["output_mode"])
    summary_fields = list(config.get("summary_fields", DEFAULT_SUMMARY_FIELDS))
    gzip_enabled = bool(config.get("gzip", False))

    output = Path(str(config["output"]))

    if gzip_enabled and output.suffix != ".gz":
        output = output.with_name(output.name + ".gz")

    flattened_rows = [flatten_json(issue) for issue in issues]

    if output_mode == "summary":
        rows = [
            select_summary_fields(flattened, summary_fields)
            for flattened in flattened_rows
        ]
        fieldnames = summary_fields
    else:
        rows = flattened_rows
        fieldnames = all_fieldnames(rows)

    with open_output_file(output, gzip_enabled) as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=fieldnames,
            extrasaction="ignore",
        )
        writer.writeheader()
        writer.writerows(rows)

    return output


def print_filters(filters: Sequence[Mapping[str, Any]]) -> None:
    print("API filters:")

    if not filters:
        print("    (none)")
        return

    for item in filters:
        field = item.get("field")
        operator = item.get("operator")
        value = item.get("value")
        print(f"    {field} {operator} {value}")


def main() -> int:
    args = parse_args()

    try:
        config = load_config(args.config)
        filters = build_cli_filters(args.filter)

        print_filters(filters)
        print(f"Output mode: {config['output_mode']}")
        print(f"Open only: {bool(config.get('open_only', True))}")

        issues, api_count, skipped_resolved = collect_issues(
            config=config,
            filters=filters,
            debug=args.debug,
            debug_payload=args.debug_payload,
        )

        output_path = write_csv(issues, config)

        print()
        print(f"API matched: {api_count}")
        print(f"Resolved/closed skipped locally: {skipped_resolved}")
        print(f"Exported: {len(issues)}")
        print(f"CSV created: {output_path.resolve()}")

        return 0

    except KeyboardInterrupt:
        print("\nCancelled.", file=sys.stderr)
        return 130
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
