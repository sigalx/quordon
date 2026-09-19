#!/usr/bin/env python3
"""Exercise historic and malformed temporal values in isolated MySQL fixtures."""

import base64
import copy
from contextlib import contextmanager
import json
import subprocess
import time
import urllib.error
import urllib.request


def request(path, body=None, status=200):
    headers = {"Authorization": "Basic " + base64.b64encode(b"integration-client:password").decode()}
    if body is not None:
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request("http://127.0.0.1:18080" + path,
                                 data=None if body is None else json.dumps(body).encode(), headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=10) as response:
            actual, result = response.status, json.load(response)
    except urllib.error.HTTPError as error:
        actual, result = error.code, json.load(error)
    assert actual == status, (path, actual, result)
    return result


def main_select_count():
    result = subprocess.run([
        "docker", "compose", "-f", "compose.integration.yaml", "exec", "-T", "mysql",
        "mysql", "--user=root", "--password=root-password", "--batch", "--skip-column-names",
        "--execute=SELECT COUNT(*) FROM mysql.general_log WHERE user_host LIKE 'quordon[%' "
        "AND argument LIKE 'SELECT /*+ MAX_EXECUTION_TIME%'",
    ], check=True, capture_output=True, text=True)
    return int(result.stdout.strip())


def field(name, text=True):
    result = {"kind": "field", "field": name}
    if text:
        result["representation"] = "source_text"
    return result


def mysql(statement):
    result = subprocess.run([
        "docker", "compose", "-f", "compose.integration.yaml", "exec", "-T", "mysql",
        "mysql", "--user=root", "--password=root-password", "--batch", "--skip-column-names",
        "--execute=" + statement,
    ], check=True, capture_output=True, text=True, timeout=10)
    return result.stdout.strip()


def close_fixture_connections():
    identifiers = mysql("SELECT ID FROM information_schema.processlist WHERE USER = 'quordon'")
    for identifier in identifiers.splitlines():
        mysql("KILL CONNECTION " + str(int(identifier)))


@contextmanager
def non_utc_fixture():
    # Only this isolated administrator changes the fixture default. Fresh
    # SELECT-only service sessions must pin UTC and restore their +03:00 state.
    original = mysql("SELECT @@GLOBAL.time_zone")
    mysql("SET GLOBAL time_zone = '+03:00'")
    try:
        close_fixture_connections()
        yield
        assert int(mysql("SELECT COUNT(*) FROM mysql.general_log WHERE user_host LIKE 'quordon[%' "
                         "AND argument LIKE 'SET SESSION time_zone = %03:00%'")) > 0
        assert int(mysql("SELECT COUNT(*) FROM mysql.general_log WHERE user_host LIKE 'quordon[%' "
                         "AND argument LIKE 'SET%sql_mode%'")) == 0
    finally:
        mysql("SET GLOBAL time_zone = '" + original.replace("'", "''") + "'")
        close_fixture_connections()


def main():
    source = {"schema": "application", "name": "diagnostic_dates"}
    projection = [field("id", False)] + [field(name) for name in
                                        ("event_date", "wall_time", "occurred_at", "optional_date")]
    query = {"source": source, "projection": projection,
             "order_by": [{"field": "id", "direction": "asc"}], "limit": 20}
    body = {"profile": "diagnostic-reader", "datasource": "integration-mysql", "query": query}
    rows = request("/queries/select", body)
    assert rows["row_count"] == 8
    assert all(column["type"] == column["encoding"] == "string" for column in rows["columns"][1:])
    assert rows["rows"][0][1:] == ["0000-00-00", "0000-00-00 00:00:00.000000",
                                   "0000-00-00 00:00:00.000000", None]
    assert rows["rows"][1][1] == "0001-01-01"
    assert rows["rows"][1][3] == "2026-01-01 00:00:00.000001"
    assert rows["rows"][2][1] == "0999-12-31"
    assert rows["rows"][5][1] == "2026-02-31"
    assert rows["rows"][3][4] == "2026-02-31"
    assert request("/queries/explain", body)["format"] == "mysql_json"
    # Restoring the session must not leave its cleanup socket deadline pinned.
    time.sleep(1.25)
    assert request("/health/ready")["status"] == "ok"
    assert request("/queries/select", body)["rows"] == rows["rows"]

    discovery = request("/query-shapes?profile=diagnostic-reader&datasource=integration-mysql")
    shapes = {shape["name"]: shape for shape in discovery["shapes"]}
    assert "required_index" not in json.dumps(discovery)
    assert "source_text" in json.dumps(discovery)


    def shape_query(name, values=None):
        result = copy.deepcopy(shapes[name]["query"])
        maximum_limit = result.pop("maximum_limit", None)
        if maximum_limit is not None:
            result["limit"] = 1 if shapes[name]["operation"] == "select_keyset" else maximum_limit
        if "filter" in result:
            types = result["filter"].pop("value_types")
            assert len(types) == len(values or [])
            result["filter"]["values"] = [{"type": kind, "value": value}
                                          for kind, value in zip(types, values or [])]
        return result


    for column in ("event_date", "wall_time", "occurred_at"):
        for direction in ("asc", "desc"):
            name = "diagnostic_" + column + "_" + direction
            spec = shape_query(name)
            page = {"kind": "first"}
            observed, cursors = [], set()
            for _ in range(12):
                result = request("/queries/select", {"kind": "keyset", "profile": "diagnostic-reader", "datasource": "integration-mysql",
                                 "shape": name, "query": spec, "page": page})
                assert result["columns"][0]["type"] == "string"
                observed.extend(result["rows"])
                if not result["page"]["has_more"]:
                    break
                cursor = result["page"]["next_cursor"]
                assert cursor[0] == {"type": "string", "value": result["rows"][-1][0]}
                signature = json.dumps(cursor, sort_keys=True)
                assert signature not in cursors
                cursors.add(signature)
                page = {"kind": "after", "cursor": cursor}
            assert len(observed) == 8
            assert len({row[1] for row in observed}) == 8
            assert observed == sorted(observed, key=lambda row: (row[0].encode(), int(row[1])),
                                      reverse=direction == "desc")

    # Invalid values retain diagnostic text, while ordinary calendar keyset remains strict.
    for identity in (1, 5, 6):
        failure = request("/queries/select", {"kind": "keyset", "profile": "diagnostic-reader", "datasource": "integration-mysql",
                          "shape": "diagnostic_calendar_by_id", "query": shape_query("diagnostic_calendar_by_id", [identity]),
                          "page": {"kind": "first"}}, status=502)
        assert failure["code"] == "UPSTREAM_ERROR"
    for identity in (2, 3, 4, 8):
        result = request("/queries/select", {"kind": "keyset", "profile": "diagnostic-reader", "datasource": "integration-mysql",
                         "shape": "diagnostic_calendar_by_id", "query": shape_query("diagnostic_calendar_by_id", [identity]),
                         "page": {"kind": "first"}})
        assert result["row_count"] == 1

    for name, value, cursor_type in (("diagnostic_calendar_by_date", "0001-01-01", "date"),
                                    ("diagnostic_calendar_by_datetime", "0001-01-01T00:00:00Z", "datetime")):
        spec = shape_query(name, [value])
        page = {"kind": "first"}
        for expected_id in (2, 3, 4):
            result = request("/queries/select", {"kind": "keyset", "profile": "diagnostic-reader", "datasource": "integration-mysql",
                             "shape": name, "query": spec, "page": page})
            assert result["rows"][0][1] == str(expected_id)
            assert result["page"]["next_cursor"][0]["type"] == cursor_type
            page = {"kind": "after", "cursor": result["page"]["next_cursor"]}

    for operator, values, total in (("eq", ["2026-02-31"], 2), ("gte", ["2026-02-31"], 3),
                                    ("in", ["0000-00-00", "2026-02-31"], 3),
                                    ("like", ["2026-%"], 3), ("is_null", [], 1)):
        name = "diagnostic_date_" + operator
        spec = shape_query(name, values)
        assert request("/queries/aggregate", {"profile": "diagnostic-reader", "datasource": "integration-mysql", "query": spec})["rows"] == [[str(total)]]
        select = {"source": source, "projection": [field("id", False)], "filter": spec["filter"], "limit": 20}
        assert request("/queries/select", {"profile": "diagnostic-reader", "datasource": "integration-mysql", "query": select})["row_count"] == total

    assert request("/queries/aggregate", {"profile": "diagnostic-reader", "datasource": "integration-mysql",
                   "query": shape_query("diagnostic_timestamp_eq", ["2026-01-01 00:00:00.000001"])})["rows"] == [["1"]]
    timestamp_groups = request("/queries/aggregate", {"profile": "diagnostic-reader", "datasource": "integration-mysql",
                              "query": shape_query("diagnostic_timestamp_counts")})
    assert ["2026-01-01 00:00:00.000001", "1"] in timestamp_groups["rows"]
    assert ["0000-00-00 00:00:00.000000", "1"] in timestamp_groups["rows"]
    result = request("/queries/aggregate", {"profile": "diagnostic-reader", "datasource": "integration-mysql",
                     "query": shape_query("diagnostic_date_counts")})
    assert result["columns"][0]["type"] == result["columns"][0]["encoding"] == "string"
    assert ["2026-02-31", "2"] in result["rows"]
    assert len(result["rows"]) == 7
    for name in ("diagnostic_date_counts_work_denied", "diagnostic_date_counts_estimate_denied"):
        before = main_select_count()
        failure = request("/queries/aggregate", {"profile": "diagnostic-reader", "datasource": "integration-mysql", "query": shape_query(name)}, status=422)
        assert failure["code"] == "UNSUPPORTED_QUERY"
        assert main_select_count() == before

    description = request("/schemas/application/objects/diagnostic_dates?profile=diagnostic-reader&datasource=integration-mysql")
    assert all(column["name"] != "hidden_date" for column in description["columns"])
    for placement in ("projection", "filter", "order_by"):
        spec = {"source": source, "projection": [field("id", False)], "limit": 2}
        if placement == "projection":
            spec["projection"] = [field("hidden_date")]
        elif placement == "filter":
            spec["filter"] = {"kind": "predicate", "field": "hidden_date", "representation": "source_text",
                              "operator": "eq", "values": [{"type": "string", "value": "2026-01-01"}]}
        else:
            spec["order_by"] = [{"field": "hidden_date", "direction": "asc", "representation": "source_text"}]
        before = main_select_count()
        failure = request("/queries/select", {"profile": "diagnostic-reader", "datasource": "integration-mysql", "query": spec}, status=403)
        assert failure["code"] == "DENIED_FIELD"
        assert main_select_count() == before

    before = main_select_count()
    failure = request("/queries/select", {"profile": "diagnostic-reader", "datasource": "integration-mysql",
                      "query": {"source": source, "projection": [field("id")], "limit": 2}}, status=422)
    assert failure["code"] == "UNSUPPORTED_QUERY"
    assert main_select_count() == before

    # The diagnostic cleanup must preserve the original query timeout. A
    # connection with an interrupted transaction/session is discarded safely.
    slow = {"profile": "diagnostic-reader", "datasource": "integration-mysql", "query": {
        "source": {"schema": "application", "name": "diagnostic_slow_dates"},
        "projection": [field("event_date")], "limit": 1,
    }}
    failure = request("/queries/select", slow, status=504)
    assert failure["code"] == "QUERY_TIMEOUT"
    assert request("/health/ready")["status"] == "ok"
    assert request("/queries/select", body)["row_count"] == 8


if __name__ == "__main__":
    with non_utc_fixture():
        main()
    print("Historic dates and diagnostic temporal API integration passed.")
