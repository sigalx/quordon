#!/usr/bin/env python3
"""Check trusted views through the public API and isolated MySQL fixtures."""

import base64
import json
import subprocess
import urllib.error
import urllib.request


def request(path, body=None, status=200, accept=None):
    headers = {"Authorization": "Basic " + base64.b64encode(b"integration-client:password").decode()}
    if accept:
        headers["Accept"] = accept
    data = None
    if body is not None:
        headers["Content-Type"] = "application/json"
        data = json.dumps(body).encode()
    req = urllib.request.Request("http://127.0.0.1:18080" + path, data=data, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=10) as response:
            actual, result = response.status, json.load(response)
    except urllib.error.HTTPError as error:
        actual, result = error.code, json.load(error)
    assert actual == status, (path, body, actual, result)
    return result


def service_log_count(predicate):
    result = subprocess.run([
        "docker", "compose", "-f", "compose.integration.yaml", "exec", "-T", "mysql",
        "mysql", "--user=root", "--password=root-password", "--batch", "--skip-column-names",
        "--execute=SELECT COUNT(*) FROM mysql.general_log WHERE user_host LIKE 'quordon[%' AND " + predicate,
    ], check=True, capture_output=True, text=True)
    return int(result.stdout.strip())


def main_select_count():
    return service_log_count("argument LIKE 'SELECT /*+ MAX_EXECUTION_TIME%'")


def field(name, alias=None):
    result = {"kind": "field", "field": name}
    if alias:
        result["alias"] = alias
    return result


def query(source, fields):
    return {"source": {"schema": "application", "name": source},
            "projection": fields, "limit": 20}


privilege_failures = []


def unavailable(path, body):
    before = main_select_count()
    result = request(path, body, status=503)
    assert result["code"] == "DATABASE_UNAVAILABLE", result
    assert result["message"] == "The database is unavailable", result
    assert main_select_count() == before
    privilege_failures.append(result["request_id"])


def pages(source, keys, fields, shape, profile="admission-reader", status=200, directions=None):
    spec = query(source, fields)
    spec["limit"] = 1
    spec["order_by"] = [{"field": key, "direction": direction}
                        for key, direction in zip(keys, directions or ["asc"] * len(keys))]
    body = {"kind": "keyset", "profile": profile, "datasource": "integration-mysql", "shape": shape,
            "query": spec, "page": {"kind": "first"}}
    rows, cursors = [], set()
    for _ in range(10):
        if status == 503:
            unavailable("/queries/select", body)
            # A well-typed continuation must fail at the same privilege boundary.
            body["page"] = {"kind": "after", "cursor": [
                {"type": "string" if key == "unicode_label" else "integer", "value": "a" if key == "unicode_label" else "1"}
                for key in keys]}
            unavailable("/queries/select", body)
            return
        result = request("/queries/select", body, status=status)
        if status != 200:
            assert result["code"] == "UNSUPPORTED_QUERY", result
            return
        rows.extend(result["rows"])
        if not result["page"]["has_more"]:
            assert "next_cursor" not in result["page"]
            return rows
        cursor = result["page"]["next_cursor"]
        assert json.dumps(cursor) not in cursors, result
        cursors.add(json.dumps(cursor))
        body["page"] = {"kind": "after", "cursor": cursor}
    raise AssertionError("Keyset did not terminate")


objects = request("/schemas/application/objects?profile=views-reader&datasource=integration-mysql")["objects"]
assert {value["name"] for value in objects} == {
    "Orders", "join_orders", "materialized_orders", "character_aliases"}

for source in ("Orders", "join_orders", "materialized_orders", "character_aliases"):
    description = request(f"/schemas/application/objects/{source}?profile=views-reader&datasource=integration-mysql")
    assert all(not column["primary_key"] and not column["indexed"] for column in description["columns"])
    if source == "character_aliases":
        assert "hidden_value" not in {column["name"] for column in description["columns"]}
        assert "exposed_alias" in {column["name"] for column in description["columns"]}
    stats = request(f"/schemas/application/objects/{source}/statistics?profile=views-reader&datasource=integration-mysql", status=422)
    assert stats["code"] == "UNSUPPORTED_QUERY"

for source, key, expected in (("Orders", "id", [["1", "active"], ["2", "closed"]]),
                              ("join_orders", "order_id", [["1", "active"], ["2", "closed"]]),
                              ("materialized_orders", "id", [["1", "active"], ["2", "closed"]])):
    spec = query(source, [field(key, "source_id"), field("status")])
    spec["order_by"] = [{"field": key, "direction": "asc"}]
    before = main_select_count()
    result = request("/queries/select", {"profile": "views-reader", "datasource": "integration-mysql", "query": spec})
    assert result["rows"] == expected, result
    assert main_select_count() > before, "Main SELECT log assertion did not detect successful execution"
    unavailable("/queries/explain", {"profile": "views-reader", "datasource": "integration-mysql", "query": spec})
    for mode in ("scalar", "grouped"):
        projection = [{"kind": "measure", "function": "count_all", "alias": "row_count"}]
        if mode == "grouped":
            projection.insert(0, {"kind": "dimension", "field": "status"})
        aggregate = {"mode": mode, "source": {"schema": "application", "name": source}, "projection": projection}
        if mode == "grouped":
            aggregate["limit"] = 20
        unavailable("/queries/aggregate", {"profile": "views-reader", "datasource": "integration-mysql", "query": aggregate})

aliases = request("/queries/select", {"profile": "views-reader", "datasource": "integration-mysql", "query": query(
    "character_aliases", [field("unicode_label"), field("id"), field("exposed_alias")])})["rows"]
assert len(aliases) == 4 and all(row[-1] == "hidden" for row in aliases), aliases
unavailable("/queries/explain", {"profile": "views-reader", "datasource": "integration-mysql", "query": query(
    "character_aliases", [field("id"), field("exposed_alias")])})

for source, keys, fields in (
    ("Orders", ["id"], [field("id"), field("status")]),
    ("join_orders", ["order_id", "event_id"], [field("order_id"), field("event_id"), field("status")]),
    ("materialized_orders", ["id"], [field("id"), field("status")]),
    ("character_aliases", ["unicode_label", "id"], [field("unicode_label"), field("id"), field("exposed_alias")]),
):
    pages(source, keys, fields, source + "_pages", profile="views-reader", status=503)

for endpoint in ("select", "explain"):
    for feature in ("projection", "filter", "order_by"):
        spec = query("character_aliases", [field("id")])
        if feature == "projection":
            spec["projection"] = [field("hidden_value", "safe_alias")]
        elif feature == "filter":
            spec["filter"] = {"kind": "predicate", "field": "hidden_value", "operator": "eq",
                              "values": [{"type": "string", "value": "hidden"}]}
        else:
            spec["order_by"] = [{"field": "hidden_value", "direction": "asc"}]
        before = service_log_count("command_type = 'Execute'")
        denial = request("/queries/" + endpoint, {"profile": "views-reader", "datasource": "integration-mysql", "query": spec}, status=403)
        assert denial["code"] == "DENIED_FIELD", denial
        assert service_log_count("command_type = 'Execute'") == before

# Physical sources reach admission with the exact same SELECT-only credentials.
for alias, status in (("unconstrained", 200), ("index_match", 200), ("index_mismatch", 422),
                      ("estimate_rejected", 422), ("temporary_rejected", 422),
                      ("filesort_rejected", 422), ("work_allowed", 200)):
    grouped = alias in ("temporary_rejected", "filesort_rejected", "work_allowed")
    measure = {"kind": "measure", "function": "count_all", "alias": alias}
    if alias == "estimate_rejected":
        measure.update(function="sum", field="amount")
    projection = [measure]
    if grouped:
        projection.insert(0, {"kind": "dimension", "field": "amount"})
    spec = {"mode": "grouped" if grouped else "scalar", "source": {"schema": "application", "name": "orders"}, "projection": projection}
    if alias == "index_match":
        spec["filter"] = {"kind": "predicate", "field": "status", "operator": "eq",
                          "values": [{"type": "string", "value": "active"}]}
    if grouped:
        spec.update(limit=20, order_by=[{"kind": "measure", "alias": alias, "direction": "desc"}])
    before = main_select_count()
    result = request("/queries/aggregate", {"profile": "admission-reader", "datasource": "integration-mysql", "query": spec}, status=status)
    if status != 200:
        assert result["code"] == "UNSUPPORTED_QUERY", result
        assert main_select_count() == before
    else:
        expected = [["10.00", "1"], ["20.00", "1"]] if grouped else [["1" if alias == "index_match" else "2"]]
        assert sorted(result["rows"]) == expected, result
        assert main_select_count() > before

for name in ("unconstrained", "index_match", "index_mismatch", "estimate_rejected", "filesort_rejected", "work_allowed"):
    sorting = name in ("filesort_rejected", "work_allowed")
    keys = ["status", "id"] if sorting else ["id"]
    fields = [field("id"), field("status", name)]
    status = 200 if name in ("unconstrained", "index_match", "work_allowed") else 422
    before = main_select_count()
    rows = pages("orders", keys, fields, "plan_keyset_" + name, status=status,
                 directions=["asc", "desc"] if sorting else None)
    if status != 200:
        assert main_select_count() == before
    else:
        assert rows == [["1", "active"], ["2", "closed"]], rows
        assert main_select_count() > before

shapes = request("/query-shapes?profile=views-reader&datasource=integration-mysql", accept="application/json")
payload = json.dumps(shapes)
assert all(name not in payload for name in ("required_index", "allow_temporary_table", "allow_filesort", "maximum_rows_examined_per_scan"))
assert service_log_count("argument IN ('LOCK INSTANCE FOR BACKUP', 'UNLOCK INSTANCE')") == 0

logs = subprocess.run(["docker", "compose", "-f", "compose.integration.yaml", "logs", "--no-color", "--no-log-prefix", "quordon"],
                      check=True, capture_output=True, text=True).stdout
records = []
for line in logs.splitlines():
    try:
        records.append(json.loads(line))
    except json.JSONDecodeError:
        continue
for request_id in privilege_failures:
    completion = [record for record in records if record.get("type") == "query_completion" and record.get("request_id") == request_id]
    assert len(completion) == 1 and completion[0]["error_kind"] == "unavailable", completion
    assert completion[0]["outcome"] == "error" and completion[0]["duration_ms"] >= 0, completion
    assert completion[0]["resources"] and completion[0]["query_shape_hash"], completion
assert all("ddl_guard_mode" not in record for record in records)
print("Trusted-view SELECT, SELECT-only EXPLAIN limitation, admission and denylist checks passed.")
