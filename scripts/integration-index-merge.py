#!/usr/bin/env python3
"""Verify whole index names and merge expressions against native preflights."""

import base64
import json
import os
from pathlib import Path
import subprocess
import tempfile
import urllib.error
import urllib.request


def mysql(sql, service=False):
    user = "quordon" if service else "root"
    password = "quordon-password" if service else "root-password"
    result = subprocess.run([
        "docker", "compose", "-f", "compose.integration.yaml", "exec", "-T", "mysql",
        "mysql", "--protocol=tcp", "--host=127.0.0.1", "--user=" + user,
        "--password=" + password, "--batch", "--raw", "--skip-column-names",
        "--execute=" + sql,
    ], check=True, capture_output=True, text=True, timeout=10)
    return result.stdout.strip()


def request(path, body, status=200):
    headers = {"Authorization": "Basic " + base64.b64encode(b"integration-client:password").decode(),
               "Content-Type": "application/json"}
    req = urllib.request.Request("http://127.0.0.1:18080" + path,
                                 data=json.dumps(body).encode(), headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=10) as response:
            actual, result = response.status, json.load(response)
    except urllib.error.HTTPError as error:
        actual, result = error.code, json.load(error)
    assert actual == status, (path, body, actual, result)
    return result


def main_select_count():
    return int(mysql("SELECT COUNT(*) FROM mysql.general_log WHERE user_host LIKE 'quordon[%' "
                     "AND argument LIKE 'SELECT /*+ MAX_EXECUTION_TIME%'"))


def tables(value):
    if isinstance(value, dict):
        if isinstance(value.get("table"), dict):
            yield value["table"]
        for child in value.values():
            yield from tables(child)
    elif isinstance(value, list):
        for child in value:
            yield from tables(child)


def read_preflight_plan():
    # Read only the latest service Execute, then re-explain that exact compiled
    # statement under the same SELECT-only account. Client SQL is never used.
    statement = mysql("SELECT argument FROM mysql.general_log WHERE user_host LIKE 'quordon[%' "
                      "AND command_type = 'Execute' "
                      "AND argument LIKE 'EXPLAIN FORMAT=JSON SELECT /*+ MAX_EXECUTION_TIME%' "
                      "ORDER BY event_time DESC LIMIT 1")
    assert statement, "Missing native preflight"
    return json.loads(mysql(statement, service=True))


def read_preflight():
    return list(tables(read_preflight_plan()))


def assert_merge_preflight(algorithm):
    nodes = read_preflight()
    assert len(nodes) == 1 and nodes[0]["access_type"] == "index_merge", nodes
    keys = {f"{algorithm}(idx_a,idx_b)", f"{algorithm}(idx_b,idx_a)"}
    assert nodes[0]["key"] in keys, nodes
    assert nodes[0]["rows_examined_per_scan"] <= 1000, nodes


def filter_spec(group="or", predicate="eq", values=(3, 7)):
    return {"kind": "group", "operator": group, "expressions": [
        {"kind": "predicate", "field": field, "operator": predicate,
         "values": [{"type": "integer", "value": value}]}
        for field, value in zip(("a", "b"), values)]}


grants = mysql("SHOW GRANTS", service=True)
assert "GRANT SELECT ON `application`.*" in grants, grants
assert "BACKUP_ADMIN" not in grants and "SHOW VIEW" not in grants, grants

for algorithm, group, predicate, values, count in (
    ("union", "or", "eq", (3, 7), "199"),
    ("intersect", "and", "eq", (3, 7), "1"),
    ("sort_union", "or", "lt", (2, 2), "396"),
):
    for variant in ("unconstrained", "first", "second", "mismatch"):
        spec = {"mode": "scalar", "source": {"schema": "application", "name": "merge_rows"},
                "projection": [{"kind": "measure", "function": "count_all", "alias": algorithm + "_" + variant}],
                "filter": filter_spec(group, predicate, values)}
        before = main_select_count()
        result = request("/queries/aggregate", {"profile": "index-merge-reader", "datasource": "integration-mysql", "query": spec},
                         status=422 if variant == "mismatch" else 200)
        assert_merge_preflight(algorithm)
        if variant == "mismatch":
            assert result["code"] == "UNSUPPORTED_QUERY", result
            assert main_select_count() == before
        else:
            assert result["rows"] == [[count]], result
            assert main_select_count() > before

expected = sorted([[str(n % 100), str(n // 100), str(n + 1)] for n in range(10000)
                   if n % 100 == 3 or n // 100 == 7], key=lambda row: tuple(map(int, row)))
for variant in ("unconstrained", "first", "second", "mismatch", "filesort_rejected"):
    spec = {"source": {"schema": "application", "name": "merge_rows"},
            "projection": [{"kind": "field", "field": "a"}, {"kind": "field", "field": "b"},
                           {"kind": "field", "field": "id", "alias": variant}],
            "filter": filter_spec(), "order_by": [{"field": field, "direction": "asc"} for field in ("a", "b", "id")],
            "limit": 100}
    body = {"kind": "keyset", "profile": "index-merge-reader", "datasource": "integration-mysql", "shape": "merge_pages_" + variant,
            "query": spec, "page": {"kind": "first"}}
    before = main_select_count()
    denied = variant in ("mismatch", "filesort_rejected")
    result = request("/queries/select", body, status=422 if denied else 200)
    assert_merge_preflight("union")
    if denied:
        assert result["code"] == "UNSUPPORTED_QUERY", result
        assert main_select_count() == before
    else:
        assert result["rows"] == expected[:100], result
        assert result["page"]["has_more"], result
        assert main_select_count() > before
        if variant == "unconstrained":
            body["page"] = {"kind": "after", "cursor": result["page"]["next_cursor"]}
            result = request("/queries/select", body)
            assert result["rows"] == expected[100:], result
            assert not result["page"]["has_more"] and "next_cursor" not in result["page"], result

indexes = set(mysql("SELECT DISTINCT INDEX_NAME FROM INFORMATION_SCHEMA.STATISTICS "
                    "WHERE TABLE_SCHEMA='application' AND TABLE_NAME='comma_rows'", service=True).splitlines())
assert indexes == {"PRIMARY", "idx_a,idx_b"}, indexes
for operation in ("aggregate", "keyset"):
    for variant in ("unconstrained", "prefix", "suffix"):
        alias = "comma_" + variant
        predicate = {"kind": "predicate", "field": "a", "operator": "eq",
                     "values": [{"type": "integer", "value": 3}]}
        spec = {"source": {"schema": "application", "name": "comma_rows"}, "filter": predicate}
        if operation == "aggregate":
            spec.update(mode="scalar", projection=[{"kind": "measure", "function": "count_all", "alias": alias}])
            body = {"profile": "index-merge-reader", "datasource": "integration-mysql", "query": spec}
            endpoint, expected_rows = "/queries/aggregate", [["10"]]
        else:
            spec.update(projection=[{"kind": "field", "field": "id", "alias": alias},
                                    {"kind": "field", "field": "a"}],
                        order_by=[{"field": "id", "direction": "asc"}], limit=20)
            body = {"kind": "keyset", "profile": "index-merge-reader", "datasource": "integration-mysql", "shape": "comma_pages_" + variant,
                    "query": spec, "page": {"kind": "first"}}
            endpoint = "/queries/select"
            expected_rows = [[str(n + 1), "3"] for n in range(3, 1000, 100)]
        before = main_select_count()
        denied = variant != "unconstrained"
        result = request(endpoint, body, status=422 if denied else 200)
        nodes = read_preflight()
        assert len(nodes) == 1 and nodes[0]["access_type"] in ("ref", "range", "index"), nodes
        assert nodes[0]["key"] == "idx_a,idx_b", nodes
        if denied:
            assert result["code"] == "UNSUPPORTED_QUERY", result
            assert main_select_count() == before
        else:
            assert result["rows"] == expected_rows, result
            assert main_select_count() > before
            if operation == "keyset":
                assert not result["page"]["has_more"] and "next_cursor" not in result["page"], result

indexes = set(mysql("SELECT DISTINCT INDEX_NAME FROM INFORMATION_SCHEMA.STATISTICS "
                    "WHERE TABLE_SCHEMA='application' AND TABLE_NAME='ambiguous_merge_rows'",
                    service=True).splitlines())
assert indexes == {"PRIMARY", "idx_a,idx_b", "idx_c"}, indexes
with tempfile.TemporaryDirectory(prefix="quordon-native-index-") as directory:
    for operation in ("aggregate", "keyset"):
        for variant in ("unconstrained", "prefix", "suffix", "actual"):
            alias = "ambiguous_" + variant
            spec = {"source": {"schema": "application", "name": "ambiguous_merge_rows"},
                    "filter": filter_spec()}
            if operation == "aggregate":
                spec.update(mode="scalar", projection=[{"kind": "measure", "function": "count_all", "alias": alias}])
                endpoint, body = "/queries/aggregate", {"profile": "index-merge-reader", "datasource": "integration-mysql", "query": spec}
            else:
                spec.update(projection=[{"kind": "field", "field": "a"}, {"kind": "field", "field": "b"},
                                        {"kind": "field", "field": "id", "alias": alias}],
                            order_by=[{"field": field, "direction": "asc"} for field in ("a", "b", "id")],
                            limit=100)
                endpoint = "/queries/select"
                body = {"kind": "keyset", "profile": "index-merge-reader", "datasource": "integration-mysql", "shape": "ambiguous_pages_" + variant,
                        "query": spec, "page": {"kind": "first"}}
            before = main_select_count()
            result = request(endpoint, body, status=422)
            assert result["code"] == "UNSUPPORTED_QUERY", result
            assert main_select_count() == before
            plan = read_preflight_plan()
            nodes = list(tables(plan))
            assert len(nodes) == 1 and nodes[0]["access_type"] == "index_merge", nodes
            assert nodes[0]["key"] in {"union(idx_a,idx_b,idx_c)", "union(idx_c,idx_a,idx_b)"}, nodes
            assert nodes[0]["key_length"] == "4,4", nodes
            assert nodes[0]["rows_examined_per_scan"] <= 1000, nodes
            if variant == "unconstrained":
                Path(directory, "ambiguous_" + operation + ".json").write_text(json.dumps(plan))

        predicate = {"kind": "predicate", "field": "b", "operator": "eq",
                     "values": [{"type": "integer", "value": 7}]}
        spec = {"source": {"schema": "application", "name": "physical_alias_view"}, "filter": predicate}
        if operation == "aggregate":
            spec.update(mode="scalar", projection=[{"kind": "measure", "function": "count_all", "alias": "alias_count"}])
            endpoint, body = "/queries/aggregate", {"profile": "index-merge-reader", "datasource": "integration-mysql", "query": spec}
        else:
            spec.update(projection=[{"kind": "field", "field": "id"}, {"kind": "field", "field": "b"}],
                        order_by=[{"field": "id", "direction": "asc"}], limit=20)
            endpoint = "/queries/select"
            body = {"kind": "keyset", "profile": "index-merge-reader", "datasource": "integration-mysql", "shape": "physical_alias_pages",
                    "query": spec, "page": {"kind": "first"}}
        before = main_select_count()
        result = request(endpoint, body, status=503)
        assert result["code"] == "DATABASE_UNAVAILABLE", result
        assert main_select_count() == before
        # Only the fixture observer has SHOW VIEW. The service's EXPLAIN fails
        # during Prepare, before Execute is logged. Observe the corresponding
        # synthetic query directly, then check its admission in the adapter.
        selection = "COUNT(*)" if operation == "aggregate" else "id, b"
        pagination = "" if operation == "aggregate" else " ORDER BY id LIMIT 21"
        plan = json.loads(mysql("EXPLAIN FORMAT=JSON SELECT " + selection +
                                " FROM application.physical_alias_view WHERE b = 7" + pagination))
        nodes = list(tables(plan))
        assert len(nodes) == 1 and nodes[0]["table_name"] == "<orders>", nodes
        assert nodes[0]["key"] == "idx_c" and nodes[0]["access_type"] == "ref", nodes
        assert "materialized_from_subquery" not in nodes[0], nodes
        assert "sharing_temporary_table_with" not in nodes[0], nodes
        Path(directory, "alias_" + operation + ".json").write_text(json.dumps(plan))

    environment = os.environ.copy()
    environment["QUORDON_NATIVE_PLAN_DIRECTORY"] = directory
    environment.setdefault("GOCACHE", "/tmp/quordon-go-build")
    subprocess.run(["go", "test", "./internal/adapters/mysql8", "-run", "^TestNativeIndexPlanAdmission$",
                    "-count=1", "-timeout=30s"], env=environment, check=True, timeout=60)

print("Native aggregate/keyset index identities and physical aliases with SELECT-only checks passed.")
