#!/usr/bin/env python3
"""Verify exact policy numeric buckets through the two-datasource API fixture."""
import copy
from decimal import Decimal
import subprocess
import sys

sys.dont_write_bytecode = True

from importlib.util import module_from_spec, spec_from_file_location

spec = spec_from_file_location("fixture_http", "scripts/integration-source-text.py")
fixture_http = module_from_spec(spec)
spec.loader.exec_module(fixture_http)
request = fixture_http.request


def fixture_mysql(statement, service):
    result = subprocess.run([
        "docker", "compose", "-f", "compose.integration.yaml", "exec", "-T", service,
        "mysql", "--user=root", "--password=root-password", "--batch", "--skip-column-names",
        "--execute=" + statement,
    ], check=True, capture_output=True, text=True, timeout=10)
    return result.stdout.strip()


def observed_statement_count(prefix, service):
    return int(fixture_mysql("SELECT COUNT(*) FROM mysql.general_log WHERE user_host LIKE 'quordon[%' "
                     "AND argument LIKE '" + prefix + "%'", service))


def make_request(profile, datasource, template, value=None):
    query = copy.deepcopy(template["query"])
    for output in query["projection"]:
        output.pop("boundaries", None)
    query["limit"] = query.pop("maximum_limit")
    if "filter" in query:
        types = query["filter"].pop("value_types")
        query["filter"]["values"] = [{"type": types[0], "value": value}]
    return {"profile": profile, "datasource": datasource, "query": query}


def main():
    profile = "numeric"
    for datasource, service in [("integration-mysql", "mysql"), ("integration-rc-mysql", "mysql-rc")]:
        print("Checking numeric buckets on", datasource, flush=True)
        discovery = request("/query-shapes?profile=" + profile + "&datasource=" + datasource)
        assert discovery["datasource"] == datasource
        templates = {shape["name"]: shape for shape in discovery["shapes"]}
        for field in ["signed_value", "unsigned_value", "decimal_value"]:
            # Derive the expectation independently from physical fixture values
            # with Decimal comparisons; no binary floating-point arithmetic.
            values = fixture_mysql("SELECT " + field + " FROM application.numeric_distribution", service)
            boundaries = [Decimal(x) for x in templates[field + "_asc"]["query"]["projection"][0]["boundaries"]]
            counts = {}
            for text in values.splitlines():
                bucket = None if text == "NULL" else sum(Decimal(text) >= bound for bound in boundaries)
                counts[bucket] = counts.get(bucket, 0) + 1
            expected = [[None if b is None else str(b), str(counts[b])]
                        for b in sorted(counts, key=lambda b: -1 if b is None else b)]
            for direction in ["asc", "desc"]:
                body = make_request(profile, datasource, templates[field + "_" + direction])
                response = request("/queries/aggregate", body)
                assert response["datasource"] == datasource
                assert response["rows"] == (expected if direction == "asc" else list(reversed(expected))), (field, direction, response)
                assert response["columns"][0] == {"name": field + "_bucket", "type": "integer", "encoding": "string", "nullable": True}
                body["query"]["limit"] = 2
                prefix = request("/queries/aggregate", body)
                assert prefix["rows"] == response["rows"][:2] and prefix["truncated"]
            empty = request("/queries/aggregate", make_request(profile, datasource, templates[field + "_empty"], 999))
            assert empty["rows"] == [] and empty["row_count"] == 0 and not empty["truncated"]
            unordered = request("/queries/aggregate", make_request(profile, datasource, templates[field + "_unordered"]))
            assert {tuple(row) for row in unordered["rows"]} == {tuple(row) for row in expected}
        response = request("/queries/aggregate", make_request(profile, datasource, templates["composition"], 1))
        assert len(response["columns"]) == 11 and response["row_count"] > 0
        assert all(row[3] == "2026-09-18T00:00:00Z" for row in response["rows"])
        for name in ["float_value_unsupported", "double_value_unsupported", "text_value_unsupported", "precision_unsupported", "scale_unsupported"]:
            explain_before = observed_statement_count("EXPLAIN FORMAT=JSON SELECT /*+ MAX_EXECUTION_TIME", service)
            select_before = observed_statement_count("SELECT /*+ MAX_EXECUTION_TIME", service)
            failure = request("/queries/aggregate", make_request(profile, datasource, templates[name]), status=422)
            assert failure["code"] == "UNSUPPORTED_QUERY"
            assert observed_statement_count("EXPLAIN FORMAT=JSON SELECT /*+ MAX_EXECUTION_TIME", service) == explain_before
            assert observed_statement_count("SELECT /*+ MAX_EXECUTION_TIME", service) == select_before
        for name in ["work_denied", "estimate_denied", "index_denied"]:
            select_before = observed_statement_count("SELECT /*+ MAX_EXECUTION_TIME", service)
            request("/queries/aggregate", make_request(profile, datasource, templates[name]), status=422)
            assert observed_statement_count("SELECT /*+ MAX_EXECUTION_TIME", service) == select_before
        body = make_request(profile, datasource, templates["signed_value_asc"])
        body["query"]["projection"][0]["field"] = "hidden_value"
        select_before = observed_statement_count("SELECT /*+ MAX_EXECUTION_TIME", service)
        request("/queries/aggregate", body, status=403)
        assert observed_statement_count("SELECT /*+ MAX_EXECUTION_TIME", service) == select_before
        body = make_request(profile, datasource, templates["signed_value_asc"])
        body["query"]["projection"][0]["boundaries"] = ["0"]
        request("/queries/aggregate", body, status=400)
    templates = {s["name"]: s for s in request("/query-shapes?profile=numeric&datasource=integration-mysql")["shapes"]}
    response = request("/queries/aggregate", make_request("numeric-byte", "integration-mysql", templates["byte_prefix"]))
    assert response["truncated"] and 0 < response["row_count"] < 11, response
    print("Numeric buckets: exact boundaries, NULL, composition, truncation, denials and datasource routing passed.")


if __name__ == "__main__":
    main()
