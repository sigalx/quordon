#!/usr/bin/env python3
"""Verify routing and preserved denials for shared policy refs on two MySQLs."""

import base64
import json
import subprocess
import urllib.error
import urllib.request


def request(path, body=None, status=200):
    headers = {"Authorization": "Basic " + base64.b64encode(b"integration-client:password").decode()}
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
    assert actual == status, (path, actual, result.get("code"))
    return result


def main_select_count(service):
    result = subprocess.run([
        "docker", "compose", "-f", "compose.integration.yaml", "exec", "-T", service,
        "mysql", "--user=root", "--password=root-password", "--batch", "--skip-column-names",
        "--execute=SELECT COUNT(*) FROM mysql.general_log WHERE user_host LIKE 'quordon[%' "
        "AND argument LIKE 'SELECT /*+ MAX_EXECUTION_TIME%'",
    ], check=True, capture_output=True, text=True)
    return int(result.stdout.strip())


for service in ("mysql", "mysql-rc"):
    grants = subprocess.run([
        "docker", "compose", "-f", "compose.integration.yaml", "exec", "-T", service,
        "mysql", "--user=quordon", "--password=quordon-password", "--batch",
        "--skip-column-names", "--execute=SHOW GRANTS",
    ], check=True, capture_output=True, text=True).stdout
    assert "BACKUP_ADMIN" not in grants and "SHOW VIEW" not in grants

capabilities = request("/capabilities")
assert "routing-test" in json.dumps(capabilities) and "routing-rc" in json.dumps(capabilities)
request("/health/ready")

for contour, service in (("test", "mysql"), ("rc", "mysql-rc")):
    profile = "routing-" + contour
    discovery = request("/query-shapes?profile=" + profile)
    assert "marker_page" in json.dumps(discovery)
    assert "required_index" not in json.dumps(discovery)
    spec = {"source": {"schema": "application", "name": "routing_marker"},
            "projection": [{"kind": "field", "field": "id"}, {"kind": "field", "field": "contour"}],
            "order_by": [{"field": "id", "direction": "asc"}], "limit": 2}
    result = request("/queries/select", {"profile": profile, "query": spec})
    assert result["rows"] == [["1", contour]]
    request("/queries/explain", {"profile": profile, "query": spec})
    result = request("/queries/select", {"kind": "keyset", "profile": profile, "shape": "marker_page",
                                        "query": spec, "page": {"kind": "first"}})
    assert result["rows"] == [["1", contour]]
    aggregate = {"mode": "scalar", "source": spec["source"],
                 "projection": [{"kind": "measure", "function": "count_all", "alias": "marker_count"}]}
    result = request("/queries/aggregate", {"profile": profile, "query": aggregate})
    assert result["rows"] == [["1"]]
    before = main_select_count(service)
    denied = dict(spec, projection=[{"kind": "field", "field": "hidden_value"}])
    result = request("/queries/select", {"profile": profile, "query": denied}, status=403)
    assert result["code"] == "DENIED_FIELD"
    denied = dict(spec, source={"schema": "application", "name": "orders"})
    result = request("/queries/select", {"profile": profile, "query": denied}, status=403)
    assert result["code"] == "DENIED_RESOURCE"
    assert main_select_count(service) == before

    # The same policy-curated plan rejections must survive routing overrides.
    admission = "admission-reader" if contour == "test" else "admission-rc"
    query = {"mode": "scalar", "source": {"schema": "application", "name": "orders"},
             "projection": [{"kind": "measure", "function": "count_all", "alias": "index_mismatch"}]}
    result = request("/queries/aggregate", {"profile": admission, "query": query}, status=422)
    assert result["code"] == "UNSUPPORTED_QUERY"
    keyset = {"source": query["source"], "projection": [{"kind": "field", "field": "id"},
              {"kind": "field", "field": "status", "alias": "index_mismatch"}],
              "order_by": [{"field": "id", "direction": "asc"}], "limit": 2}
    result = request("/queries/select", {"kind": "keyset", "profile": admission,
                     "shape": "plan_keyset_index_mismatch", "query": keyset, "page": {"kind": "first"}}, status=422)
    assert result["code"] == "UNSUPPORTED_QUERY"
    assert main_select_count(service) == before

    # Views retain the known MySQL SELECT-only limitation in both contours.
    view_profile = "views-reader" if contour == "test" else "views-rc"
    view_spec = dict(spec, source={"schema": "application", "name": "Orders"},
                     projection=[{"kind": "field", "field": "id"}, {"kind": "field", "field": "status"}])
    result = request("/queries/select", {"profile": view_profile, "query": view_spec})
    assert result["rows"] == [["1", "active"], ["2", "closed"]]
    before = main_select_count(service)
    result = request("/queries/explain", {"profile": view_profile, "query": view_spec}, status=503)
    assert result["code"] == "DATABASE_UNAVAILABLE"
    view_aggregate = {"mode": "scalar", "source": view_spec["source"],
                      "projection": [{"kind": "measure", "function": "count_all", "alias": "row_count"}]}
    result = request("/queries/aggregate", {"profile": view_profile, "query": view_aggregate}, status=503)
    assert result["code"] == "DATABASE_UNAVAILABLE"
    result = request("/queries/select", {"kind": "keyset", "profile": view_profile, "shape": "Orders_pages",
                     "query": view_spec, "page": {"kind": "first"}}, status=503)
    assert result["code"] == "DATABASE_UNAVAILABLE"
    assert main_select_count(service) == before

print("Shared policy refs: two-datasource routing and authorization/plan denials passed.")
