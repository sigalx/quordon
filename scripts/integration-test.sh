#!/bin/sh
set -eu

compose_file=compose.integration.yaml
QUORDON_UID=$(id -u)
QUORDON_GID=$(id -g)
export QUORDON_UID QUORDON_GID
chmod 600 config/policy.integration.yaml
query_shapes_headers=""

cleanup() {
  if [ -n "$query_shapes_headers" ]; then
    rm -f "$query_shapes_headers"
  fi
  docker compose -f "$compose_file" down --volumes
}
trap cleanup EXIT INT TERM

docker compose -f "$compose_file" up --build --detach --wait

if docker compose -f "$compose_file" exec -T mysql \
  mysql --protocol=tcp --host=127.0.0.1 --user=quordon --password=quordon-password application \
  --execute="UPDATE orders SET status = 'tampered' WHERE id = 1" \
  >/dev/null 2>&1; then
  echo 'Integration database user unexpectedly has DML privileges.' >&2
  exit 1
fi

attempt=1
while ! curl --fail --silent --output /dev/null http://127.0.0.1:18080/health/ready; do
  if [ "$attempt" -ge 30 ]; then
    echo 'Quordon did not become ready within 30 seconds.' >&2
    exit 1
  fi
  attempt=$((attempt + 1))
  sleep 1
done

curl --fail --silent --show-error \
  --user integration-client:password \
  http://127.0.0.1:18080/capabilities \
  | grep --quiet 'explain_select'

capabilities=$(curl --fail --silent --show-error \
  --user integration-client:password \
  http://127.0.0.1:18080/capabilities)
printf '%s\n' "$capabilities" | grep --quiet 'list_objects'
printf '%s\n' "$capabilities" | grep --quiet 'describe_object'
printf '%s\n' "$capabilities" | grep --quiet '"select"'
printf '%s\n' "$capabilities" | grep --quiet '"select_keyset"'
printf '%s\n' "$capabilities" | grep --quiet '"aggregate"'
printf '%s\n' "$capabilities" | grep --quiet '"list_query_shapes"'
printf '%s\n' "$capabilities" | grep --quiet '"describe_object_statistics"'

query_shapes_headers=$(mktemp)
query_shapes=$(curl --fail --silent --show-error \
  --dump-header "$query_shapes_headers" \
  --user integration-client:password \
  --header 'Accept: application/vnd.quordon.query-shapes.v3+json' \
  'http://127.0.0.1:18080/query-shapes?profile=analytics')
grep --ignore-case --quiet '^Cache-Control: no-store' "$query_shapes_headers"
grep --ignore-case --quiet '^Vary: Accept' "$query_shapes_headers"
grep --ignore-case --quiet '^Content-Type: application/vnd.quordon.query-shapes.v3+json' "$query_shapes_headers"
printf '%s\n' "$query_shapes" | grep --quiet '"name":"orders_by_status"'
printf '%s\n' "$query_shapes" | grep --quiet '"name":"orders_by_id","description":"Page through orders in stable primary-key order.","operation":"select_keyset"'
printf '%s\n' "$query_shapes" | grep --quiet '"kind":"time_bucket","field":"created_at","alias":"created_day","unit":"day","timezone":"UTC"'
printf '%s\n' "$query_shapes" | grep --quiet '"value_types":\["string"\]'
if printf '%s\n' "$query_shapes" | grep --quiet 'required_index\|maximum_rows_examined_per_scan'; then
  echo 'Query-shape discovery exposed execution-only policy.' >&2
  exit 1
fi

legacy_query_shapes_status=$(curl --silent --show-error --output /dev/null --write-out '%{http_code}' \
  --user integration-client:password \
  --header 'Accept: application/json' \
  'http://127.0.0.1:18080/query-shapes?profile=analytics')
if [ "$legacy_query_shapes_status" != "406" ]; then
  echo "Legacy query-shape representation returned HTTP $legacy_query_shapes_status instead of 406." >&2
  exit 1
fi

v2_query_shapes_status=$(curl --silent --show-error --output /dev/null --write-out '%{http_code}' \
  --user integration-client:password \
  --header 'Accept: application/vnd.quordon.query-shapes.v2+json' \
  'http://127.0.0.1:18080/query-shapes?profile=analytics')
if [ "$v2_query_shapes_status" != "406" ]; then
  echo "V2 query-shape representation returned HTTP $v2_query_shapes_status instead of 406." >&2
  exit 1
fi

objects=$(curl --fail --silent --show-error \
  --user integration-client:password \
  'http://127.0.0.1:18080/schemas/application/objects?profile=data-reader')
printf '%s\n' "$objects" | grep --quiet '"name":"orders"'
if printf '%s\n' "$objects" | grep --quiet '"name":"Orders"'; then
  echo 'Schema discovery exposed a view.' >&2
  exit 1
fi

bounded_objects=$(curl --fail --silent --show-error \
  --user integration-client:password \
  'http://127.0.0.1:18080/schemas/application/objects?profile=metadata-reader')
printf '%s\n' "$bounded_objects" | grep --quiet '"objects":\[{"name":"orders"}\]'
if printf '%s\n' "$bounded_objects" | grep --quiet 'hidden_metadata'; then
  echo 'Policy-hidden objects affected or entered the bounded metadata response.' >&2
  exit 1
fi

description=$(curl --fail --silent --show-error \
  --user integration-client:password \
  'http://127.0.0.1:18080/schemas/application/objects/orders?profile=data-reader')
printf '%s\n' "$description" | grep --quiet '"name":"id","type":"integer"'
printf '%s\n' "$description" | grep --quiet '"name":"status","type":"string"'
printf '%s\n' "$description" | grep --quiet '"name":"location","type":"bytes"'
printf '%s\n' "$description" | grep --quiet '"primary_key":true,"indexed":true'
if printf '%s\n' "$description" | grep --quiet 'view_only'; then
  echo 'Physical table description mixed in columns from a case-colliding view.' >&2
  exit 1
fi

bounded_description=$(curl --fail --silent --show-error \
  --user integration-client:password \
  'http://127.0.0.1:18080/schemas/application/objects/orders?profile=metadata-reader')
printf '%s\n' "$bounded_description" | grep --quiet '"columns":\[{"name":"id"'
if printf '%s\n' "$bounded_description" | grep --quiet 'legacy_text'; then
  echo 'Policy-hidden columns affected or entered the bounded metadata response.' >&2
  exit 1
fi

view_description_status=$(curl --silent --show-error --output /dev/null --write-out '%{http_code}' \
  --user integration-client:password \
  'http://127.0.0.1:18080/schemas/application/objects/Orders?profile=data-reader')
if [ "$view_description_status" != "404" ]; then
  echo "View description returned HTTP $view_description_status instead of 404." >&2
  exit 1
fi

table_statistics=$(curl --fail --silent --show-error \
  --user integration-client:password \
  'http://127.0.0.1:18080/schemas/application/objects/orders/statistics?profile=data-reader')
printf '%s\n' "$table_statistics" | grep --quiet '"engine":"InnoDB"'
printf '%s\n' "$table_statistics" | grep --quiet '"estimated_rows":{"value":"[0-9]*","estimated":true}'
printf '%s\n' "$table_statistics" | grep --quiet '"partitioning":{"kind":"none"}'

partitioned_statistics=$(curl --fail --silent --show-error \
  --user integration-client:password \
  'http://127.0.0.1:18080/schemas/application/objects/partitioned_orders/statistics?profile=data-reader')
printf '%s\n' "$partitioned_statistics" | grep --quiet '"kind":"partitioned","method":"range"'
printf '%s\n' "$partitioned_statistics" | grep --quiet '"name":"p_low","ordinal":1'
printf '%s\n' "$partitioned_statistics" | grep --quiet '"name":"p_max","ordinal":2'

subpartitioned_statistics=$(curl --fail --silent --show-error \
  --user integration-client:password \
  'http://127.0.0.1:18080/schemas/application/objects/subpartitioned_events/statistics?profile=data-reader')
printf '%s\n' "$subpartitioned_statistics" | grep --quiet '"kind":"subpartitioned","method":"range","subpartition_method":"hash"'
printf '%s\n' "$subpartitioned_statistics" | grep --quiet '"subpartitions"'

for unsupported_statistics_object in Orders legacy_exact_rows; do
  unsupported_statistics_status=$(curl --silent --show-error --output /dev/null --write-out '%{http_code}' \
    --user integration-client:password \
    "http://127.0.0.1:18080/schemas/application/objects/$unsupported_statistics_object/statistics?profile=data-reader")
  if [ "$unsupported_statistics_status" != "404" ]; then
    echo "Statistics for $unsupported_statistics_object returned HTTP $unsupported_statistics_status instead of 404." >&2
    exit 1
  fi
done

response=$(curl --fail --silent --show-error \
  --user integration-client:password \
  --header 'Content-Type: application/json' \
  --data '{"profile":"query-explainer","query":{"source":{"schema":"application","name":"orders"},"projection":[{"kind":"field","field":"id"},{"kind":"field","field":"status"}],"filter":{"kind":"predicate","field":"status","operator":"eq","values":[{"type":"string","value":"active"}]},"order_by":[{"field":"id","direction":"desc"}],"limit":10}}' \
  http://127.0.0.1:18080/queries/explain)
echo "$response" | grep --quiet '"format":"mysql_json"'
echo "$response" | grep --quiet '"query_block"'

alias_response=$(curl --fail --silent --show-error \
  --user integration-client:password \
  --header 'Content-Type: application/json' \
  --data '{"profile":"query-explainer","query":{"source":{"schema":"application","name":"orders"},"projection":[{"kind":"aggregate","function":"count","alias":"id"}],"group_by":["id"],"order_by":[{"field":"id","direction":"asc"}],"limit":10}}' \
  http://127.0.0.1:18080/queries/explain)
echo "$alias_response" | grep --quiet '"format":"mysql_json"'
echo "$alias_response" | grep --quiet '"query_block"'

select_response=$(curl --fail --silent --show-error \
  --user integration-client:password \
  --header 'Content-Type: application/json' \
  --data '{"profile":"data-reader","query":{"source":{"schema":"application","name":"orders"},"projection":[{"kind":"field","field":"id"},{"kind":"field","field":"status"},{"kind":"field","field":"amount"}],"order_by":[{"field":"id","direction":"asc"}],"limit":1}}' \
  http://127.0.0.1:18080/queries/select)
printf '%s\n' "$select_response" | grep --quiet '"rows":\[\["1","active","10.00"\]\]'
printf '%s\n' "$select_response" | grep --quiet '"name":"id","type":"integer","encoding":"string"'
printf '%s\n' "$select_response" | grep --quiet '"row_count":1'
printf '%s\n' "$select_response" | grep --quiet '"truncated":true'

keyset_first_response=$(curl --fail --silent --show-error \
  --user integration-client:password \
  --header 'Content-Type: application/json' \
  --data '{"kind":"keyset","profile":"analytics","shape":"orders_by_id","query":{"source":{"schema":"application","name":"orders"},"projection":[{"kind":"field","field":"id"},{"kind":"field","field":"status"},{"kind":"field","field":"amount"}],"filter":{"kind":"group","operator":"and","expressions":[{"kind":"predicate","field":"amount","operator":"gte","values":[{"type":"decimal","value":1e1}]},{"kind":"predicate","field":"id","operator":"gte","values":[{"type":"integer","value":0}]}]},"order_by":[{"field":"id","direction":"asc"}],"limit":1},"page":{"kind":"first"}}' \
  http://127.0.0.1:18080/queries/select)
printf '%s\n' "$keyset_first_response" | grep --quiet '"kind":"keyset"'
printf '%s\n' "$keyset_first_response" | grep --quiet '"shape":"orders_by_id"'
printf '%s\n' "$keyset_first_response" | grep --quiet '"rows":\[\["1","active","10.00"\]\]'
printf '%s\n' "$keyset_first_response" | grep --quiet '"truncated":true'
printf '%s\n' "$keyset_first_response" | grep --quiet '"page":{"has_more":true,"next_cursor":\[{"type":"integer","value":"1"}\]}'

keyset_after_response=$(curl --fail --silent --show-error \
  --user integration-client:password \
  --header 'Content-Type: application/json' \
  --data '{"kind":"keyset","profile":"analytics","shape":"orders_by_id","query":{"source":{"schema":"application","name":"orders"},"projection":[{"kind":"field","field":"id"},{"kind":"field","field":"status"},{"kind":"field","field":"amount"}],"filter":{"kind":"group","operator":"and","expressions":[{"kind":"predicate","field":"amount","operator":"gte","values":[{"type":"decimal","value":10.00}]},{"kind":"predicate","field":"id","operator":"gte","values":[{"type":"integer","value":0}]}]},"order_by":[{"field":"id","direction":"asc"}],"limit":1},"page":{"kind":"after","cursor":[{"type":"integer","value":"1"}]}}' \
  http://127.0.0.1:18080/queries/select)
printf '%s\n' "$keyset_after_response" | grep --quiet '"rows":\[\["2","closed","20.00"\]\]'
printf '%s\n' "$keyset_after_response" | grep --quiet '"truncated":false'
printf '%s\n' "$keyset_after_response" | grep --quiet '"page":{"has_more":false}'
if printf '%s\n' "$keyset_after_response" | grep --quiet 'next_cursor'; then
  echo 'Final keyset page unexpectedly contains next_cursor.' >&2
  exit 1
fi

keyset_decimal_overflow_status=$(curl --silent --show-error --output /dev/null --write-out '%{http_code}' \
  --user integration-client:password \
  --header 'Content-Type: application/json' \
  --data '{"kind":"keyset","profile":"analytics","shape":"orders_by_id","query":{"source":{"schema":"application","name":"orders"},"projection":[{"kind":"field","field":"id"},{"kind":"field","field":"status"},{"kind":"field","field":"amount"}],"filter":{"kind":"group","operator":"and","expressions":[{"kind":"predicate","field":"amount","operator":"gte","values":[{"type":"decimal","value":10.001}]},{"kind":"predicate","field":"id","operator":"gte","values":[{"type":"integer","value":0}]}]},"order_by":[{"field":"id","direction":"asc"}],"limit":1},"page":{"kind":"first"}}' \
  http://127.0.0.1:18080/queries/select)
if [ "$keyset_decimal_overflow_status" != "422" ]; then
  echo "Out-of-scale keyset decimal returned HTTP $keyset_decimal_overflow_status instead of 422." >&2
  exit 1
fi

keyset_unsigned_negative_status=$(curl --silent --show-error --output /dev/null --write-out '%{http_code}' \
  --user integration-client:password \
  --header 'Content-Type: application/json' \
  --data '{"kind":"keyset","profile":"analytics","shape":"orders_by_id","query":{"source":{"schema":"application","name":"orders"},"projection":[{"kind":"field","field":"id"},{"kind":"field","field":"status"},{"kind":"field","field":"amount"}],"filter":{"kind":"group","operator":"and","expressions":[{"kind":"predicate","field":"amount","operator":"gte","values":[{"type":"decimal","value":10}]},{"kind":"predicate","field":"id","operator":"gte","values":[{"type":"integer","value":-1}]}]},"order_by":[{"field":"id","direction":"asc"}],"limit":1},"page":{"kind":"first"}}' \
  http://127.0.0.1:18080/queries/select)
if [ "$keyset_unsigned_negative_status" != "422" ]; then
  echo "Negative filter for an unsigned keyset column returned HTTP $keyset_unsigned_negative_status instead of 422." >&2
  exit 1
fi

integral_number_response=$(curl --fail --silent --show-error \
  --user integration-client:password \
  --header 'Content-Type: application/json' \
  --data '{"profile":"data-reader","query":{"source":{"schema":"application","name":"orders"},"projection":[{"kind":"field","field":"id"}],"filter":{"kind":"predicate","field":"id","operator":"eq","values":[{"type":"integer","value":1e0}]},"limit":1.0,"offset":0e2}}' \
  http://127.0.0.1:18080/queries/select)
printf '%s\n' "$integral_number_response" | grep --quiet '"rows":\[\["1"\]\]'
printf '%s\n' "$integral_number_response" | grep --quiet '"row_count":1'

temporal_response=$(curl --fail --silent --show-error \
  --user integration-client:password \
  --header 'Content-Type: application/json' \
  --data '{"profile":"data-reader","query":{"source":{"schema":"application","name":"orders"},"projection":[{"kind":"field","field":"created_at"}],"order_by":[{"field":"id","direction":"asc"}],"limit":1}}' \
  http://127.0.0.1:18080/queries/select)
printf '%s\n' "$temporal_response" | grep --quiet '"name":"created_at","type":"datetime","encoding":"string"'
printf '%s\n' "$temporal_response" | grep --quiet '"rows":\[\["2026-08-15 10:00:00"\]\]'

text_response=$(curl --fail --silent --show-error \
  --user integration-client:password \
  --header 'Content-Type: application/json' \
  --data '{"profile":"data-reader","query":{"source":{"schema":"application","name":"orders"},"projection":[{"kind":"field","field":"legacy_text"}],"order_by":[{"field":"id","direction":"asc"}],"limit":1}}' \
  http://127.0.0.1:18080/queries/select)
printf '%s\n' "$text_response" | grep --quiet '"name":"legacy_text","type":"string","encoding":"string"'
printf '%s\n' "$text_response" | grep --quiet '"rows":\[\["café"\]\]'

spatial_response=$(curl --fail --silent --show-error \
  --user integration-client:password \
  --header 'Content-Type: application/json' \
  --data '{"profile":"data-reader","query":{"source":{"schema":"application","name":"orders"},"projection":[{"kind":"field","field":"location"}],"order_by":[{"field":"id","direction":"asc"}],"limit":1}}' \
  http://127.0.0.1:18080/queries/select)
printf '%s\n' "$spatial_response" | grep --quiet '"name":"location","type":"bytes","encoding":"base64"'

byte_truncated_response=$(curl --fail --silent --show-error \
  --user integration-client:password \
  --header 'Content-Type: application/json' \
  --data '{"profile":"data-reader","query":{"source":{"schema":"application","name":"orders"},"projection":[{"kind":"field","field":"payload"}],"order_by":[{"field":"id","direction":"asc"}],"limit":10}}' \
  http://127.0.0.1:18080/queries/select)
printf '%s\n' "$byte_truncated_response" | grep --quiet '"rows":\[\["small"\]\]'
printf '%s\n' "$byte_truncated_response" | grep --quiet '"row_count":1'
printf '%s\n' "$byte_truncated_response" | grep --quiet '"truncated":true'

first_row_truncated_response=$(curl --fail --silent --show-error \
  --user integration-client:password \
  --header 'Content-Type: application/json' \
  --data '{"profile":"data-reader","query":{"source":{"schema":"application","name":"orders"},"projection":[{"kind":"field","field":"payload"}],"order_by":[{"field":"id","direction":"desc"}],"limit":10}}' \
  http://127.0.0.1:18080/queries/select)
printf '%s\n' "$first_row_truncated_response" | grep --quiet '"rows":\[\]'
printf '%s\n' "$first_row_truncated_response" | grep --quiet '"row_count":0'
printf '%s\n' "$first_row_truncated_response" | grep --quiet '"truncated":true'

grouped_aggregate_response=$(curl --fail --silent --show-error \
  --user integration-client:password \
  --header 'Content-Type: application/json' \
  --data '{"profile":"analytics","query":{"mode":"grouped","source":{"schema":"application","name":"orders"},"projection":[{"kind":"dimension","field":"status"},{"kind":"measure","function":"count_all","alias":"orders_count"},{"kind":"measure","function":"sum","field":"amount","alias":"amount_sum"}],"limit":20}}' \
  http://127.0.0.1:18080/queries/aggregate)
printf '%s\n' "$grouped_aggregate_response" | grep --quiet '"mode":"grouped"'
printf '%s\n' "$grouped_aggregate_response" | grep --quiet '\["active","1","10.00"\]'
printf '%s\n' "$grouped_aggregate_response" | grep --quiet '\["closed","1","20.00"\]'
printf '%s\n' "$grouped_aggregate_response" | grep --quiet '"name":"orders_count","type":"integer","encoding":"string","nullable":false'
printf '%s\n' "$grouped_aggregate_response" | grep --quiet '"name":"amount_sum","type":"decimal","encoding":"string","nullable":false'
printf '%s\n' "$grouped_aggregate_response" | grep --quiet '"row_count":2'
printf '%s\n' "$grouped_aggregate_response" | grep --quiet '"truncated":false'

time_bucket_response=$(curl --fail --silent --show-error \
  --user integration-client:password \
  --header 'Content-Type: application/json' \
  --data '{"profile":"analytics","query":{"mode":"grouped","source":{"schema":"application","name":"orders"},"projection":[{"kind":"time_bucket","field":"created_at","unit":"day","timezone":"UTC","alias":"created_day"},{"kind":"measure","function":"count_all","alias":"orders_count"}],"order_by":[{"kind":"time_bucket","alias":"created_day","direction":"asc"}],"limit":20}}' \
  http://127.0.0.1:18080/queries/aggregate)
printf '%s\n' "$time_bucket_response" | grep --quiet '"mode":"grouped"'
printf '%s\n' "$time_bucket_response" | grep --quiet '"name":"created_day","type":"datetime","encoding":"string","nullable":false'
printf '%s\n' "$time_bucket_response" | grep --quiet '"rows":\[\["2026-08-15T00:00:00Z","2"\]\]'
printf '%s\n' "$time_bucket_response" | grep --quiet '"row_count":1'

scalar_aggregate_response=$(curl --fail --silent --show-error \
  --user integration-client:password \
  --header 'Content-Type: application/json' \
  --data '{"profile":"analytics","query":{"mode":"scalar","source":{"schema":"application","name":"orders"},"projection":[{"kind":"measure","function":"count_all","alias":"orders_count"},{"kind":"measure","function":"max","field":"created_at","alias":"latest_created_at"}],"filter":{"kind":"predicate","field":"status","operator":"eq","values":[{"type":"string","value":"active"}]}}}' \
  http://127.0.0.1:18080/queries/aggregate)
printf '%s\n' "$scalar_aggregate_response" | grep --quiet '"mode":"scalar"'
printf '%s\n' "$scalar_aggregate_response" | grep --quiet '"rows":\[\["1","2026-08-15 10:00:00"\]\]'
printf '%s\n' "$scalar_aggregate_response" | grep --quiet '"row_count":1'
printf '%s\n' "$scalar_aggregate_response" | grep --quiet '"truncated":false'

empty_scalar_aggregate_response=$(curl --fail --silent --show-error \
  --user integration-client:password \
  --header 'Content-Type: application/json' \
  --data '{"profile":"analytics","query":{"mode":"scalar","source":{"schema":"application","name":"orders"},"projection":[{"kind":"measure","function":"count_all","alias":"missing_orders_count"},{"kind":"measure","function":"max","field":"created_at","alias":"latest_missing_created_at"}],"filter":{"kind":"predicate","field":"id","operator":"eq","values":[{"type":"integer","value":999}]}}}' \
  http://127.0.0.1:18080/queries/aggregate)
printf '%s\n' "$empty_scalar_aggregate_response" | grep --quiet '"mode":"scalar"'
printf '%s\n' "$empty_scalar_aggregate_response" | grep --quiet '"rows":\[\["0",null\]\]'
printf '%s\n' "$empty_scalar_aggregate_response" | grep --quiet '"name":"missing_orders_count","type":"integer","encoding":"string","nullable":false'
printf '%s\n' "$empty_scalar_aggregate_response" | grep --quiet '"name":"latest_missing_created_at","type":"datetime","encoding":"string","nullable":true'
printf '%s\n' "$empty_scalar_aggregate_response" | grep --quiet '"row_count":1'
printf '%s\n' "$empty_scalar_aggregate_response" | grep --quiet '"truncated":false'

unmatched_aggregate_status=$(curl --silent --show-error --output /dev/null --write-out '%{http_code}' \
  --user integration-client:password \
  --header 'Content-Type: application/json' \
  --data '{"profile":"analytics","query":{"mode":"grouped","source":{"schema":"application","name":"orders"},"projection":[{"kind":"dimension","field":"status"},{"kind":"measure","function":"count_all","alias":"orders_count"}],"order_by":[{"kind":"dimension","field":"status","direction":"asc"}],"limit":20}}' \
  http://127.0.0.1:18080/queries/aggregate)
if [ "$unmatched_aggregate_status" != "403" ]; then
  echo "Unmatched aggregate shape returned HTTP $unmatched_aggregate_status instead of 403." >&2
  exit 1
fi

invisible_index_status=$(curl --silent --show-error --output /dev/null --write-out '%{http_code}' \
  --user integration-client:password \
  --header 'Content-Type: application/json' \
  --data '{"profile":"analytics","query":{"mode":"scalar","source":{"schema":"application","name":"orders"},"projection":[{"kind":"measure","function":"count_all","alias":"invisible_index_count"}],"filter":{"kind":"predicate","field":"status","operator":"eq","values":[{"type":"string","value":"active"}]}}}' \
  http://127.0.0.1:18080/queries/aggregate)
if [ "$invisible_index_status" != "422" ]; then
  echo "Aggregate requiring an invisible index returned HTTP $invisible_index_status instead of 422." >&2
  exit 1
fi

aggregate_select_status=$(curl --silent --show-error --output /dev/null --write-out '%{http_code}' \
  --user integration-client:password \
  --header 'Content-Type: application/json' \
  --data '{"profile":"data-reader","query":{"source":{"schema":"application","name":"orders"},"projection":[{"kind":"aggregate","function":"count"}],"limit":10}}' \
  http://127.0.0.1:18080/queries/select)
if [ "$aggregate_select_status" != "400" ]; then
	echo "Aggregate SELECT returned HTTP $aggregate_select_status instead of 400." >&2
	exit 1
fi

empty_group_select_status=$(curl --silent --show-error --output /dev/null --write-out '%{http_code}' \
  --user integration-client:password \
  --header 'Content-Type: application/json' \
  --data '{"profile":"data-reader","query":{"source":{"schema":"application","name":"orders"},"projection":[{"kind":"field","field":"id"}],"group_by":[]}}' \
  http://127.0.0.1:18080/queries/select)
if [ "$empty_group_select_status" != "400" ]; then
	echo "SELECT with explicit group_by returned HTTP $empty_group_select_status instead of 400." >&2
	exit 1
fi

select_view_status=$(curl --silent --show-error --output /dev/null --write-out '%{http_code}' \
  --user integration-client:password \
  --header 'Content-Type: application/json' \
  --data '{"profile":"data-reader","query":{"source":{"schema":"application","name":"Orders"},"projection":[{"kind":"field","field":"id"}],"limit":10}}' \
  http://127.0.0.1:18080/queries/select)
if [ "$select_view_status" != "422" ]; then
	echo "SELECT over a view returned HTTP $select_view_status instead of 422." >&2
	exit 1
fi

view_status=$(curl --silent --show-error --output /dev/null --write-out '%{http_code}' \
  --user integration-client:password \
  --header 'Content-Type: application/json' \
  --data '{"profile":"query-explainer","query":{"source":{"schema":"application","name":"Orders"},"projection":[{"kind":"field","field":"id"}],"limit":10}}' \
  http://127.0.0.1:18080/queries/explain)
if [ "$view_status" != "422" ]; then
  echo "EXPLAIN over a view returned HTTP $view_status instead of 422." >&2
  exit 1
fi

missing_column_status=$(curl --silent --show-error --output /dev/null --write-out '%{http_code}' \
  --user integration-client:password \
  --header 'Content-Type: application/json' \
  --data '{"profile":"query-explainer","query":{"source":{"schema":"application","name":"orders"},"projection":[{"kind":"field","field":"missing_column"}],"limit":10}}' \
  http://127.0.0.1:18080/queries/explain)
if [ "$missing_column_status" != "422" ]; then
  echo "EXPLAIN with a missing column returned HTTP $missing_column_status instead of 422." >&2
  exit 1
fi

audit_output=$(docker compose -f "$compose_file" logs --no-color quordon)
printf '%s\n' "$audit_output" | grep --quiet '"client_identifier":"integration-client"'
printf '%s\n' "$audit_output" | grep --quiet '"resources":\[{"schema":"application","object":"orders"}\]'
printf '%s\n' "$audit_output" | grep --quiet '"fields":\["id","status"\]'
printf '%s\n' "$audit_output" | grep --quiet '"result_bytes":'
printf '%s\n' "$audit_output" | grep --quiet '"object":"Orders"'
printf '%s\n' "$audit_output" | grep --quiet '"error_kind":"invalid"'
printf '%s\n' "$audit_output" | grep --quiet '"operation":"list_objects"'
printf '%s\n' "$audit_output" | grep --quiet '"operation":"describe_object"'
printf '%s\n' "$audit_output" | grep --quiet '"operation":"select"'
printf '%s\n' "$audit_output" | grep --quiet '"operation":"select_keyset"'
printf '%s\n' "$audit_output" | grep --quiet '"operation":"aggregate"'
printf '%s\n' "$audit_output" | grep --quiet '"operation":"list_query_shapes"'
printf '%s\n' "$audit_output" | grep --quiet '"operation":"describe_object_statistics"'
printf '%s\n' "$audit_output" | grep --quiet '"partition_count":2'
printf '%s\n' "$audit_output" | grep --quiet '"subpartition_count":4'
printf '%s\n' "$audit_output" | grep --quiet '"public_shape_set_hash":'
printf '%s\n' "$audit_output" | grep --quiet '"aggregate_shape":"orders_by_status"'
printf '%s\n' "$audit_output" | grep --quiet '"keyset_shape":"orders_by_id"'
printf '%s\n' "$audit_output" | grep --quiet '"has_more":true'
keyset_success_audit=$(printf '%s\n' "$audit_output" | grep '"operation":"select_keyset"' | grep '"outcome":"success"')
printf '%s\n' "$keyset_success_audit" | grep --quiet '"truncated":true'
printf '%s\n' "$keyset_success_audit" | grep --quiet '"truncated":false'
if printf '%s\n' "$audit_output" | grep --quiet 'next_cursor'; then
  echo 'Audit output exposed a keyset cursor.' >&2
  exit 1
fi
printf '%s\n' "$audit_output" | grep --quiet '"row_count":1'
printf '%s\n' "$audit_output" | grep --quiet '"truncated":true'
echo 'Quordon integration test passed.'
