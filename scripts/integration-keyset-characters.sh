#!/bin/sh
set -eu

# Only synthetic fixture values are parsed here. None contains a JSON bracket;
# sed extracts the exact server-issued tuple without normalizing its values.
character_page_request() {
  character_page_body="{\"kind\":\"keyset\",\"profile\":\"analytics\",\"datasource\":\"integration-mysql\",\"shape\":\"$character_shape\",\"query\":{\"source\":{\"schema\":\"application\",\"name\":\"${character_source:-character_keys}\"},\"projection\":$character_projection,$character_filter\"order_by\":$character_order,\"limit\":${character_limit:-1}},\"page\":$character_page}"
  character_http_response=$(curl --silent --show-error --write-out '\n%{http_code}' \
    --user integration-client:password \
    --header 'Content-Type: application/json' \
    --data "$character_page_body" \
    http://127.0.0.1:18080/queries/select)
  character_http_status=$(printf '%s\n' "$character_http_response" | tail -n 1)
  if [ "$character_http_status" != "${character_expected_status:-200}" ]; then
    echo "Character shape $character_shape returned HTTP $character_http_status instead of ${character_expected_status:-200}." >&2
    printf '%s\n' "$character_http_response" >&2
    exit 1
  fi
  printf '%s\n' "$character_http_response" | sed '$d'
}

check_character_pages() {
  character_shape=$1
  printf 'Checking character keyset %s\n' "$character_shape"
  character_projection=$2
  character_order=$3
  character_filter=$4
  shift 4
  for character_expected do
    character_expected_last=$character_expected
  done
  character_page='{"kind":"first"}'
  for character_expected do
    character_response=$(character_page_request)
    if ! printf '%s\n' "$character_response" | grep --fixed-strings --quiet "\"rows\":[$character_expected]"; then
      echo "Unexpected page for $character_shape; expected $character_expected." >&2
      printf '%s\n' "$character_response" >&2
      exit 1
    fi
    printf '%s\n' "$character_response" | grep --quiet '"row_count":1'
    if [ "$character_expected" != "$character_expected_last" ]; then
      printf '%s\n' "$character_response" | grep --quiet '"has_more":true'
      character_cursor=$(printf '%s\n' "$character_response" | sed -n 's/.*"next_cursor":\(\[[^]]*\]\).*/\1/p')
      printf '%s\n' "$character_cursor" | grep --quiet '"type":"string"'
      printf '%s\n' "$character_cursor" | grep --quiet '"type":"integer"'
      if printf '%s\n' "$character_cursor" | grep --quiet '"type":"bytes"'; then
        echo 'Character key was incorrectly exposed as a binary cursor.' >&2
        exit 1
      fi
      character_page="{\"kind\":\"after\",\"cursor\":$character_cursor}"
    else
      printf '%s\n' "$character_response" | grep --quiet '"has_more":false'
      if printf '%s\n' "$character_response" | grep --quiet 'next_cursor'; then
        echo 'Final character page unexpectedly contains a cursor.' >&2
        exit 1
      fi
    fi
  done
}

character_unicode_projection='[{"kind":"field","field":"id"},{"kind":"field","field":"unicode_label"},{"kind":"field","field":"western_label"}]'
character_unicode_order='[{"field":"unicode_label","direction":"asc"},{"field":"western_label","direction":"asc"},{"field":"id","direction":"asc"}]'
check_character_pages characters_by_unicode "$character_unicode_projection" "$character_unicode_order" \
  '"filter":{"kind":"predicate","field":"western_label","operator":"gte","values":[{"type":"string","value":""}]},' \
  '["0","",""]' '["1","a","Straße"]' '["2","A","Strasse"]' '["3","á","Strasse "]'
check_character_pages characters_by_unicode_desc "$character_unicode_projection" \
  '[{"field":"unicode_label","direction":"desc"},{"field":"western_label","direction":"desc"},{"field":"id","direction":"desc"}]' '' \
  '["3","á","Strasse "]' '["2","A","Strasse"]' '["1","a","Straße"]' '["0","",""]'
check_character_pages characters_by_western \
  '[{"kind":"field","field":"id"},{"kind":"field","field":"western_label"}]' \
  '[{"field":"western_label","direction":"asc"},{"field":"id","direction":"asc"}]' '' \
  '["0",""]' '["1","Straße"]' '["2","Strasse"]' '["3","Strasse "]'
check_character_pages characters_by_cyrillic \
  '[{"kind":"field","field":"id"},{"kind":"field","field":"cyrillic_label"}]' \
  '[{"field":"cyrillic_label","direction":"asc"},{"field":"id","direction":"asc"}]' '' \
  '["0",""]' '["1","А"]' '["2","а"]' '["3","Б"]'
check_character_pages characters_by_wide \
  '[{"kind":"field","field":"id"},{"kind":"field","field":"wide_label"}]' \
  '[{"field":"wide_label","direction":"desc"},{"field":"id","direction":"desc"}]' '' \
  '["3","😁"]' '["2","😀"]' '["1","😀"]' '["0",""]'
check_character_pages characters_by_ascii \
  '[{"kind":"field","field":"id"},{"kind":"field","field":"ascii_label"}]' \
  '[{"field":"ascii_label","direction":"asc"},{"field":"id","direction":"asc"}]' '' \
  '["0",""]' '["1","a"]' '["2","a"]' '["3","b"]'

# Incoming cursors and filters must reject unrepresentable Unicode without
# replacing it by '?', even when MySQL would report only a conversion warning.
character_expected_status=422
for character_field in unicode_label western_label cyrillic_label ascii_label; do
  case "$character_field" in
    unicode_label)
      character_shape=characters_by_unicode
      character_projection=$character_unicode_projection
      character_order=$character_unicode_order
      character_filter='"filter":{"kind":"predicate","field":"western_label","operator":"gte","values":[{"type":"string","value":""}]},'
      character_cursor='[{"type":"string","value":"😀"},{"type":"string","value":"Straße"},{"type":"integer","value":"1"}]'
      ;;
    *)
      character_suffix=$(printf '%s\n' "$character_field" | sed 's/_label$//')
      character_shape="characters_by_$character_suffix"
      character_projection="[{\"kind\":\"field\",\"field\":\"id\"},{\"kind\":\"field\",\"field\":\"$character_field\"}]"
      character_order="[{\"field\":\"$character_field\",\"direction\":\"asc\"},{\"field\":\"id\",\"direction\":\"asc\"}]"
      character_filter=''
      character_cursor='[{"type":"string","value":"😀"},{"type":"integer","value":"1"}]'
      ;;
  esac
  character_page="{\"kind\":\"after\",\"cursor\":$character_cursor}"
  character_page_request | grep --quiet '"code":"UNSUPPORTED_QUERY"'
done

character_shape=characters_by_unicode
character_projection=$character_unicode_projection
character_order=$character_unicode_order
character_page='{"kind":"first"}'
character_filter='"filter":{"kind":"predicate","field":"western_label","operator":"gte","values":[{"type":"string","value":"Ж"}]},'
character_page_request | grep --quiet '"code":"UNSUPPORTED_QUERY"'
character_expected_status=403
character_filter='"filter":{"kind":"predicate","field":"hidden_value","operator":"gte","values":[{"type":"string","value":""}]},'
character_page_request | grep --quiet '"code":"DENIED_QUERY_FEATURE"'
character_filter='"filter":{"kind":"predicate","field":"western_label","operator":"gte","values":[{"type":"string","value":""}]},'
character_projection='[{"kind":"field","field":"id"},{"kind":"field","field":"unicode_label"},{"kind":"field","field":"western_label"},{"kind":"field","field":"hidden_value"}]'
character_page_request | grep --quiet '"code":"DENIED_QUERY_FEATURE"'

# The ad-hoc SELECT path demonstrates deny-overrides-allow independently of
# curated-shape matching, including hidden metadata and filter-only references.
character_description=$(curl --fail --silent --show-error \
  --user integration-client:password \
  'http://127.0.0.1:18080/schemas/application/objects/character_keys?profile=data-reader&datasource=integration-mysql')
printf '%s\n' "$character_description" | grep --quiet '"name":"unicode_label"'
if printf '%s\n' "$character_description" | grep --quiet 'hidden_value'; then
  echo 'Character-key metadata exposed a denied field.' >&2
  exit 1
fi
for character_denied_query in \
  '{"source":{"schema":"application","name":"character_keys"},"projection":[{"kind":"field","field":"hidden_value"}],"limit":1}' \
  '{"source":{"schema":"application","name":"character_keys"},"projection":[{"kind":"field","field":"id"}],"filter":{"kind":"predicate","field":"hidden_value","operator":"eq","values":[{"type":"string","value":"hidden"}]},"limit":1}'; do
  character_denied_response=$(curl --silent --show-error --write-out '\n%{http_code}' \
    --user integration-client:password --header 'Content-Type: application/json' \
    --data "{\"profile\":\"data-reader\",\"datasource\":\"integration-mysql\",\"query\":$character_denied_query}" \
    http://127.0.0.1:18080/queries/select)
  printf '%s\n' "$character_denied_response" | tail -n 1 | grep --quiet '^403$'
  printf '%s\n' "$character_denied_response" | grep --quiet '"code":"DENIED_FIELD"'
done

# A source encoding can be non-injective even if every incoming Unicode value
# is representable. Reject a lossy source key, including after a valid prefix.
character_source=lossy_character_keys
character_shape=lossy_characters_by_pk
character_projection='[{"kind":"field","field":"id"},{"kind":"field","field":"label"}]'
character_order='[{"field":"label","direction":"asc"},{"field":"id","direction":"asc"}]'
character_filter=''
character_expected_status=200
character_page='{"kind":"first"}'
character_page_request | grep --quiet '"next_cursor":\[{"type":"string","value":"A"},{"type":"integer","value":"1"}\]'
character_expected_status=422
character_page='{"kind":"after","cursor":[{"type":"string","value":"A"},{"type":"integer","value":"1"}]}'
character_page_request | grep --quiet '"code":"UNSUPPORTED_QUERY"'
character_limit=20
character_page='{"kind":"first"}'
character_page_request | grep --quiet '"code":"UNSUPPORTED_QUERY"'
