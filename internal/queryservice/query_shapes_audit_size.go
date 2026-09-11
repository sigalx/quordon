package queryservice

import (
	"errors"
	"sort"
	"unicode/utf8"

	"github.com/sigalx/quordon/internal/audit"
)

// queryShapeAuditEventJSONSizeWithin counts the exact encoding/json payload
// size for the closed audit.Event representation used by startup preflights.
// It stops as soon as maximum is exceeded and never materializes the event JSON
// or an encoded copy of an attacker/configuration-controlled string. The
// trailing newline written by JSONSink is intentionally counted by the caller.
func queryShapeAuditEventJSONSizeWithin(event audit.Event, maximum int) (int, bool, error) {
	counter := newBoundedJSONSize(maximum)
	counter.add(1) // {
	first := true
	addStringField := func(name, value string, omitEmpty bool) {
		if omitEmpty && value == "" {
			return
		}
		counter.addObjectField(name, &first)
		counter.addString(value)
	}
	addIntegerField := func(name string, value int64, omitEmpty bool) {
		if omitEmpty && value == 0 {
			return
		}
		counter.addObjectField(name, &first)
		counter.addInteger(value)
	}

	counter.addObjectField("timestamp", &first)
	timestampJSON, err := event.Timestamp.MarshalJSON()
	if err != nil {
		return 0, false, err
	}
	counter.add(len(timestampJSON))
	addStringField("type", event.Type, false)
	addStringField("request_id", event.RequestID, false)
	addStringField("query_id", event.QueryID, true)
	addStringField("principal", event.Principal, true)
	addStringField("client_identifier", event.ClientIdentifier, true)
	addStringField("policy_profile", event.PolicyProfile, true)
	addStringField("policy_version", event.PolicyVersion, false)
	addStringField("policy_hash", event.PolicyHash, false)
	addStringField("datasource", event.Datasource, true)
	addStringField("adapter", event.Adapter, true)
	addStringField("operation", event.Operation, true)
	addStringField("decision", event.Decision, true)
	addStringField("reason_code", event.ReasonCode, true)
	addStringField("outcome", event.Outcome, true)
	addStringField("error_kind", event.ErrorKind, true)
	if event.DurationMS != nil {
		addIntegerField("duration_ms", *event.DurationMS, false)
	}
	addIntegerField("result_bytes", int64(event.ResultBytes), true)
	addStringField("query_shape_hash", event.QueryShapeHash, true)
	addStringField("public_shape_set_hash", event.PublicShapeSetHash, true)
	addIntegerField("shape_count", int64(event.ShapeCount), true)
	addStringField("requested_profile_hash", event.RequestedProfileHash, true)
	addIntegerField("requested_profile_bytes", int64(event.RequestedProfileBytes), true)
	if len(event.Resources) != 0 {
		counter.addObjectField("resources", &first)
		counter.add(1) // [
		for index, resource := range event.Resources {
			if !counter.within {
				break
			}
			if index != 0 {
				counter.add(1) // ,
			}
			counter.add(1) // {
			resourceFirst := true
			counter.addObjectField("schema", &resourceFirst)
			counter.addString(resource.Schema)
			if resource.Object != "" {
				counter.addObjectField("object", &resourceFirst)
				counter.addString(resource.Object)
			}
			counter.add(1) // }
		}
		counter.add(1) // ]
	}
	if len(event.Fields) != 0 {
		counter.addObjectField("fields", &first)
		counter.add(1) // [
		for index, field := range event.Fields {
			if !counter.within {
				break
			}
			if index != 0 {
				counter.add(1) // ,
			}
			counter.addString(field)
		}
		counter.add(1) // ]
	}
	if len(event.Metadata) != 0 {
		counter.addObjectField("metadata", &first)
		counter.add(1) // {
		keys := make([]string, 0, len(event.Metadata))
		for key := range event.Metadata {
			keys = append(keys, key)
		}
		sort.Strings(keys) // encoding/json sorts string map keys.
		metadataFirst := true
		for _, key := range keys {
			counter.addObjectField(key, &metadataFirst)
			switch value := event.Metadata[key].(type) {
			case bool:
				if value {
					counter.add(len("true"))
				} else {
					counter.add(len("false"))
				}
			case int:
				counter.addInteger(int64(value))
			case int64:
				counter.addInteger(value)
			case string:
				counter.addString(value)
			default:
				return 0, false, errors.New("audit preflight encountered unsupported metadata")
			}
		}
		counter.add(1) // }
	}
	counter.add(1) // }
	return counter.size, counter.within, nil
}

type boundedJSONSize struct {
	size    int
	maximum int
	within  bool
}

func newBoundedJSONSize(maximum int) *boundedJSONSize {
	return &boundedJSONSize{maximum: maximum, within: maximum >= 0}
}

func (c *boundedJSONSize) add(size int) bool {
	if !c.within {
		return false
	}
	if size < 0 || size > c.maximum-c.size {
		c.within = false
		return false
	}
	c.size += size
	return true
}

func (c *boundedJSONSize) addObjectField(name string, first *bool) {
	if !c.within {
		return
	}
	if !*first {
		c.add(1) // ,
	}
	*first = false
	c.addString(name)
	c.add(1) // :
}

func (c *boundedJSONSize) addString(value string) {
	if !c.add(2) { // opening and closing quotes
		return
	}
	for index := 0; index < len(value) && c.within; {
		character := value[index]
		if character < utf8.RuneSelf {
			switch character {
			case '\\', '"', '\b', '\f', '\n', '\r', '\t':
				c.add(2)
			case '<', '>', '&':
				c.add(6)
			default:
				if character < 0x20 {
					c.add(6)
				} else {
					c.add(1)
				}
			}
			index++
			continue
		}
		runeValue, width := utf8.DecodeRuneInString(value[index:])
		if runeValue == utf8.RuneError && width == 1 {
			c.add(6) // encoding/json replaces invalid UTF-8 with \ufffd.
			index++
			continue
		}
		if runeValue == '\u2028' || runeValue == '\u2029' {
			c.add(6)
		} else {
			c.add(width)
		}
		index += width
	}
}

func (c *boundedJSONSize) addInteger(value int64) {
	c.add(jsonIntegerSize(value))
}

func jsonIntegerSize(value int64) int {
	if value == 0 {
		return 1
	}
	size := 0
	var magnitude uint64
	if value < 0 {
		size++
		magnitude = uint64(-(value + 1)) + 1
	} else {
		magnitude = uint64(value)
	}
	for magnitude != 0 {
		size++
		magnitude /= 10
	}
	return size
}
