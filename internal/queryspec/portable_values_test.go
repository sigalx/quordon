package queryspec

import "testing"

func TestPortableTemporalValuesUseClosedAdapterNeutralForms(t *testing.T) {
	validDates := []string{"0001-01-01", "2000-02-29", "9999-12-31"}
	for _, value := range validDates {
		if _, ok := ParsePortableDate(value); !ok {
			t.Fatalf("portable date %q was rejected", value)
		}
	}
	invalidDates := []string{"0000-01-01", "10000-01-01", "2026-02-29", "2026-00-01", "2026-01-00", "2026-1-01"}
	for _, value := range invalidDates {
		if _, ok := ParsePortableDate(value); ok {
			t.Fatalf("non-portable date %q was accepted", value)
		}
	}

	validDateTimes := []struct {
		value  string
		digits int
	}{
		{value: "0001-01-01 00:00:00"},
		{value: "2026-02-28 12:34:56.1", digits: 1},
		{value: "9999-12-31 23:59:59.123456789", digits: 9},
	}
	for _, fixture := range validDateTimes {
		if _, digits, ok := ParsePortableDateTime(fixture.value); !ok || digits != fixture.digits {
			t.Fatalf("portable datetime %q => digits=%d valid=%t", fixture.value, digits, ok)
		}
	}
	for _, value := range []string{
		"0000-01-01 00:00:00", "2026-02-29 00:00:00", "2026-01-01T00:00:00",
		"2026-01-01 00:00:00Z", "2026-01-01 00:00:00.", "2026-01-01 00:00:00.1234567890",
	} {
		if _, _, ok := ParsePortableDateTime(value); ok {
			t.Fatalf("non-portable datetime %q was accepted", value)
		}
	}

	validTimestamps := []struct {
		value  string
		digits int
	}{
		{value: "0001-01-01T00:00:00Z"},
		{value: "2026-02-28T12:34:56.123456Z", digits: 6},
		{value: "9999-12-31T23:59:59.123456789Z", digits: 9},
	}
	for _, fixture := range validTimestamps {
		if parsed, digits, ok := ParsePortableTimestamp(fixture.value); !ok || digits != fixture.digits || parsed.Location().String() != "UTC" {
			t.Fatalf("portable timestamp %q => value=%v digits=%d valid=%t", fixture.value, parsed, digits, ok)
		}
	}
	for _, value := range []string{
		"2026-01-01 00:00:00Z", "2026-01-01t00:00:00z", "2026-01-01T00:00:00+00:00",
		"2026-01-01T00:00:00", "infinity", "-infinity", "2026-01-01T00:00:00.1234567890Z",
	} {
		if _, _, ok := ParsePortableTimestamp(value); ok {
			t.Fatalf("non-portable timestamp %q was accepted", value)
		}
	}
}

func TestPortableTimeAllowsNineFractionalDigits(t *testing.T) {
	for _, value := range []string{"00:00:00", "100:00:00", "-01:02:03.4", "838:59:59.123456789"} {
		if !ValidPortableTime(value) {
			t.Fatalf("portable time %q was rejected", value)
		}
	}
	for _, value := range []string{"+01:00:00", "001:00:00", "838:59:59.1234567890", "839:00:00"} {
		if ValidPortableTime(value) {
			t.Fatalf("non-portable time %q was accepted", value)
		}
	}
}
