package database

import "testing"

func TestValidTimeCellUsesClosedCanonicalSyntax(t *testing.T) {
	for _, value := range []string{
		"00:00:00", "23:59:59", "100:00:00", "838:59:59.999999", "-01:02:03.4",
	} {
		if !ValidTimeCell(value) {
			t.Fatalf("canonical TIME %q was rejected", value)
		}
	}
	for _, value := range []string{
		"+01:00:00", "-+01:00:00", "--01:00:00", "001:00:00", "839:00:00",
		"01:60:00", "01:00:60", "1:00:00", "01:00:00.", "01:00:00.0000000",
	} {
		if ValidTimeCell(value) {
			t.Fatalf("noncanonical TIME %q was accepted", value)
		}
	}
}

func TestTemporalResultCellsUseCanonicalMySQLRanges(t *testing.T) {
	for _, value := range []string{"1000-01-01", "2026-09-10", "9999-12-31"} {
		if !ValidDateCell(value) {
			t.Fatalf("valid DATE %q was rejected", value)
		}
	}
	for _, value := range []string{"0000-01-01", "0999-12-31", "2026-02-29", "10000-01-01"} {
		if ValidDateCell(value) {
			t.Fatalf("invalid DATE %q was accepted", value)
		}
	}

	for _, value := range []string{
		"1000-01-01 00:00:00", "2026-09-10 12:34:56.1", "9999-12-31 23:59:59.499999",
	} {
		if !ValidDateTimeCell(value) {
			t.Fatalf("valid DATETIME %q was rejected", value)
		}
	}
	for _, value := range []string{
		"0000-01-01 00:00:00", "0999-12-31 23:59:59", "2026-09-10T12:34:56",
		"9999-12-31 23:59:59.500000", "2026-09-10 12:34:56.1234567",
	} {
		if ValidDateTimeCell(value) {
			t.Fatalf("invalid DATETIME %q was accepted", value)
		}
	}

	for _, value := range []string{"1970-01-01 00:00:01", "2038-01-19 03:14:07.499999"} {
		if !ValidTimestampCell(value) {
			t.Fatalf("valid TIMESTAMP %q was rejected", value)
		}
	}
	for _, value := range []string{"1000-01-01 00:00:00", "2038-01-19 03:14:07.500000"} {
		if ValidTimestampCell(value) {
			t.Fatalf("invalid TIMESTAMP %q was accepted", value)
		}
	}
}
