package database

import (
	"strings"
	"time"
)

var (
	dateCellMinimum      = time.Date(1000, time.January, 1, 0, 0, 0, 0, time.UTC)
	dateCellMaximum      = time.Date(9999, time.December, 31, 0, 0, 0, 0, time.UTC)
	dateTimeCellMinimum  = time.Date(1000, time.January, 1, 0, 0, 0, 0, time.UTC)
	dateTimeCellMaximum  = time.Date(9999, time.December, 31, 23, 59, 59, 499999000, time.UTC)
	timestampCellMinimum = time.Date(1970, time.January, 1, 0, 0, 1, 0, time.UTC)
	timestampCellMaximum = time.Date(2038, time.January, 19, 3, 14, 7, 499999000, time.UTC)
)

// ValidDateCell reports whether value is the exact textual representation and
// physical range promised for MySQL DATE result cells.
func ValidDateCell(value string) bool {
	parsed, err := time.Parse(time.DateOnly, value)
	return err == nil && parsed.Format(time.DateOnly) == value &&
		!parsed.Before(dateCellMinimum) && !parsed.After(dateCellMaximum)
}

// ValidDateTimeCell reports whether value is the exact textual representation
// and physical range promised for MySQL DATETIME result cells.
func ValidDateTimeCell(value string) bool {
	parsed, ok := parseDateTimeCell(value)
	return ok && !parsed.Before(dateTimeCellMinimum) && !parsed.After(dateTimeCellMaximum)
}

// ValidTimestampCell reports whether a UTC textual result value is inside the
// narrower MySQL TIMESTAMP range supported by the keyset contract.
func ValidTimestampCell(value string) bool {
	parsed, ok := parseDateTimeCell(value)
	return ok && !parsed.Before(timestampCellMinimum) && !parsed.After(timestampCellMaximum)
}

func parseDateTimeCell(value string) (time.Time, bool) {
	base := value
	nanoseconds := 0
	if dot := strings.IndexByte(value, '.'); dot >= 0 {
		fraction := value[dot+1:]
		if len(fraction) < 1 || len(fraction) > 6 || !decimalDigitsOnly(fraction) {
			return time.Time{}, false
		}
		base = value[:dot]
		parsedFraction, _ := parseDecimalDigits(fraction)
		for digits := len(fraction); digits < 9; digits++ {
			parsedFraction *= 10
		}
		nanoseconds = parsedFraction
	}
	parsed, err := time.Parse("2006-01-02 15:04:05", base)
	if err != nil || parsed.Format("2006-01-02 15:04:05") != base {
		return time.Time{}, false
	}
	return time.Date(
		parsed.Year(), parsed.Month(), parsed.Day(),
		parsed.Hour(), parsed.Minute(), parsed.Second(), nanoseconds, time.UTC,
	), true
}

// ValidTimeCell reports whether value is the closed textual TIME
// representation used by Quordon responses. It accepts the MySQL physical
// range with an optional minus sign, but never relies on permissive numeric
// parsers that also accept a leading plus sign.
func ValidTimeCell(value string) bool {
	text := value
	if strings.HasPrefix(text, "-") {
		text = text[1:]
	}
	if text == "" || text[0] == '+' || text[0] == '-' {
		return false
	}
	base := text
	if dot := strings.IndexByte(text, '.'); dot >= 0 {
		fraction := text[dot+1:]
		if len(fraction) < 1 || len(fraction) > 6 || !decimalDigitsOnly(fraction) {
			return false
		}
		base = text[:dot]
	}
	parts := strings.Split(base, ":")
	if len(parts) != 3 || len(parts[0]) < 2 || len(parts[0]) > 3 ||
		len(parts[1]) != 2 || len(parts[2]) != 2 {
		return false
	}
	hours, hoursOK := parseDecimalDigits(parts[0])
	minutes, minutesOK := parseDecimalDigits(parts[1])
	seconds, secondsOK := parseDecimalDigits(parts[2])
	if !hoursOK || !minutesOK || !secondsOK {
		return false
	}
	// MySQL emits two hour digits below 100 and three from 100 onward.
	if len(parts[0]) == 3 && parts[0][0] == '0' {
		return false
	}
	return hours <= 838 && minutes <= 59 && seconds <= 59
}

func decimalDigitsOnly(value string) bool {
	if value == "" {
		return false
	}
	for index := range len(value) {
		if value[index] < '0' || value[index] > '9' {
			return false
		}
	}
	return true
}

func parseDecimalDigits(value string) (int, bool) {
	if !decimalDigitsOnly(value) {
		return 0, false
	}
	result := 0
	for index := range len(value) {
		result = result*10 + int(value[index]-'0')
	}
	return result, true
}
