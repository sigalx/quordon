package queryspec

import (
	"strings"
	"time"
)

const ProtocolMaxTemporalFractionDigits = 9

// ParsePortableDate parses the finite, four-digit Gregorian date representation
// shared by every adapter. Physical source ranges remain adapter-owned.
func ParsePortableDate(value string) (time.Time, bool) {
	if len(value) != len("0001-01-01") {
		return time.Time{}, false
	}
	parsed, err := time.Parse(time.DateOnly, value)
	if err != nil || parsed.Year() < 1 || parsed.Year() > 9999 || parsed.Format(time.DateOnly) != value {
		return time.Time{}, false
	}
	return parsed, true
}

// ParsePortableDateTime parses a timezone-naive wall-clock value. The returned
// time uses UTC only as a location-free container; callers must not interpret
// that location as a timezone conversion.
func ParsePortableDateTime(value string) (time.Time, int, bool) {
	return parsePortableDateTime(value, ' ', false)
}

// ParsePortableTimestamp parses a finite UTC instant with an explicit Z suffix.
func ParsePortableTimestamp(value string) (time.Time, int, bool) {
	return parsePortableDateTime(value, 'T', true)
}

func parsePortableDateTime(value string, separator byte, utcSuffix bool) (time.Time, int, bool) {
	minimumLength := len("0001-01-01 00:00:00")
	maximumLength := minimumLength + 1 + ProtocolMaxTemporalFractionDigits
	text := value
	if utcSuffix {
		minimumLength++
		maximumLength++
		if len(text) == 0 || text[len(text)-1] != 'Z' {
			return time.Time{}, 0, false
		}
		text = text[:len(text)-1]
	}
	if len(value) < minimumLength || len(value) > maximumLength || len(text) < 19 || text[10] != separator {
		return time.Time{}, 0, false
	}
	base := text[:19]
	canonicalBase := base[:10] + " " + base[11:]
	parsed, err := time.Parse("2006-01-02 15:04:05", canonicalBase)
	if err != nil || parsed.Year() < 1 || parsed.Year() > 9999 || parsed.Format("2006-01-02 15:04:05") != canonicalBase {
		return time.Time{}, 0, false
	}
	fractionDigits := 0
	nanoseconds := 0
	if len(text) != 19 {
		if text[19] != '.' {
			return time.Time{}, 0, false
		}
		fraction := text[20:]
		if len(fraction) == 0 || len(fraction) > ProtocolMaxTemporalFractionDigits || !decimalDigitsOnly(fraction) {
			return time.Time{}, 0, false
		}
		fractionDigits = len(fraction)
		nanoseconds, _ = parseDecimalDigits(fraction)
		for digits := fractionDigits; digits < ProtocolMaxTemporalFractionDigits; digits++ {
			nanoseconds *= 10
		}
	}
	return time.Date(
		parsed.Year(), parsed.Month(), parsed.Day(),
		parsed.Hour(), parsed.Minute(), parsed.Second(), nanoseconds, time.UTC,
	), fractionDigits, true
}

// ValidPortableTime reports whether value uses the bounded exact textual TIME
// representation published by the API. The bound is part of the portable wire
// contract; adapters may support only a subset of physical source values.
func ValidPortableTime(value string) bool {
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
		if len(fraction) < 1 || len(fraction) > ProtocolMaxTemporalFractionDigits || !decimalDigitsOnly(fraction) {
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
