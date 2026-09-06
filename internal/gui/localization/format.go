package localization

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// FormatTime renders a user-facing local timestamp using the active locale.
func FormatTime(catalog Catalog, value time.Time) string {
	if value.IsZero() {
		return Normalize(catalog).Text(CommonUnavailable)
	}
	value = value.Local()
	if LanguageOf(catalog) == LanguageRussian {
		return value.Format("02.01.2006 15:04:05 MST")
	}
	return value.Format("Jan 2, 2006 3:04:05 PM MST")
}

// FormatDuration renders diagnostic durations with locale-specific decimal
// separators and units while preserving sub-millisecond evidence.
func FormatDuration(catalog Catalog, value time.Duration) string {
	if value <= 0 {
		return Normalize(catalog).Text(CommonUnavailable)
	}
	var number, unit string
	switch {
	case value < time.Millisecond:
		number, unit = trimFloat(float64(value)/float64(time.Microsecond), 3), "µs"
	case value < time.Second:
		number, unit = trimFloat(float64(value)/float64(time.Millisecond), 3), "ms"
	case value < time.Minute:
		number, unit = trimFloat(float64(value)/float64(time.Second), 3), "s"
	default:
		number, unit = trimFloat(float64(value)/float64(time.Minute), 2), "min"
	}
	if LanguageOf(catalog) == LanguageRussian {
		number = strings.ReplaceAll(number, ".", ",")
		switch unit {
		case "ms":
			unit = "мс"
		case "s":
			unit = "с"
		case "min":
			unit = "мин"
		}
	}
	return number + " " + unit
}

// FormatNumber renders an integer with locale grouping.
func FormatNumber(catalog Catalog, value int64) string {
	raw := strconv.FormatInt(value, 10)
	separator := ","
	if LanguageOf(catalog) == LanguageRussian {
		separator = " "
	}
	start := 0
	if strings.HasPrefix(raw, "-") {
		start = 1
	}
	for index := len(raw) - 3; index > start; index -= 3 {
		raw = raw[:index] + separator + raw[index:]
	}
	return raw
}

func trimFloat(value float64, precision int) string {
	return strings.TrimRight(strings.TrimRight(fmt.Sprintf("%.*f", precision, value), "0"), ".")
}
