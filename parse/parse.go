package parse

import (
	"fmt"
	"log"
	"strings"
)

type KeyValue struct {
	Original  string
	Key       string
	Value     string
	Separator string
}

// ParseKeyValue parses a single key/value pair from the input string using the specified separator.
// It trims leading and trailing whitespace from both the key and value.
func ParseKeyValue(input, separator string) (KeyValue, error) {
	if len(separator) == 0 {
		return KeyValue{}, fmt.Errorf("empty separator")
	}

	if !strings.Contains(input, separator) {
		return KeyValue{}, fmt.Errorf("separator %q not found in input %q", separator, input)
	}

	if len(input) == 0 {
		return KeyValue{}, fmt.Errorf("empty input")
	}

	result := KeyValue{
		Original:  input,
		Separator: separator,
	}

	parts := strings.Split(input, separator)
	result.Key = strings.TrimSpace(parts[0])
	result.Value = strings.TrimSpace(parts[1])

	return result, nil
}

// SplitIntoKVFields splits the input string into key/value pairs based on the specified entrySeparator and fieldSeparator.
// It trims leading and trailing whitespace from each entry and logs any parsing errors encountered.
func SplitIntoKVFields(input, entrySeparator, fieldSeparator string) ([]KeyValue, error) {
	var results []KeyValue
	entries := strings.Split(input, entrySeparator)

	for i, entry := range entries {
		// trim leading or trailling spaces
		entry = strings.TrimSpace(entry)
		entry = strings.TrimRight(entry, entrySeparator)

		value, err := ParseKeyValue(entry, fieldSeparator)

		if err != nil {
			log.Printf("Failed to parse key/value from entry %d (%q): %s", i, entry, err.Error())
			continue
		}

		results = append(results, value)
	}

	return results, nil
}

// ParseIntoFields splits the input string into fields based on the specified entrySeparator.
// It trims leading and trailing whitespace from each field and ignores empty fields.
func ParseIntoFields(input string, entrySeparator string) []string {
	entries := strings.Split(input, entrySeparator)
	var results []string
	for _, entry := range entries {
		entry = strings.TrimSpace(entry)
		if entry != "" {
			results = append(results, entry)
		}
	}
	return results
}
