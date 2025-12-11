package parse

import (
	"testing"
)

func TestKeyValue(t *testing.T) {
	input := "v=STSv1"

	field, err := ParseKeyValue(input, "=")

	if err != nil {
		t.Errorf("Unexpected parsing error: %s\n", err.Error())
	}

	expectedKey := "v"

	if field.Key != expectedKey {
		t.Errorf("Got the wrong key - expected %q but got %q\n", expectedKey, field.Key)
	}

	expectedValue := "STSv1"

	if field.Value != expectedValue {
		t.Errorf("Got the wrong value - expected %q but got %q\n", expectedValue, field.Value)
	}
}

func TestKeyValueTrim(t *testing.T) {
	input := " v= STSv1 "

	field, err := ParseKeyValue(input, "=")

	if err != nil {
		t.Errorf("Unexpected parsing error: %s\n", err.Error())
	}

	expectedKey := "v"

	if field.Key != expectedKey {
		t.Errorf("Got the wrong key - expected %q but got %q\n", expectedKey, field.Key)
	}

	expectedValue := "STSv1"

	if field.Value != expectedValue {
		t.Errorf("Got the wrong value - expected %q but got %q\n", expectedValue, field.Value)
	}
}

func TestFieldSplitting(t *testing.T) {
	input := "key1=value1;key2=value2;key3=value3"

	values, err := SplitIntoKVFields(input, ";", "=")

	if err != nil {
		t.Errorf("Unexpected parsing error: %s\n", err.Error())
	}

	if len(values) != 3 {
		t.Errorf("Got %d fields, expected 3\n", len(values))
	}

	if values[0].Key != "key1" {
		t.Errorf("Got the wrong key - expected \"key1\" but got %q\n", values[0].Key)
	}

	if values[0].Value != "value1" {
		t.Errorf("Got the wrong key - expected \"value1\" but got %q\n", values[0].Value)
	}

	if values[1].Key != "key2" {
		t.Errorf("Got the wrong key - expected \"key2\" but got %q\n", values[1].Key)
	}

	if values[1].Value != "value2" {
		t.Errorf("Got the wrong key - expected \"value2\" but got %q\n", values[1].Value)
	}

	if values[2].Key != "key3" {
		t.Errorf("Got the wrong key - expected \"key3\" but got %q\n", values[2].Key)
	}

	if values[2].Value != "value3" {
		t.Errorf("Got the wrong key - expected \"value3\" but got %q\n", values[2].Value)
	}
}

func TestFieldSplittingTrimming(t *testing.T) {
	input := " key1 =value1;key2= value2;key3 = value3 "

	values, err := SplitIntoKVFields(input, ";", "=")

	if err != nil {
		t.Errorf("Unexpected parsing error: %s\n", err.Error())
	}

	if len(values) != 3 {
		t.Errorf("Got %d fields, expected 3\n", len(values))
	}

	if values[0].Key != "key1" {
		t.Errorf("Got the wrong key - expected \"key1\" but got %q\n", values[0].Key)
	}

	if values[1].Key != "key2" {
		t.Errorf("Got the wrong key - expected \"key2\" but got %q\n", values[1].Key)
	}

	if values[1].Value != "value2" {
		t.Errorf("Got the wrong key - expected \"value2\" but got %q\n", values[1].Value)
	}

	if values[2].Key != "key3" {
		t.Errorf("Got the wrong key - expected \"key3\" but got %q\n", values[2].Key)
	}

	if values[2].Value != "value3" {
		t.Errorf("Got the wrong key - expected \"value3\" but got %q\n", values[2].Value)
	}
}

func TestLineSplitting(t *testing.T) {
	input := `version: STSv1
mode: testing
mx: mts-com.mail.protection.outlook.com
max_age: 604800`

	values, err := SplitIntoKVFields(input, "\n", ":")

	if err != nil {
		t.Errorf("Unexpected parsing error: %s\n", err.Error())
	}

	if len(values) != 4 {
		t.Errorf("Got %d fields, expected 4\n", len(values))
	}
}

func TestSpaceSplitting(t *testing.T) {
	input := "v=spf1 include:spf.protection.outlook.com ~all"

	values := ParseIntoFields(input, " ")

	if len(values) != 3 {
		t.Errorf("Got %d fields, expected 4\n", len(values))
	}

	if values[0] != "v=spf1" {
		t.Errorf("Got the wrong field - expected \"v=spf1\" but got %q\n", values[0])
	}

	if values[1] != "include:spf.protection.outlook.com" {
		t.Errorf("Got the wrong field - expected \"include:spf.protection.outlook.com\" but got %q\n", values[1])
	}

	if values[2] != "~all" {
		t.Errorf("Got the wrong field - expected \"~all\" but got %q\n", values[3])
	}
}
