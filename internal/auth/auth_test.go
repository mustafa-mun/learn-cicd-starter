package auth

import (
	"errors"
	"net/http"
	"reflect"
	"testing"
)

func TestNoHeader(t *testing.T) {
	var headers http.Header = make(map[string][]string)
	headers.Set("ApiKey", "")
	_, err := GetAPIKey(headers)
	if err != ErrNoAuthHeaderIncluded {
		t.Errorf("Result was incorrect, got: %s, want: %s.", err, ErrNoAuthHeaderIncluded)
	}
}

func TestMalformedHeader(t *testing.T) {
	expectedErr := errors.New("malformed authorization header")
	var headersOne http.Header = make(map[string][]string)
	headersOne.Set("Authorization", "key")
	var headersTwo http.Header = make(map[string][]string)
	headersTwo.Set("Authorization", "Bearer key")

	tests := []struct {
		name  string
		input http.Header
		want  error
	}{
		{name: "short array length", input: headersOne, want: expectedErr},
		{name: "wrong key", input: headersTwo, want: expectedErr},
	}

	for _, tc := range tests {
		_, err := GetAPIKey(tc.input)
		if !reflect.DeepEqual(tc.want, err) {
			t.Fatalf("%s: expected: %v, got: %v", tc.name, tc.want, err)
		}
	}
}

func TestAPIKey(t *testing.T) {
	expectedApiKey := "eyJhbGciOiJIUzI1NiIsInR5cCI6I" // Non-valid api key
	var headers http.Header = make(map[string][]string)
	headers.Set("Authorization", "ApiKey "+expectedApiKey)
	result, err := GetAPIKey(headers)
	if result != expectedApiKey {
		t.Errorf("Result was incorrect, got: %s, want: %s. err: %s", result, expectedApiKey, err)
	}
}
