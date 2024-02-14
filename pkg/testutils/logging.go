package testutils

import (
	"github.com/go-logr/logr"
)

type Log struct {
	Message   string
	Type      string
	KeyValues map[interface{}]interface{}
}

// TestLogSink is a simple implementation of the LogSink interface for testing purposes.
type TestLogSink struct {
	Logs []Log
}

// keysAndValuesToMap converts key-value pairs to a map.
func keysAndValuesToMap(keysAndValues []interface{}) map[interface{}]interface{} {
	// Initialize an empty map
	result := make(map[interface{}]interface{})
	// Ensure that there are an even number of arguments
	if len(keysAndValues)%2 != 0 {
		// If the number of arguments is odd, return an empty map
		return result
	}

	// Iterate over the key-value pairs
	for i := 0; i < len(keysAndValues); i += 2 {
		// Assign the key-value pairs to the map
		key := keysAndValues[i]
		value := keysAndValues[i+1]
		result[key] = value
	}

	return result
}

// Init initializes the TestLogSink.
func (t *TestLogSink) Init(info logr.RuntimeInfo) {
	// For simplicity, we don't use any information about the logr library here.
}

// Enabled always returns true, assuming all logs should be captured in tests.
func (t *TestLogSink) Enabled(level int) bool {
	return true
}

// Info captures log messages.
func (t *TestLogSink) Info(level int, msg string, keysAndValues ...interface{}) {
	t.Logs = append(t.Logs, Log{Type: "info", Message: msg, KeyValues: keysAndValuesToMap(keysAndValues)})
}

// Error captures error messages.
func (t *TestLogSink) Error(err error, msg string, keysAndValues ...interface{}) {
	t.Logs = append(t.Logs, Log{Type: "error", Message: err.Error(), KeyValues: keysAndValuesToMap(keysAndValues)})
}

// WithValues is not used in this simple implementation.
func (t *TestLogSink) WithValues(keysAndValues ...interface{}) logr.LogSink {
	panic("Not implemented")
}

// WithName is not used in this simple implementation.
func (t *TestLogSink) WithName(name string) logr.LogSink {
	panic("Not implemented")
}
