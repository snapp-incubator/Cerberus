package testutils

import (
	"github.com/go-logr/logr"
)

// Log is a structure of logr logs targets easy assertion in tests
type Log struct {
	Message   string
	Type      string
	Name      string
	KeyValues map[interface{}]interface{}
}

// Logs is array of logs to define references
type Logs []Log

// TestLogSink is a simple implementation of the LogSink interface for testing purposes.
type TestLogSink struct {
	Logs          *Logs
	currentValues []interface{}
	currentName   string
}

func (sink TestLogSink) GetLog(n int) Log {
	return (*sink.Logs)[n]
}

func NewTestLogSink() *TestLogSink {
	return &TestLogSink{
		Logs: &Logs{},
	}
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
	if len(t.currentValues) > 0 {
		keysAndValues = append(keysAndValues, t.currentValues...)
	}
	*t.Logs = append(*t.Logs, Log{Name: t.currentName, Type: "info", Message: msg, KeyValues: keysAndValuesToMap(keysAndValues)})
}

// Error captures error messages.
func (t *TestLogSink) Error(err error, msg string, keysAndValues ...interface{}) {
	if len(t.currentValues) > 0 {
		keysAndValues = append(keysAndValues, t.currentValues...)
	}
	*t.Logs = append(*t.Logs, Log{Name: t.currentName, Type: "error", Message: err.Error(), KeyValues: keysAndValuesToMap(keysAndValues)})
}

// WithValues is not used in this simple implementation.
func (t *TestLogSink) WithValues(keysAndValues ...interface{}) logr.LogSink {
	sink := &TestLogSink{Logs: t.Logs}
	sink.currentValues = append(t.currentValues, keysAndValues...)
	sink.currentName = t.currentName
	return sink
}

// WithName is not used in this simple implementation.
func (t *TestLogSink) WithName(name string) logr.LogSink {
	sink := &TestLogSink{Logs: t.Logs}
	sink.currentValues = t.currentValues
	sink.currentName = t.currentName
	return sink
}
