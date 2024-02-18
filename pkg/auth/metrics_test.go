package auth

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
)

func TestAddReasonLabel(t *testing.T) {
	// Test case 1: Adding reason label
	labels := AddReasonLabel(nil, "random-reason")
	assert.NotNil(t, labels, "Labels should not be nil")
	assert.Equal(t, "random-reason", labels[CerberusReasonLabel])

	// Test case 2: Existing labels
	existingLabels := prometheus.Labels{"existing": "label"}
	labels = AddReasonLabel(existingLabels, "random-reason")
	assert.NotNil(t, labels, "Labels should not be nil")
	assert.Equal(t, "random-reason", labels[CerberusReasonLabel])
	assert.Equal(t, "label", labels["existing"], "Existing label should remain unchanged")
}

func TestAddKindLabel(t *testing.T) {
	// Test case 1: Adding kind label
	labels := AddKindLabel(nil, "some_kind")
	assert.NotNil(t, labels, "Labels should not be nil")
	assert.Equal(t, "some_kind", labels[ObjectKindLabel], "Kind label should be added")

	existingLabels := prometheus.Labels{"existing": "label"}
	labels = AddKindLabel(existingLabels, "some_kind")
	assert.NotNil(t, labels, "Labels should not be nil")
	assert.Equal(t, "some_kind", labels[ObjectKindLabel])
	assert.Equal(t, "label", labels["existing"])

}
func TestAddStatusLabel(t *testing.T) {
	// Test case 1: Adding status label
	labels := AddStatusLabel(nil, 200)
	assert.NotNil(t, labels, "Labels should not be nil")
	assert.Equal(t, "200", labels[StatusCode], "Status label should be added")

	existingLabels := prometheus.Labels{"existing": "label"}
	labels = AddStatusLabel(existingLabels, 200)
	assert.NotNil(t, labels, "Labels should not be nil")
	assert.Equal(t, "200", labels[StatusCode], "Status label should be '200'")
	assert.Equal(t, "label", labels["existing"], "Existing label should remain unchanged")
}
func TestAddUpstreamAuthLabel(t *testing.T) {
	// Test case 1: With upstream auth
	labels := AddUpstreamAuthLabel(nil, "true")
	assert.NotNil(t, labels, "Labels should not be nil")
	assert.Equal(t, "true", labels[HasUpstreamAuth], "HasUpstreamAuth label should be true")

	// Test case 2: Without upstream auth
	labels = AddUpstreamAuthLabel(nil, "false")
	assert.NotNil(t, labels, "Labels should not be nil")
	assert.Equal(t, "false", labels[HasUpstreamAuth], "HasUpstreamAuth label should be false")

	// Test case 3: Existing labels
	existingLabels := prometheus.Labels{"existing": "label"}
	labels = AddUpstreamAuthLabel(existingLabels, "true")
	assert.NotNil(t, labels, "Labels should not be nil")
	assert.Equal(t, "true", labels[HasUpstreamAuth], "HasUpstreamAuth label should be true")
	assert.Equal(t, "label", labels["existing"], "Existing label should remain unchanged")
}
func TestAddWithDownstreamDeadline(t *testing.T) {
	// Test case 1: With downstream deadline
	labels := AddWithDownstreamDeadline(nil, true)
	assert.NotNil(t, labels, "Labels should not be nil")
	assert.Equal(t, "true", labels[WithDownstreamDeadlineLabel], "WithDownstreamDeadlineLabel should be true")

	// Test case 2: Without downstream deadline
	labels = AddWithDownstreamDeadline(nil, false)
	assert.NotNil(t, labels, "Labels should not be nil")
	assert.Equal(t, "false", labels[WithDownstreamDeadlineLabel], "WithDownstreamDeadlineLabel should be false")

	// Test case 3: Existing labels
	existingLabels := prometheus.Labels{"existing": "label"}
	labels = AddWithDownstreamDeadline(existingLabels, true)
	assert.NotNil(t, labels, "Labels should not be nil")
	assert.Equal(t, "true", labels[WithDownstreamDeadlineLabel], "WithDownstreamDeadlineLabel should be true")
	assert.Equal(t, "label", labels["existing"], "Existing label should remain unchanged")
}
