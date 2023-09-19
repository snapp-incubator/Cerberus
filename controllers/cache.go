package controllers

import (
	"context"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

type ProcessCache interface {
	UpdateCache(client.Client, context.Context, string, bool) error
}
