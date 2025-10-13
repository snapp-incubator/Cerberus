/*
Copyright 2023.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controllers

import (
	"context"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	cerberusv1alpha1 "github.com/snapp-incubator/Cerberus/api/v1alpha1"
)

// AccessTokenReconciler reconciles a AccessToken object
type AccessTokenReconciler struct {
	client.Client
	Scheme   *runtime.Scheme
	Cache    ProcessCache
	ReadOnly bool
}

//+kubebuilder:rbac:groups=cerberus.snappcloud.io,resources=accesstokens,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=cerberus.snappcloud.io,resources=accesstokens/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=cerberus.snappcloud.io,resources=accesstokens/finalizers,verbs=update

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
func (r *AccessTokenReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	_ = log.FromContext(ctx)

	err := r.Cache.UpdateCache(r.Client, ctx, r.ReadOnly)

	return ctrl.Result{}, err
}

// SetupWithManager sets up the controller with the Manager.
func (r *AccessTokenReconciler) SetupWithManager(mgr ctrl.Manager) error {

	labelPredicate := predicate.Funcs{
		UpdateFunc: func(e event.UpdateEvent) bool {
			_, hasLabel := e.ObjectNew.GetLabels()["cerberus.snappcloud.io/secret"]
			return hasLabel
		},
		CreateFunc: func(e event.CreateEvent) bool {
			_, hasLabel := e.Object.GetLabels()["cerberus.snappcloud.io/secret"]
			return hasLabel
		},
		DeleteFunc: func(e event.DeleteEvent) bool {
			_, hasLabel := e.Object.GetLabels()["cerberus.snappcloud.io/secret"]
			return hasLabel
		},
	}

	if err := ctrl.NewControllerManagedBy(mgr).
		For(&cerberusv1alpha1.AccessToken{}).
		Watches(&corev1.Secret{}, handler.EnqueueRequestsFromMapFunc(mapSecretMapFunc), builder.WithPredicates(labelPredicate)).
		Complete(r); err != nil {
		return err
	}

	return nil
}

func mapSecretMapFunc(ctx context.Context, a client.Object) []reconcile.Request {
	return []reconcile.Request{
		{NamespacedName: client.ObjectKey{Name: a.GetName(), Namespace: a.GetNamespace()}},
	}
}
