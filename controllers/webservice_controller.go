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

	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	cerberusv1alpha1 "github.com/snapp-incubator/Cerberus/api/v1alpha1"
)

// WebServiceReconciler reconciles a WebService object
type WebServiceReconciler struct {
	client.Client
	Scheme   *runtime.Scheme
	Cache    ProcessCache
	ReadOnly bool
}

//+kubebuilder:rbac:groups=cerberus.snappcloud.io,resources=webservices,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=cerberus.snappcloud.io,resources=webservices/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=cerberus.snappcloud.io,resources=webservices/finalizers,verbs=update

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
func (r *WebServiceReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	_ = log.FromContext(ctx)

	err := r.Cache.UpdateCache(r.Client, ctx, r.ReadOnly)

	return ctrl.Result{}, err
}

// SetupWithManager sets up the controller with the Manager.
func (r *WebServiceReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&cerberusv1alpha1.WebService{}).
		Complete(r)
}
