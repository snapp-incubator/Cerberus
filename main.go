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

package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"

	// Import all Kubernetes client auth plugins (e.g. Azure, GCP, OIDC, etc.)
	// to ensure that exec-entrypoint and run can make use of them.

	"google.golang.org/grpc"
	_ "k8s.io/client-go/plugin/pkg/client/auth"

	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"

	cerberusv1alpha1 "github.com/snapp-incubator/Cerberus/api/v1alpha1"
	"github.com/snapp-incubator/Cerberus/controllers"
	"github.com/snapp-incubator/Cerberus/pkg/auth"
	//+kubebuilder:scaffold:imports
)

var (
	scheme   = runtime.NewScheme()
	setupLog = ctrl.Log.WithName("setup")
)

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))

	utilruntime.Must(cerberusv1alpha1.AddToScheme(scheme))
	//+kubebuilder:scaffold:scheme
}

func main() {
	var metricsAddr string
	var enableLeaderElection bool
	var probeAddr string
	var authAddr string

	flag.StringVar(&metricsAddr, "metrics-bind-address", ":8080", "The address the metric endpoint binds to.")
	flag.StringVar(&probeAddr, "health-probe-bind-address", ":8081", "The address the probe endpoint binds to.")
	flag.StringVar(&authAddr, "address", ":8082", "The address the authorization service binds to.")

	flag.BoolVar(&enableLeaderElection, "leader-elect", false,
		"Enable leader election for controller manager. "+
			"Enabling this will ensure there is only one active controller manager.")
	opts := zap.Options{
		Development: true,
	}
	opts.BindFlags(flag.CommandLine)
	flag.Parse()
	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))

	mgr, err := setupManager(metricsAddr, probeAddr, enableLeaderElection)
	if err != nil {
		setupLog.Error(err, "unable to set up manager")
		os.Exit(1)
	}

	//+kubebuilder:scaffold:builder

	err = setupHealthChecks(mgr)
	if err != nil {
		setupLog.Error(err, "unable to set up health/ready check")
		os.Exit(1)
	}

	listener, srv, err := setupAuthenticationServer(authAddr, mgr)
	if err != nil {
		setupLog.Error(err, "unable to set up authentication server")
		os.Exit(1)
	}

	errChan := make(chan error)
	ctx := ctrl.SetupSignalHandler()

	go runAuthenticationServer(ctx, mgr, listener, srv, errChan)
	go runManager(ctx, mgr, errChan)

	select {
	case err := <-errChan:
		setupLog.Error(err, "cerberus error")
		os.Exit(1)
	case <-ctx.Done():
		os.Exit(0)
	}
}

func setupManager(metricsAddr string, probeAddr string, enableLeaderElection bool) (ctrl.Manager, error) {
	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:                 scheme,
		MetricsBindAddress:     metricsAddr,
		Port:                   9443,
		HealthProbeBindAddress: probeAddr,
		LeaderElection:         enableLeaderElection,
		LeaderElectionID:       "f5d1781e.snappcloud.io",
		// LeaderElectionReleaseOnCancel defines if the leader should step down voluntarily
		// when the Manager ends. This requires the binary to immediately end when the
		// Manager is stopped, otherwise, this setting is unsafe. Setting this significantly
		// speeds up voluntary leader transitions as the new leader don't have to wait
		// LeaseDuration time first.
		//
		// In the default scaffold provided, the program ends immediately after
		// the manager stops, so would be fine to enable this option. However,
		// if you are doing or is intended to do any operation such as perform cleanups
		// after the manager stops then its usage might be unsafe.
		// LeaderElectionReleaseOnCancel: true,
	})
	if err != nil {
		setupLog.Error(err, "unable to start manager")
		return nil, err
	}

	if err = (&controllers.AccessTokenReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "AccessToken")
		return nil, err
	}
	if err = (&controllers.WebServiceReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "WebService")
		return nil, err
	}
	if err = (&controllers.WebserviceAccessBindingReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "WebserviceAccessBinding")
		return nil, err
	}

	return mgr, nil
}

func setupHealthChecks(mgr ctrl.Manager) error {
	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up health check")
		return err
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up ready check")
		return err
	}
	return nil
}

func setupAuthenticationServer(listenAddress string, mgr ctrl.Manager) (net.Listener, *grpc.Server, error) {
	listener, err := net.Listen("tcp", listenAddress)
	if err != nil {
		setupLog.Error(err, "problem in binding authorization service")
		return nil, nil, err
	}

	grpcOpts := []grpc.ServerOption{
		grpc.MaxConcurrentStreams(1 << 20),
	}
	// TODO: add grpc creds to support TLS
	srv := grpc.NewServer(grpcOpts...)

	authenticator, err := auth.NewAuthenticator(
		mgr.GetClient(),
		setupLog.WithName("cerberus.authenticator"),
	)
	if err != nil {
		setupLog.Error(err, "unable to create and update authenticator")
		return nil, nil, err
	}
	auth.RegisterServer(srv, authenticator)
	return listener, srv, nil
}

func runAuthenticationServer(ctx context.Context, mgr ctrl.Manager, listener net.Listener, srv *grpc.Server, errChan chan error) {
	setupLog.Info("started controller")

	if err := mgr.Start(ctx); err != nil {
		errChan <- fmt.Errorf("error in manager server: %w", err)
	}

	errChan <- nil
}

func runManager(ctx context.Context, mgr ctrl.Manager, errChan chan error) {
	setupLog.Info("started controller")

	if err := mgr.Start(ctx); err != nil {
		errChan <- fmt.Errorf("error in manager server: %w", err)
	}

	errChan <- nil
}
