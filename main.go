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
	_ "go.uber.org/automaxprocs"
	"google.golang.org/grpc"
	v1 "k8s.io/api/core/v1"
	_ "k8s.io/client-go/plugin/pkg/client/auth"
	"k8s.io/client-go/rest"
	controllercache "sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
	"sigs.k8s.io/controller-runtime/pkg/webhook"

	cerberusv1alpha1 "github.com/snapp-incubator/Cerberus/api/v1alpha1"
	"github.com/snapp-incubator/Cerberus/controllers"
	"github.com/snapp-incubator/Cerberus/internal/settings"
	"github.com/snapp-incubator/Cerberus/internal/tracing"
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
	// load settings from env and bind flags for overwrites
	st, err := settings.GetSettings()
	if err != nil {
		reportFatalErrorAndExit(err, "failed-to-load-settings")
		return
	}
	st.BindFlags(flag.CommandLine)

	// bind zap flags
	opts := zap.Options{
		Development: true,
	}
	opts.BindFlags(flag.CommandLine)
	flag.Parse()

	// add zapper to controller
	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))

	if st.Tracing.Enabled {
		switch st.Tracing.Provider {
		case "http":
			err = tracing.SetTracingProvider(tracing.HTTPTracingProvider, st.Tracing.SamplingRatio, st.Tracing.Timeout)
		case "grpc":
			err = tracing.SetTracingProvider(tracing.GRPCTracingProvider, st.Tracing.SamplingRatio, st.Tracing.Timeout)
		default:
			err = fmt.Errorf("invalid-tracing-provider")
		}
	}
	if err != nil {
		reportFatalErrorAndExit(err, "setup tracing provider encountered error")
		return
	}

	listener, srv, authenticator, err := setupAuthenticationServer(st)
	if err != nil {
		reportFatalErrorAndExit(err, "unable to setup authentication server")
		return
	}

	mgr, err := setupManager(st, authenticator)
	if err != nil {
		reportFatalErrorAndExit(err, "unable to setup manager")
	}

	//+kubebuilder:scaffold:builder

	err = setupHealthChecks(mgr)
	if err != nil {
		reportFatalErrorAndExit(err, "unable to set up health/ready check")
	}

	errChan := make(chan error)
	ctx := ctrl.SetupSignalHandler()

	go runAuthenticationServer(ctx, listener, srv, errChan)
	go runManager(ctx, mgr, errChan)

	select {
	case err := <-errChan:
		finalizers()
		reportFatalErrorAndExit(err, "cerberus error")
	case <-ctx.Done():
		finalizers()
		os.Exit(0)
	}
}

func setupManager(
	st settings.Settings,
	cache controllers.ProcessCache,
) (ctrl.Manager, error) {
	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme: scheme,
		WebhookServer: webhook.NewServer(webhook.Options{
			Port: 9443,
		}),
		Metrics: metricsserver.Options{
			BindAddress: st.MetricsAddress,
		},
		HealthProbeBindAddress: st.ProbeAddress,
		LeaderElection:         st.LeaderElection.Enabled,
		LeaderElectionID:       st.LeaderElection.ID,

		// limit Manager to cerberus namespace
		NewCache: func(config *rest.Config, opts controllercache.Options) (controllercache.Cache, error) {
			operatorNamespace := os.Getenv("OPERATOR_NAMESPACE")
			if operatorNamespace == "" {
				operatorNamespace = "cerberus-operator-system"
			}

			opts.ByObject = make(map[client.Object]controllercache.ByObject)
			opts.ByObject[&v1.Secret{}] = controllercache.ByObject{
				Namespaces: map[string]controllercache.Config{
					operatorNamespace: {},
				},
			}

			return controllercache.New(config, opts)
		},
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

	setupLog.Info(fmt.Sprintf("authenticator: %v", cache))

	if err = (&controllers.AccessTokenReconciler{
		Client:   mgr.GetClient(),
		Scheme:   mgr.GetScheme(),
		Cache:    cache,
		ReadOnly: !st.LeaderElection.Enabled,
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "AccessToken")
		return nil, err
	}
	if err = (&controllers.WebServiceReconciler{
		Client:   mgr.GetClient(),
		Scheme:   mgr.GetScheme(),
		Cache:    cache,
		ReadOnly: !st.LeaderElection.Enabled,
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "WebService")
		return nil, err
	}
	if err = (&controllers.WebserviceAccessBindingReconciler{
		Client:   mgr.GetClient(),
		Scheme:   mgr.GetScheme(),
		Cache:    cache,
		ReadOnly: !st.LeaderElection.Enabled,
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

func setupAuthenticationServer(st settings.Settings) (net.Listener, *grpc.Server, *auth.Authenticator, error) {
	listener, err := net.Listen("tcp", st.AuthServerAddress)
	if err != nil {
		setupLog.Error(err, "problem in binding authorization service")
		return nil, nil, nil, err
	}

	grpcOpts := []grpc.ServerOption{
		grpc.MaxConcurrentStreams(1 << 20),
	}

	if st.TLS.CertPath != "" && st.TLS.KeyPath != "" {
		creds, err := auth.NewServerCredentials(st.TLS.CertPath, st.TLS.KeyPath, st.TLS.CaPath)
		if err != nil {
			return nil, nil, nil, err
		}

		grpcOpts = append(grpcOpts, grpc.Creds(creds))
	}

	srv := grpc.NewServer(grpcOpts...)

	authenticator := auth.NewAuthenticator(
		setupLog.WithName("cerberus.authenticator"),
	)

	auth.RegisterServer(srv, authenticator)
	return listener, srv, authenticator, nil
}

func runAuthenticationServer(ctx context.Context, listener net.Listener, srv *grpc.Server, errChan chan error) {
	setupLog.Info("starting authorization server")

	if err := auth.RunServer(ctx, listener, srv); err != nil {
		errChan <- fmt.Errorf("authorization server failed: %w", err)
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

func reportFatalErrorAndExit(err error, msg string) {
	setupLog.Error(err, msg)
	os.Exit(1)
}

func finalizers() {
	err := tracing.Shutdown(context.Background())
	if err != nil {
		setupLog.Error(err, "failed to shutdown tracing properly")
	} else {
		setupLog.Info("tracer shutdown properly")
	}
}
