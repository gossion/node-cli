// Copyright © 2017 The virtual-kubelet authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package root

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/virtual-kubelet/node-cli/opts"
	"github.com/virtual-kubelet/node-cli/provider"
	"github.com/virtual-kubelet/virtual-kubelet/log"
	"github.com/virtual-kubelet/virtual-kubelet/node/api"
	v1 "k8s.io/api/core/v1"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"k8s.io/kubernetes/pkg/kubelet/server"
)

// AcceptedCiphers is the list of accepted TLS ciphers, with known weak ciphers elided
// Note this list should be a moving target.
var AcceptedCiphers = []uint16{
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
	tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
	tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,

	tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
}

func loadTLSConfig(ctx context.Context, certPath, keyPath, caPath string, allowUnauthenticatedClients bool) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	log.G(ctx).WithField("caPath", caPath).WithField("allowUnauthenticatedClients", allowUnauthenticatedClients).Info("loadTLSConfig")
	if err != nil {
		return nil, errors.Wrap(err, "error loading tls certs")
	}

	var (
		caPool     *x509.CertPool
		clientAuth = tls.RequireAndVerifyClientCert
	)

	if allowUnauthenticatedClients {
		clientAuth = tls.NoClientCert
	}

	if caPath != "" {
		caPool = x509.NewCertPool()
		pem, err := ioutil.ReadFile(caPath)
		if err != nil {
			return nil, err
		}
		if !caPool.AppendCertsFromPEM(pem) {
			return nil, errors.New("error appending ca cert to certificate pool")
		}
	}

	return &tls.Config{
		Certificates:             []tls.Certificate{cert},
		MinVersion:               tls.VersionTLS12,
		PreferServerCipherSuites: true,
		CipherSuites:             AcceptedCiphers,
		ClientCAs:                caPool,
		ClientAuth:               clientAuth,
	}, nil
}

func setupHTTPServer(ctx context.Context, p provider.Provider, cfg *apiServerConfig /*, client kubernetes.Interface*/) (_ func(), retErr error) { //TODO: still need cfg?
	var closers []io.Closer
	cancel := func() {
		for _, c := range closers {
			c.Close()
		}
	}
	defer func() {
		if retErr != nil {
			cancel()
		}
	}()

	if cfg.CertPath == "" || cfg.KeyPath == "" || (cfg.CACertPath == "" && !cfg.AllowUnauthenticatedClients) {
		log.G(ctx).
			WithField("certPath", cfg.CertPath).
			WithField("keyPath", cfg.KeyPath).
			WithField("caPath", cfg.CACertPath).
			Error("TLS certificates not provided, not setting up pod http server")
	} else {
		tlsCfg, err := loadTLSConfig(ctx, cfg.CertPath, cfg.KeyPath, cfg.CACertPath, cfg.AllowUnauthenticatedClients)
		if err != nil {
			return nil, err
		}
		l, err := tls.Listen("tcp", cfg.Addr, tlsCfg)
		if err != nil {
			return nil, errors.Wrapf(err, "error setting up listener for pod http server: tlsconfig: \n%+v", tlsCfg)
		}

		mux := http.NewServeMux()

		podRoutes := api.PodHandlerConfig{
			RunInContainer:        p.RunInContainer,
			GetContainerLogs:      p.GetContainerLogs,
			GetPods:               p.GetPods,
			StreamIdleTimeout:     cfg.StreamIdleTimeout,
			StreamCreationTimeout: cfg.StreamCreationTimeout,
			Auth:                  NewKubeletKubeletAuthMiddleware(cfg.Auth, ctx),
		}

		if mp, ok := p.(provider.PodMetricsProvider); ok {
			podRoutes.GetStatsSummary = mp.GetStatsSummary
		}

		if cfg.Auth != nil && cfg.EnableTokenAuth {
			m := NewKubeletKubeletAuthMiddleware(cfg.Auth, ctx)
			podRoutes.HandlerMiddleware = []api.Middleware{m.AuthFilter}
		}

		// func auth(f http.HandlerFunc) http.HandlerFunc {
		// 	return func(w http.ResponseWriter, r *http.Request) {
		// 		if r.Method != "GET" {
		// 			http.NotFound(w, r)
		// 			return
		// 		}
		// 		f(w, r)
		// 	}
		// }

		// authFunc := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 	if r.Method != "GET" {
		// 		http.NotFound(w, r)
		// 		return
		// 	}
		// 	f(w, r)
		// })

		// authFilter := http.HandlerFunc(func(f http.HandlerFunc) http.HandlerFunc {
		// 	return func(w http.ResponseWriter, r *http.Request) {
		// 		if r.Method != "GET" {
		// 			http.NotFound(w, r)
		// 			return
		// 		}
		// 		f(w, r)
		// 	}
		// })

		api.AttachPodRoutes(podRoutes, mux, true)

		s := &http.Server{
			Handler:   mux,
			TLSConfig: tlsCfg,
		}
		go serveHTTP(ctx, s, l, "pods")
		closers = append(closers, s)
	}

	if cfg.MetricsAddr != "" {
		l, err := net.Listen("tcp", cfg.MetricsAddr)
		if err != nil {
			return nil, errors.Wrap(err, "could not setup listener for pod metrics http server")
		}
		var summaryHandlerFunc api.PodStatsSummaryHandlerFunc
		if mp, ok := p.(provider.PodMetricsProvider); ok {
			summaryHandlerFunc = mp.GetStatsSummary
		}
		podMetricsRoutes := api.PodMetricsConfig{
			GetStatsSummary: summaryHandlerFunc,
		}

		mux := http.NewServeMux()
		api.AttachPodMetricsRoutes(podMetricsRoutes, mux)
		s := &http.Server{
			Handler: mux,
		}
		go serveHTTP(ctx, s, l, "pod metrics")
		closers = append(closers, s)
	}

	return cancel, nil
}

func serveHTTP(ctx context.Context, s *http.Server, l net.Listener, name string) {
	if err := s.Serve(l); err != nil {
		select {
		case <-ctx.Done():
		default:
			log.G(ctx).WithError(err).Errorf("Error setting up %s http server", name)
		}
	}
	l.Close()
}

type apiServerConfig struct {
	CACertPath                  string
	CertPath                    string
	KeyPath                     string
	Addr                        string
	MetricsAddr                 string
	StreamIdleTimeout           time.Duration
	StreamCreationTimeout       time.Duration
	AllowUnauthenticatedClients bool

	Auth            server.AuthInterface
	EnableTokenAuth bool
}

type authConfig struct {
	// authentication specifies how requests to the Kubelet's server are authenticated
	Authentication KubeletAuthentication
	// authorization specifies how requests to the Kubelet's server are authorized
	Authorization KubeletAuthorization
}

// KubeletAuthorizationMode denotes the authorization mode for the kubelet
type KubeletAuthorizationMode string

const (
	// KubeletAuthorizationModeAlwaysAllow authorizes all authenticated requests
	KubeletAuthorizationModeAlwaysAllow KubeletAuthorizationMode = "AlwaysAllow"
	// KubeletAuthorizationModeWebhook uses the SubjectAccessReview API to determine authorization
	KubeletAuthorizationModeWebhook KubeletAuthorizationMode = "Webhook"
)

// KubeletAuthorization holds the state related to the authorization in the kublet.
type KubeletAuthorization struct {
	// mode is the authorization mode to apply to requests to the kubelet server.
	// Valid values are AlwaysAllow and Webhook.
	// Webhook mode uses the SubjectAccessReview API to determine authorization.
	Mode KubeletAuthorizationMode

	// webhook contains settings related to Webhook authorization.
	Webhook KubeletWebhookAuthorization
}

// KubeletWebhookAuthorization holds the state related to the Webhook
// Authorization in the Kubelet.
type KubeletWebhookAuthorization struct {
	// cacheAuthorizedTTL is the duration to cache 'authorized' responses from the webhook authorizer.
	CacheAuthorizedTTL metav1.Duration
	// cacheUnauthorizedTTL is the duration to cache 'unauthorized' responses from the webhook authorizer.
	CacheUnauthorizedTTL metav1.Duration
}

// KubeletAuthentication holds the Kubetlet Authentication setttings.
type KubeletAuthentication struct {
	// x509 contains settings related to x509 client certificate authentication
	X509 KubeletX509Authentication
	// webhook contains settings related to webhook bearer token authentication
	Webhook KubeletWebhookAuthentication
	// anonymous contains settings related to anonymous authentication
	Anonymous KubeletAnonymousAuthentication
}

// KubeletX509Authentication contains settings related to x509 client certificate authentication
type KubeletX509Authentication struct {
	// clientCAFile is the path to a PEM-encoded certificate bundle. If set, any request presenting a client certificate
	// signed by one of the authorities in the bundle is authenticated with a username corresponding to the CommonName,
	// and groups corresponding to the Organization in the client certificate.
	ClientCAFile string
}

// KubeletWebhookAuthentication contains settings related to webhook authentication
type KubeletWebhookAuthentication struct {
	// enabled allows bearer token authentication backed by the tokenreviews.authentication.k8s.io API
	Enabled bool
	// cacheTTL enables caching of authentication results
	CacheTTL metav1.Duration
}

// KubeletAnonymousAuthentication enables anonymous requests to the kubetlet server.
type KubeletAnonymousAuthentication struct {
	// enabled allows anonymous requests to the kubelet server.
	// Requests that are not rejected by another authentication method are treated as anonymous requests.
	// Anonymous requests have a username of system:anonymous, and a group name of system:unauthenticated.
	Enabled bool
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// SerializedNodeConfigSource allows us to serialize NodeConfigSource
// This type is used internally by the Kubelet for tracking checkpointed dynamic configs.
// It exists in the kubeletconfig API group because it is classified as a versioned input to the Kubelet.
type SerializedNodeConfigSource struct {
	metav1.TypeMeta
	// Source is the source that we are serializing
	// +optional
	Source v1.NodeConfigSource
}

func getAPIConfig(c *opts.Opts) (*apiServerConfig, error) {
	config := apiServerConfig{
		CertPath: os.Getenv("APISERVER_CERT_LOCATION"),
		KeyPath:  os.Getenv("APISERVER_KEY_LOCATION"),
	}

	//For testing...
	EnableTokenAuth := os.Getenv("EnableTokenAuth")
	if strings.EqualFold(EnableTokenAuth, "true") {
		config.EnableTokenAuth = true
	}

	config.Addr = fmt.Sprintf(":%d", c.ListenPort)
	config.MetricsAddr = c.MetricsAddr
	config.StreamIdleTimeout = c.StreamIdleTimeout
	config.StreamCreationTimeout = c.StreamCreationTimeout
	config.AllowUnauthenticatedClients = c.AllowUnauthenticatedClients

	config.CACertPath = c.ClientCACert
	if c.ClientCACert == "" {
		config.CACertPath = os.Getenv("APISERVER_CA_CERT_LOCATION")
	}

	return &config, nil
}
