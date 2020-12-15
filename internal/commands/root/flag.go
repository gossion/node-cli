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
	"flag"
	"os"

	"github.com/spf13/pflag"
	"github.com/virtual-kubelet/node-cli/opts"
	"k8s.io/klog"
)

func installFlags(flags *pflag.FlagSet, c *opts.Opts) {
	flags.StringVar(&c.KubeConfigPath, "kubeconfig", c.KubeConfigPath, "kube config file to use for connecting to the Kubernetes API server")
	flags.StringVar(&c.KubeNamespace, "namespace", c.KubeNamespace, "kubernetes namespace (default is 'all')")
	flags.StringVar(&c.KubeClusterDomain, "cluster-domain", c.KubeClusterDomain, "kubernetes cluster-domain (default is 'cluster.local')")
	flags.StringVar(&c.NodeName, "nodename", c.NodeName, "kubernetes node name")
	flags.StringVar(&c.OperatingSystem, "os", c.OperatingSystem, "Operating System (Linux/Windows)")
	flags.StringVar(&c.Provider, "provider", c.Provider, "cloud provider")
	flags.StringVar(&c.ProviderConfigPath, "provider-config", c.ProviderConfigPath, "cloud provider configuration file")
	flags.StringVar(&c.MetricsAddr, "metrics-addr", c.MetricsAddr, "address to listen for metrics/stats requests")

	flags.StringVar(&c.TaintKey, "taint", c.TaintKey, "Set node taint key")
	flags.BoolVar(&c.DisableTaint, "disable-taint", c.DisableTaint, "disable the virtual-kubelet node taint")
	flags.MarkDeprecated("taint", "Taint key should now be configured using the VK_TAINT_KEY environment variable")

	flags.IntVar(&c.PodSyncWorkers, "pod-sync-workers", c.PodSyncWorkers, `set the number of pod synchronization workers`)
	flags.BoolVar(&c.EnableNodeLease, "enable-node-lease", c.EnableNodeLease, `use node leases (1.13) for node heartbeats`)

	flags.DurationVar(&c.InformerResyncPeriod, "full-resync-period", c.InformerResyncPeriod, "how often to perform a full resync of pods between kubernetes and the provider")
	flags.DurationVar(&c.StartupTimeout, "startup-timeout", c.StartupTimeout, "How long to wait for the virtual-kubelet to start")

	flags.Int32Var(&c.KubeAPIQPS, "kube-api-qps", c.KubeAPIQPS,
		"kubeAPIQPS is the QPS to use while talking with kubernetes apiserver")
	flags.Int32Var(&c.KubeAPIBurst, "kube-api-burst", c.KubeAPIBurst,
		"kubeAPIBurst is the burst to allow while talking with kubernetes apiserver")

	flags.StringVar(&c.ClientCACert, "client-verify-ca", os.Getenv("APISERVER_CA_CERT_LOCATION"), "CA cert to use to verify client requests")
	flags.BoolVar(&c.AllowUnauthenticatedClients, "no-verify-clients", false, "Do not require client certificate validation")

	//TODO: default value??
	///usr/local/bin/kubelet
	// --enable-server
	// --node-labels=kubernetes.azure.com/role=agent,agentpool=nodepool1,storageprofile=managed,storagetier=Premium_LRS,kubernetes.azure.com/cluster=MC_xiazhan-manifest_api11_westus2,
	//kubernetes.azure.com/mode=system,
	//kubernetes.azure.com/node-image-version=AKSUbuntu-1804-2020.11.11
	//--v=2
	//--volume-plugin-dir=/etc/kubernetes/volumeplugins
	//--address=0.0.0.0
	//--anonymous-auth=false
	//--authentication-token-webhook=true
	//--authorization-mode=Webhook
	//--azure-container-registry-config=/etc/kubernetes/azure.json
	//--cgroups-per-qos=true
	//--client-ca-file=/etc/kubernetes/certs/ca.crt
	//--cloud-config=/etc/kubernetes/azure.json
	//--cloud-provider=azure
	//--cluster-dns=10.0.0.10
	//--cluster-domain=cluster.local
	//--dynamic-config-dir=/var/lib/kubelet
	//--enforce-node-allocatable=pods
	//--event-qps=0
	//--eviction-hard=memory.available<750Mi,nodefs.available<10%,nodefs.inodesFree<5%
	//--feature-gates=RotateKubeletServerCertificate=true
	//--image-gc-high-threshold=85 --image-gc-low-threshold=80
	//--image-pull-progress-deadline=30m
	//--keep-terminated-pod-volumes=false
	//--kube-reserved=cpu=100m,memory=1638Mi
	//--kubeconfig=/var/lib/kubelet/kubeconfig
	//--max-pods=110 --network-plugin=kubenet
	//--node-status-update-frequency=10s
	//--non-masquerade-cidr=10.244.0.0/16
	//--pod-infra-container-image=mcr.microsoft.com/oss/kubernetes/pause:1.3.1
	//--pod-manifest-path=/etc/kubernetes/manifests
	//--pod-max-pids=-1 --protect-kernel-defaults=true
	//--read-only-port=0 --resolv-conf=/run/systemd/resolve/resolv.conf
	//--rotate-certificates=false --streaming-connection-idle-timeout=4h
	//--tls-cert-file=/etc/kubernetes/certs/kubeletserver.crt
	//--tls-cipher-suites=TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,TLS_RSA_WITH_AES_256_GCM_SHA384,TLS_RSA_WITH_AES_128_GCM_SHA256
	//--tls-private-key-file=/etc/kubernetes/certs/kubeletserver.key

	//virtual-kubelet
	// - args:
	// - --provider
	// - azure
	// - --nodename
	// - virtual-node-aci-linux
	// - --os
	// - Linux
	// command:
	// - virtual-kubelet
	// env:
	// - name: KUBELET_PORT
	//   value: "10250"
	// - name: ACS_CREDENTIAL_LOCATION
	//   value: /etc/acs/azure.json
	// - name: AZURE_CLIENT_SECRET
	//   valueFrom:
	// 	secretKeyRef:
	// 	  key: clientSecret
	// 	  name: aci-connector-linux
	// - name: APISERVER_CERT_LOCATION
	//   value: /etc/virtual-kubelet/cert.pem
	// - name: APISERVER_KEY_LOCATION
	//   value: /etc/virtual-kubelet/key.pem
	// - name: VKUBELET_POD_IP
	//   valueFrom:
	// 	fieldRef:
	// 	  apiVersion: v1
	// 	  fieldPath: status.podIP
	// - name: ACI_EXTRA_USER_AGENT
	//   value: add-on/aks
	// - name: ACI_SUBNET_NAME
	//   value: aci
	// - name: MASTER_URI
	//   value: https://guweaci-e3223ab4.hcp.guweebld37637780.e2e.azmk8s.io
	// - name: CLUSTER_CIDR
	//   value: 10.1.0.0/24
	// - name: KUBE_DNS_IP
	//   value: 10.0.0.10
	// - name: VIRTUALNODE_USER_IDENTITY_CLIENTID

	// Authentication
	flags.BoolVar(&c.Authentication.Anonymous.Enabled, "anonymous-auth", c.Authentication.Anonymous.Enabled, ""+
		"Enables anonymous requests to the Kubelet server. Requests that are not rejected by another "+
		"authentication method are treated as anonymous requests. Anonymous requests have a username "+
		"of system:anonymous, and a group name of system:unauthenticated.")
	flags.BoolVar(&c.Authentication.Webhook.Enabled, "authentication-token-webhook", c.Authentication.Webhook.Enabled, ""+
		"Use the TokenReview API to determine authentication for bearer tokens.")
	flags.DurationVar(&c.Authentication.Webhook.CacheTTL.Duration, "authentication-token-webhook-cache-ttl", c.Authentication.Webhook.CacheTTL.Duration, ""+
		"The duration to cache responses from the webhook token authenticator.")
	flags.StringVar(&c.Authentication.X509.ClientCAFile, "client-ca-file", c.Authentication.X509.ClientCAFile, ""+
		"If set, any request presenting a client certificate signed by one of the authorities in the client-ca-file "+
		"is authenticated with an identity corresponding to the CommonName of the client certificate.")

	// Authorization
	flags.StringVar((*string)(&c.Authorization.Mode), "authorization-mode", string(c.Authorization.Mode), ""+
		"Authorization mode for Kubelet server. Valid options are AlwaysAllow or Webhook. "+
		"Webhook mode uses the SubjectAccessReview API to determine authorization.")
	flags.DurationVar(&c.Authorization.Webhook.CacheAuthorizedTTL.Duration, "authorization-webhook-cache-authorized-ttl", c.Authorization.Webhook.CacheAuthorizedTTL.Duration, ""+
		"The duration to cache 'authorized' responses from the webhook authorizer.")
	flags.DurationVar(&c.Authorization.Webhook.CacheUnauthorizedTTL.Duration, "authorization-webhook-cache-unauthorized-ttl", c.Authorization.Webhook.CacheUnauthorizedTTL.Duration, ""+
		"The duration to cache 'unauthorized' responses from the webhook authorizer.")

	flagset := flag.NewFlagSet("klog", flag.PanicOnError)
	klog.InitFlags(flagset)
	flagset.VisitAll(func(f *flag.Flag) {
		f.Name = "klog." + f.Name
		flags.AddGoFlag(f)
	})
}

func getEnv(key, defaultValue string) string {
	value, found := os.LookupEnv(key)
	if found {
		return value
	}
	return defaultValue
}
