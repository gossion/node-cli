package root

import (
	"context"
	"errors"
	"fmt"
	"reflect"

	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apiserver/pkg/authentication/authenticator"
	"k8s.io/apiserver/pkg/authentication/authenticatorfactory"
	"k8s.io/apiserver/pkg/authorization/authorizer"
	"k8s.io/apiserver/pkg/authorization/authorizerfactory"
	"k8s.io/apiserver/pkg/server/dynamiccertificates"
	clientset "k8s.io/client-go/kubernetes"
	authenticationclient "k8s.io/client-go/kubernetes/typed/authentication/v1"
	authorizationclient "k8s.io/client-go/kubernetes/typed/authorization/v1"

	"k8s.io/kubernetes/pkg/kubelet/server"

	"github.com/virtual-kubelet/node-cli/opts"
	"github.com/virtual-kubelet/virtual-kubelet/log"
	kubeletconfig "k8s.io/kubernetes/pkg/kubelet/apis/config"

	"github.com/virtual-kubelet/virtual-kubelet/node/api"

	"net/http"
)

// BuildAuth creates an authenticator, an authorizer, and a matching authorizer attributes getter compatible with the kubelet's needs
// It returns AuthInterface, a run method to start internal controllers (like cert reloading) and error.
func BuildAuth(nodeName types.NodeName, client clientset.Interface, config opts.Opts) (server.AuthInterface, func(<-chan struct{}), error) {
	// Get clients, if provided
	var (
		tokenClient authenticationclient.TokenReviewInterface
		sarClient   authorizationclient.SubjectAccessReviewInterface
	)
	if client != nil && !reflect.ValueOf(client).IsNil() {
		tokenClient = client.AuthenticationV1().TokenReviews()
		sarClient = client.AuthorizationV1().SubjectAccessReviews()
	}

	authenticator, runAuthenticatorCAReload, err := BuildAuthn(tokenClient, config.Authentication)
	if err != nil {
		return nil, nil, err
	}

	attributes := server.NewNodeAuthorizerAttributesGetter(nodeName)

	authorizer, err := BuildAuthz(sarClient, config.Authorization)
	if err != nil {
		return nil, nil, err
	}

	return NewKubeletAuth(authenticator, attributes, authorizer), runAuthenticatorCAReload, nil
}

// BuildAuthn creates an authenticator compatible with the kubelet's needs
func BuildAuthn(client authenticationclient.TokenReviewInterface, authn kubeletconfig.KubeletAuthentication) (authenticator.Request, func(<-chan struct{}), error) {
	var dynamicCAContentFromFile *dynamiccertificates.DynamicFileCAContent
	var err error
	if len(authn.X509.ClientCAFile) > 0 {
		dynamicCAContentFromFile, err = dynamiccertificates.NewDynamicCAContentFromFile("client-ca-bundle", authn.X509.ClientCAFile)
		if err != nil {
			return nil, nil, err
		}
	}

	authenticatorConfig := authenticatorfactory.DelegatingAuthenticatorConfig{
		Anonymous:                          authn.Anonymous.Enabled,
		CacheTTL:                           authn.Webhook.CacheTTL.Duration,
		ClientCertificateCAContentProvider: dynamicCAContentFromFile,
	}

	if authn.Webhook.Enabled {
		if client == nil {
			return nil, nil, errors.New("no client provided, cannot use webhook authentication")
		}
		authenticatorConfig.TokenAccessReviewClient = client
	}

	authenticator, _, err := authenticatorConfig.New()
	if err != nil {
		return nil, nil, err
	}

	return authenticator, func(stopCh <-chan struct{}) {
		if dynamicCAContentFromFile != nil {
			go dynamicCAContentFromFile.Run(1, stopCh)
		}
	}, err
}

// BuildAuthz creates an authorizer compatible with the kubelet's needs
func BuildAuthz(client authorizationclient.SubjectAccessReviewInterface, authz kubeletconfig.KubeletAuthorization) (authorizer.Authorizer, error) {
	switch authz.Mode {
	case kubeletconfig.KubeletAuthorizationModeAlwaysAllow:
		return authorizerfactory.NewAlwaysAllowAuthorizer(), nil

	case kubeletconfig.KubeletAuthorizationModeWebhook:
		if client == nil {
			return nil, errors.New("no client provided, cannot use webhook authorization")
		}
		authorizerConfig := authorizerfactory.DelegatingAuthorizerConfig{
			SubjectAccessReviewClient: client,
			AllowCacheTTL:             authz.Webhook.CacheAuthorizedTTL.Duration,
			DenyCacheTTL:              authz.Webhook.CacheUnauthorizedTTL.Duration,
		}
		return authorizerConfig.New()

	case "":
		return nil, fmt.Errorf("no authorization mode specified")

	default:
		return nil, fmt.Errorf("unknown authorization mode %s", authz.Mode)

	}
}

type AuthInterface interface {
	authenticator.Request
	authorizer.RequestAttributesGetter
	authorizer.Authorizer
}

type KubeletAuth struct {
	// authenticator identifies the user for requests to the Kubelet API
	authenticator.Request
	// authorizerAttributeGetter builds authorization.Attributes for a request to the Kubelet API
	authorizer.RequestAttributesGetter
	// authorizer determines whether a given authorization.Attributes is allowed
	authorizer.Authorizer
}

// NewKubeletAuth returns a kubelet.AuthInterface composed of the given authenticator, attribute getter, and authorizer
func NewKubeletAuth(authenticator authenticator.Request, authorizerAttributeGetter authorizer.RequestAttributesGetter, authorizer authorizer.Authorizer) *KubeletAuth { //?interface?
	return &KubeletAuth{authenticator, authorizerAttributeGetter, authorizer}
}

type KubeletAuthMiddleware struct {
	auth AuthInterface
	ctx  context.Context
}

func NewKubeletKubeletAuthMiddleware(auth AuthInterface, ctx context.Context) api.AuthMiddleware {
	return KubeletAuthMiddleware{auth: auth, ctx: ctx}
}

func (m KubeletAuthMiddleware) ValidateRequet(req *http.Request) (string, int) {
	info, ok, err := m.auth.AuthenticateRequest(req)
	log.G(m.ctx).
		WithField("info", info).
		WithField("ok", ok).WithField("err", err).Infof("AuthenticateRequest %v", req)

	//log.SetOutput(os.Stdout) // logs go to Stderr by default
	//log.Println(r.Method, r.URL)
	if err != nil {
		//klog.Errorf("Unable to authenticate the request due to an error: %v", err)
		return "Unauthorized", http.StatusUnauthorized
	}
	if !ok {
		//resp.WriteErrorString(http.StatusUnauthorized, "Unauthorized")
		return "Unauthorized", http.StatusUnauthorized
	}

	// Get authorization attributes
	attrs := m.auth.GetRequestAttributes(info.User, req)
	log.G(m.ctx).WithField("attrs", attrs).Info("GetReqeuestAttributes")

	// Authorize
	decision, reason, err := m.auth.Authorize(req.Context(), attrs)
	log.G(m.ctx).WithField("decision", decision).WithField("reason", reason).WithField("err", err).Info("Authorize")
	if err != nil {
		msg := fmt.Sprintf("Authorization error (user=%s, verb=%s, resource=%s, subresource=%s)", attrs.GetUser().GetName(), attrs.GetVerb(), attrs.GetResource(), attrs.GetSubresource())
		//klog.Errorf(msg, err)
		//resp.WriteErrorString(http.StatusInternalServerError, msg)
		return msg, http.StatusInternalServerError
	}
	if decision != authorizer.DecisionAllow {
		msg := fmt.Sprintf("Forbidden (user=%s, verb=%s, resource=%s, subresource=%s)", attrs.GetUser().GetName(), attrs.GetVerb(), attrs.GetResource(), attrs.GetSubresource())
		//klog.V(2).Info(msg)
		//resp.WriteErrorString(http.StatusForbidden, msg)
		return msg, http.StatusForbidden
	}

	return "", http.StatusOK
}

func (m KubeletAuthMiddleware) AuthFilter(h http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(func(resp http.ResponseWriter, req *http.Request) {

		log.G(m.ctx).Info("0")
		info, ok, err := m.auth.AuthenticateRequest(req)
		log.G(m.ctx).
			WithField("info", info).
			WithField("ok", ok).WithField("err", err).Infof("AuthenticateRequest %v", req)

		log.G(m.ctx).Info("1")
		log.G(m.ctx).Info("2")

		//log.SetOutput(os.Stdout) // logs go to Stderr by default
		//log.Println(r.Method, r.URL)
		if err != nil {
			log.G(m.ctx).Info("3")
			//klog.Errorf("Unable to authenticate the request due to an error: %v", err)
			resp.WriteHeader(http.StatusUnauthorized)
			resp.Write([]byte("Unauthorized"))

			return
		}
		if !ok {
			log.G(m.ctx).Info("4")
			//resp.WriteErrorString(http.StatusUnauthorized, "Unauthorized")
			resp.WriteHeader(http.StatusUnauthorized)
			resp.Write([]byte("Unauthorized"))

			return
		}
		log.G(m.ctx).Info("5")

		// Get authorization attributes
		attrs := m.auth.GetRequestAttributes(info.User, req)
		log.G(m.ctx).Info("6")
		log.G(m.ctx).WithField("attrs", attrs).Info("GetReqeuestAttributes")

		// Authorize
		decision, reason, err := m.auth.Authorize(req.Context(), attrs)
		log.G(m.ctx).WithField("decision", decision).WithField("reason", reason).WithField("err", err).Info("Authorize")
		if err != nil {
			log.G(m.ctx).Info("7")
			msg := fmt.Sprintf("Authorization error (user=%s, verb=%s, resource=%s, subresource=%s)", attrs.GetUser().GetName(), attrs.GetVerb(), attrs.GetResource(), attrs.GetSubresource())
			//klog.Errorf(msg, err)
			//resp.WriteErrorString(http.StatusInternalServerError, msg)
			resp.WriteHeader(http.StatusInternalServerError)
			resp.Write([]byte(msg))
			return
		}
		log.G(m.ctx).Info("8")
		if decision != authorizer.DecisionAllow {
			log.G(m.ctx).Info("9")
			msg := fmt.Sprintf("Forbidden (user=%s, verb=%s, resource=%s, subresource=%s)", attrs.GetUser().GetName(), attrs.GetVerb(), attrs.GetResource(), attrs.GetSubresource())
			//klog.V(2).Info(msg)
			//resp.WriteErrorString(http.StatusForbidden, msg)
			resp.WriteHeader(http.StatusForbidden)
			resp.Write([]byte(msg))
			return
		}

		log.G(m.ctx).Info("10")
		h(resp, req)
	})
}

// // InstallAuthFilter installs authentication filters with the restful Container.
// func (s *Server) InstallAuthFilter() {
// 	s.restfulCont.Filter(func(req *restful.Request, resp *restful.Response, chain *restful.FilterChain) {
// 		// Authenticate
// 		info, ok, err := s.auth.AuthenticateRequest(req.Request)
// 		if err != nil {
// 			klog.Errorf("Unable to authenticate the request due to an error: %v", err)
// 			resp.WriteErrorString(http.StatusUnauthorized, "Unauthorized")
// 			return
// 		}
// 		if !ok {
// 			resp.WriteErrorString(http.StatusUnauthorized, "Unauthorized")
// 			return
// 		}

// 		// Get authorization attributes
// 		attrs := s.auth.GetRequestAttributes(info.User, req.Request)

// 		// Authorize
// 		decision, _, err := s.auth.Authorize(req.Request.Context(), attrs)
// 		if err != nil {
// 			msg := fmt.Sprintf("Authorization error (user=%s, verb=%s, resource=%s, subresource=%s)", attrs.GetUser().GetName(), attrs.GetVerb(), attrs.GetResource(), attrs.GetSubresource())
// 			klog.Errorf(msg, err)
// 			resp.WriteErrorString(http.StatusInternalServerError, msg)
// 			return
// 		}
// 		if decision != authorizer.DecisionAllow {
// 			msg := fmt.Sprintf("Forbidden (user=%s, verb=%s, resource=%s, subresource=%s)", attrs.GetUser().GetName(), attrs.GetVerb(), attrs.GetResource(), attrs.GetSubresource())
// 			klog.V(2).Info(msg)
// 			resp.WriteErrorString(http.StatusForbidden, msg)
// 			return
// 		}

// 		// Continue
// 		chain.ProcessFilter(req, resp)
// 	})
// }
