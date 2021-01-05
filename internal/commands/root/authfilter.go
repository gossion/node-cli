// Copyright © 2020 The virtual-kubelet authors
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
	"fmt"
	"net/http"

	"github.com/virtual-kubelet/virtual-kubelet/log"
	"k8s.io/apiserver/pkg/authorization/authorizer"
)

// AuthFilter contains all methods required by the auth filters
type AuthFilter interface {
	AuthHandler(h http.Handler) http.Handler
}

// VirtualKubeletAuthFilter is the struct to implement AuthFilter
type VirtualKubeletAuthFilter struct {
	auth AuthInterface
	ctx  context.Context
}

// NewVirtualKubeletAuthFilter initiate an instance for AuthFilter
func NewVirtualKubeletAuthFilter(ctx context.Context, auth AuthInterface) AuthFilter {
	return VirtualKubeletAuthFilter{auth: auth, ctx: ctx}
}

// AuthHandler is the hanlder to authenticate & authorize the request
func (m VirtualKubeletAuthFilter) AuthHandler(h http.Handler) http.Handler {
	return http.HandlerFunc(func(resp http.ResponseWriter, req *http.Request) {
		info, ok, err := m.auth.AuthenticateRequest(req)
		if err != nil {
			log.G(m.ctx).Infof("Unauthorized, err: %s", err)
			resp.WriteHeader(http.StatusUnauthorized)
			resp.Write([]byte("Unauthorized"))

			return
		}
		if !ok {
			log.G(m.ctx).Infof("Unauthorized, ok: %t", ok)
			resp.WriteHeader(http.StatusUnauthorized)
			resp.Write([]byte("Unauthorized"))

			return
		}

		attrs := m.auth.GetRequestAttributes(info.User, req)
		decision, _, err := m.auth.Authorize(req.Context(), attrs)
		if err != nil {
			msg := fmt.Sprintf("Authorization error (user=%s, verb=%s, resource=%s, subresource=%s, err=%s)", attrs.GetUser().GetName(), attrs.GetVerb(), attrs.GetResource(), attrs.GetSubresource(), err)
			log.G(m.ctx).Info(msg)
			resp.WriteHeader(http.StatusInternalServerError)
			resp.Write([]byte(msg))
			return
		}
		if decision != authorizer.DecisionAllow {
			msg := fmt.Sprintf("Forbidden (user=%s, verb=%s, resource=%s, subresource=%s, decision=%d)", attrs.GetUser().GetName(), attrs.GetVerb(), attrs.GetResource(), attrs.GetSubresource(), decision)
			log.G(m.ctx).Info(msg)
			resp.WriteHeader(http.StatusForbidden)
			resp.Write([]byte(msg))
			return
		}

		h.ServeHTTP(resp, req)
	})
}
