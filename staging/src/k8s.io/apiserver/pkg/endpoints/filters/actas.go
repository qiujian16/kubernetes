package filters

import (
	"errors"
	"fmt"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apiserver/pkg/audit"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apiserver/pkg/authorization/authorizer"
	"k8s.io/apiserver/pkg/endpoints/handlers/responsewriters"
	"k8s.io/apiserver/pkg/endpoints/request"
	"k8s.io/apiserver/pkg/server/httplog"
	"k8s.io/klog/v2"
	"net/http"
	"strings"
)

const (
	ActAsUserHeader        = "ActAs-User"
	ActAsGroupHeader       = "ActAs-Group"
	ActAsExtraHeaderPrefix = "ActAs-Extra"
	ActAsUID               = "ActAs-Uid"
)

func WithActAs(handler http.Handler, a authorizer.Authorizer, s runtime.NegotiatedSerializer) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		actAsUser, isActAsRequest, err := buildActAsUserInfo(req.Header)
		if err != nil {
			klog.V(4).Infof("%v", err)
			responsewriters.InternalError(w, req, err)
			return
		}
		if !isActAsRequest {
			handler.ServeHTTP(w, req)
			return
		}

		ctx := req.Context()
		requestor, exists := request.UserFrom(ctx)
		if !exists {
			responsewriters.InternalError(w, req, errors.New("no user found for request"))
			return
		}

		// check if the real user has actas permission at all
		actingAsAttributes := &authorizer.AttributesRecord{
			User:            requestor,
			Verb:            "actas",
			Name:            "*",
			Resource:        "*",
			ResourceRequest: true,
		}
		actAsDecision, reason, err := a.Authorize(ctx, actingAsAttributes)
		if err != nil || actAsDecision != authorizer.DecisionAllow {
			klog.V(4).InfoS("Forbidden", "URI", req.RequestURI, "reason", reason, "err", err)
			responsewriters.Forbidden(ctx, actingAsAttributes, w, req, reason, s)
			return
		}

		if actAsUser.Name != user.Anonymous {
			// When acting as a non-anonymous user, include the 'system:authenticated' group
			// in the acted user info:
			// - if no groups were specified
			// - if a group has been specified other than 'system:authenticated'
			//
			// If 'system:unauthenticated' group has been specified we should not include
			// the 'system:authenticated' group.
			addAuthenticated := true
			for _, group := range actAsUser.Groups {
				if group == user.AllAuthenticated || group == user.AllUnauthenticated {
					addAuthenticated = false
					break
				}
			}

			if addAuthenticated {
				actAsUser.Groups = append(actAsUser.Groups, user.AllAuthenticated)
			}
		} else {
			addUnauthenticated := true
			for _, group := range actAsUser.Groups {
				if group == user.AllUnauthenticated {
					addUnauthenticated = false
					break
				}
			}

			if addUnauthenticated {
				actAsUser.Groups = append(actAsUser.Groups, user.AllUnauthenticated)
			}
		}

		// authorize if the acctas user is authorized
		attributes, err := GetAuthorizerAttributes(ctx)
		if err != nil {
			responsewriters.InternalError(w, req, err)
			return
		}
		attributes.User = actAsUser
		decision, reason, err := a.Authorize(ctx, attributes)
		if err != nil || decision != authorizer.DecisionAllow {
			klog.V(4).InfoS("Forbidden", "URI", req.RequestURI, "reason", reason, "err", err)
			responsewriters.Forbidden(ctx, attributes, w, req, reason, s)
			return
		}

		oldUser, _ := request.UserFrom(ctx)
		httplog.LogOf(req, w).Addf("%v is acting as %v", userString(oldUser), userString(actAsUser))

		ae := audit.AuditEventFrom(ctx)
		audit.LogActAsUser(ae, actAsUser)

		// clear all the actas headers from the request
		req.Header.Del(ActAsUserHeader)
		req.Header.Del(ActAsGroupHeader)
		req.Header.Del(ActAsUID)
		for headerName := range req.Header {
			if strings.HasPrefix(headerName, ActAsExtraHeaderPrefix) {
				req.Header.Del(headerName)
			}
		}

		handler.ServeHTTP(w, req)
	})
}

func buildActAsUserInfo(headers http.Header) (*user.DefaultInfo, bool, error) {
	groups := []string{}
	userExtra := map[string][]string{}

	username := headers.Get(ActAsUserHeader)
	hasUser := len(username) > 0

	hasGroups := false
	for _, group := range headers[ActAsGroupHeader] {
		hasGroups = true
		groups = append(groups, group)
	}

	hasUserExtra := false
	for headerName, values := range headers {
		if !strings.HasPrefix(headerName, ActAsExtraHeaderPrefix) {
			continue
		}

		hasUserExtra = true
		extraKey := unescapeExtraKey(strings.ToLower(headerName[len(ActAsExtraHeaderPrefix):]))

		// make a separate request for each extra value they're trying to set
		for _, value := range values {
			userExtra[extraKey] = append(userExtra[extraKey], value)
		}
	}

	uid := headers.Get(ActAsUID)
	hasUID := len(uid) > 0

	if (hasGroups || hasUserExtra || hasUID) && !hasUser {
		return nil, true, fmt.Errorf("requested without acting as a user")
	} else if !hasUser {
		// no actas headers are set.
		return nil, false, nil
	}

	return &user.DefaultInfo{
		Name:   username,
		Groups: groups,
		Extra:  userExtra,
		UID:    uid,
	}, true, nil
}
