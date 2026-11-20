package trafficpolicy

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	authenticationv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"

	kgwv1a1 "github.com/kgateway-dev/kgateway/v2/api/v1alpha1/kgateway"
	"github.com/kgateway-dev/kgateway/v2/pkg/pluginsdk/ir"
)

const testAudience = "api://AzureADTokenExchange"

var testTokenKey = serviceAccountTokenKey{namespace: "ns", name: "sa", audience: testAudience}

// fakeTokenAPI answers TokenRequests with numbered tokens that expire after the requested
// lifetime, or with failWith when it is set.
type fakeTokenAPI struct {
	now      time.Time
	requests []*authenticationv1.TokenRequest
	names    []string
	failWith error
}

func newTestServiceAccountTokens(api *fakeTokenAPI, live ...ir.GatewayExtension) *serviceAccountTokens {
	client := fake.NewClientset()
	client.PrependReactor("create", "serviceaccounts", func(action k8stesting.Action) (bool, runtime.Object, error) {
		create := action.(k8stesting.CreateActionImpl)
		if create.GetSubresource() != "token" {
			return false, nil, nil
		}
		req := create.Object.(*authenticationv1.TokenRequest)
		api.requests = append(api.requests, req)
		api.names = append(api.names, create.GetNamespace()+"/"+create.Name)
		if api.failWith != nil {
			return true, nil, api.failWith
		}
		lifetime := time.Duration(*req.Spec.ExpirationSeconds) * time.Second
		return true, &authenticationv1.TokenRequest{
			Status: authenticationv1.TokenRequestStatus{
				Token:               fmt.Sprintf("token-%d", len(api.requests)),
				ExpirationTimestamp: metav1.NewTime(api.now.Add(lifetime)),
			},
		}, nil
	})

	t := newServiceAccountTokens(client, func() []ir.GatewayExtension { return live })
	t.now = func() time.Time { return api.now }
	return t
}

func clientAssertionExtension(namespace, name, serviceAccount string) ir.GatewayExtension {
	return ir.GatewayExtension{
		ObjectSource: ir.ObjectSource{Namespace: namespace, Name: name},
		OAuth2: &kgwv1a1.OAuth2Provider{
			Credentials: kgwv1a1.OAuth2Credentials{
				ClientID: "client",
				ClientAssertion: &kgwv1a1.OAuth2ClientAssertion{
					ServiceAccountRef: corev1.LocalObjectReference{Name: serviceAccount},
					Audience:          testAudience,
				},
			},
		},
	}
}

func TestClientAssertionKey(t *testing.T) {
	r := require.New(t)

	ext := clientAssertionExtension("ns", "ext", "sa")
	key, ok := clientAssertionKey(&ext)
	r.True(ok)
	r.Equal(testTokenKey, key)

	withSecret := ir.GatewayExtension{OAuth2: &kgwv1a1.OAuth2Provider{
		Credentials: kgwv1a1.OAuth2Credentials{ClientSecretRef: &corev1.LocalObjectReference{Name: "secret"}},
	}}
	_, ok = clientAssertionKey(&withSecret)
	r.False(ok)
}

func TestServiceAccountTokensGetRequestsOnceAndCaches(t *testing.T) {
	r := require.New(t)
	api := &fakeTokenAPI{now: time.Unix(1000, 0)}
	tokens := newTestServiceAccountTokens(api)

	token, err := tokens.get(context.Background(), testTokenKey)
	r.NoError(err)
	r.Equal("token-1", token)
	r.Equal([]string{"ns/sa"}, api.names)
	r.Equal([]string{testAudience}, api.requests[0].Spec.Audiences)
	r.Equal(int64(3600), *api.requests[0].Spec.ExpirationSeconds)

	token, err = tokens.get(context.Background(), testTokenKey)
	r.NoError(err)
	r.Equal("token-1", token)
	r.Len(api.requests, 1, "a valid token must be served from the cache")

	// An expired token is never served, even if the renewal loop has not run.
	api.now = api.now.Add(time.Hour)
	token, err = tokens.get(context.Background(), testTokenKey)
	r.NoError(err)
	r.Equal("token-2", token)
}

func TestServiceAccountTokensFailureIsCachedAndRetried(t *testing.T) {
	r := require.New(t)
	api := &fakeTokenAPI{now: time.Unix(1000, 0), failWith: errors.New(`serviceaccounts "sa" not found`)}
	tokens := newTestServiceAccountTokens(api)

	_, err := tokens.get(context.Background(), testTokenKey)
	r.ErrorContains(err, `requesting token for ServiceAccount ns/sa: serviceaccounts "sa" not found`)

	_, err = tokens.get(context.Background(), testTokenKey)
	r.Error(err)
	r.Len(api.requests, 1, "a failure must be served from the cache until it is retried")

	// The same failure again is not a change.
	r.False(tokens.renew(context.Background(), testTokenKey))

	api.failWith = nil
	r.True(tokens.renew(context.Background(), testTokenKey), "recovery must trigger a recomputation")
	token, err := tokens.get(context.Background(), testTokenKey)
	r.NoError(err)
	r.Equal("token-3", token)
}

func TestServiceAccountTokensRenewKeepsValidTokenOnFailure(t *testing.T) {
	r := require.New(t)
	api := &fakeTokenAPI{now: time.Unix(1000, 0)}
	tokens := newTestServiceAccountTokens(api)

	_, err := tokens.get(context.Background(), testTokenKey)
	r.NoError(err)

	api.failWith = errors.New("apiserver unavailable")
	r.False(tokens.renew(context.Background(), testTokenKey))

	token, err := tokens.get(context.Background(), testTokenKey)
	r.NoError(err)
	r.Equal("token-1", token)
	tok, _ := tokens.load(testTokenKey)
	r.Equal(api.now.Add(clientAssertionRetryInterval), tok.renewAt, "the failed renewal must be retried")
}

func TestServiceAccountTokensRenewOnce(t *testing.T) {
	r := require.New(t)
	api := &fakeTokenAPI{now: time.Unix(1000, 0)}
	unusedKey := serviceAccountTokenKey{namespace: "ns", name: "unused", audience: testAudience}
	tokens := newTestServiceAccountTokens(api, clientAssertionExtension("ns", "ext", "sa"))

	_, err := tokens.get(context.Background(), testTokenKey)
	r.NoError(err)
	_, err = tokens.get(context.Background(), unusedKey)
	r.NoError(err)

	// Not due before 80% of the lifetime.
	api.now = api.now.Add(47 * time.Minute)
	tokens.renewOnce(context.Background())
	r.Len(api.requests, 2)

	// The live extension's token is renewed; the unused one is kept until it expires.
	api.now = api.now.Add(2 * time.Minute)
	tokens.renewOnce(context.Background())
	r.Len(api.requests, 3)
	tok, _ := tokens.load(testTokenKey)
	r.Equal("token-3", tok.token)
	_, ok := tokens.load(unusedKey)
	r.True(ok)

	api.now = api.now.Add(11 * time.Minute)
	tokens.renewOnce(context.Background())
	_, ok = tokens.load(unusedKey)
	r.False(ok, "an expired token no extension uses must be dropped")
	_, ok = tokens.load(testTokenKey)
	r.True(ok)
}
