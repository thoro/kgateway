package trafficpolicy

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"
	"istio.io/istio/pkg/kube/krt"
	authenticationv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/client-go/kubernetes"

	"github.com/kgateway-dev/kgateway/v2/pkg/pluginsdk/ir"
)

const (
	// clientAssertionTokenLifetime is the lifetime requested for client assertion tokens. The API
	// server may shorten it; renewal follows the expiry it returns.
	clientAssertionTokenLifetime = time.Hour
	// clientAssertionRenewAfter is the share of a token's lifetime after which it is renewed,
	// the same share the kubelet uses for projected ServiceAccount tokens.
	clientAssertionRenewAfter = 0.8
	// clientAssertionRetryInterval is how long a failed token request is served from the cache
	// before it is retried.
	clientAssertionRetryInterval = 30 * time.Second
	// clientAssertionRequestTimeout bounds a single token request.
	clientAssertionRequestTimeout = 10 * time.Second
)

// serviceAccountTokenKey identifies a client assertion token: the ServiceAccount it is issued
// for and its audience.
type serviceAccountTokenKey struct {
	namespace string
	name      string
	audience  string
}

func (k serviceAccountTokenKey) String() string {
	return k.namespace + "/" + k.name + "/" + k.audience
}

// clientAssertionKey returns the token an OAuth2 GatewayExtension sends as client assertion.
// It is shared by buildOAuth2ProviderConfig and the renewal loop, so both agree on which
// tokens are in use.
func clientAssertionKey(ext *ir.GatewayExtension) (serviceAccountTokenKey, bool) {
	if ext.OAuth2 == nil || ext.OAuth2.Credentials.ClientAssertion == nil {
		return serviceAccountTokenKey{}, false
	}
	a := ext.OAuth2.Credentials.ClientAssertion
	return serviceAccountTokenKey{
		namespace: ext.Namespace,
		name:      a.ServiceAccountRef.Name,
		audience:  a.Audience,
	}, true
}

// serviceAccountToken is a cached token request outcome. A failed request has no token; its
// expiry is the time it is retried.
type serviceAccountToken struct {
	token   string
	err     error
	expiry  time.Time
	renewAt time.Time
}

// serviceAccountTokens requests and renews the ServiceAccount tokens that OAuth2
// GatewayExtensions send as client assertions.
type serviceAccountTokens struct {
	client kubernetes.Interface

	// trigger re-runs the GatewayExtension transform when a token is renewed, so the new token
	// reaches Envoy before the previous one expires.
	trigger *krt.RecomputeTrigger

	// liveExtensions returns the GatewayExtensions that currently exist; only their tokens are
	// renewed.
	liveExtensions func() []ir.GatewayExtension

	lifetime      time.Duration
	retryInterval time.Duration
	now           func() time.Time

	mu    sync.Mutex
	cache map[serviceAccountTokenKey]serviceAccountToken

	// requests deduplicates concurrent token requests for the same key.
	requests singleflight.Group
}

// newServiceAccountTokens returns a serviceAccountTokens. Callers must start run() for tokens
// to be renewed.
func newServiceAccountTokens(
	client kubernetes.Interface,
	liveExtensions func() []ir.GatewayExtension,
	opts ...krt.CollectionOption,
) *serviceAccountTokens {
	return &serviceAccountTokens{
		client: client,
		// Start synced: get() requests a token on first use.
		trigger:        krt.NewRecomputeTrigger(true, opts...),
		liveExtensions: liveExtensions,
		lifetime:       clientAssertionTokenLifetime,
		retryInterval:  clientAssertionRetryInterval,
		now:            time.Now,
		cache:          map[serviceAccountTokenKey]serviceAccountToken{},
	}
}

// markDependant registers the calling krt transform as depending on the cached tokens. It must
// be called before get(), also when get() fails, so the transform is re-run once a token is
// renewed or a failed request succeeds.
func (t *serviceAccountTokens) markDependant(krtctx krt.HandlerContext) {
	t.trigger.MarkDependant(krtctx)
}

// get returns the token for key, requesting one when none is cached or the cached one has
// expired. Failures are cached too, and retried by run().
func (t *serviceAccountTokens) get(ctx context.Context, key serviceAccountTokenKey) (string, error) {
	if tok, ok := t.load(key); ok && t.now().Before(tok.expiry) {
		return tok.token, tok.err
	}
	v, _, _ := t.requests.Do(key.String(), func() (any, error) {
		if tok, ok := t.load(key); ok && t.now().Before(tok.expiry) {
			return tok, nil
		}
		tok := t.request(ctx, key)
		t.store(key, tok)
		return tok, nil
	})
	tok := v.(serviceAccountToken)
	return tok.token, tok.err
}

func (t *serviceAccountTokens) load(key serviceAccountTokenKey) (serviceAccountToken, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	tok, ok := t.cache[key]
	return tok, ok
}

func (t *serviceAccountTokens) store(key serviceAccountTokenKey, tok serviceAccountToken) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.cache[key] = tok
}

// request asks the API server for a token for the ServiceAccount in key.
func (t *serviceAccountTokens) request(ctx context.Context, key serviceAccountTokenKey) serviceAccountToken {
	ctx, cancel := context.WithTimeout(ctx, clientAssertionRequestTimeout)
	defer cancel()

	seconds := int64(t.lifetime / time.Second)
	resp, err := t.client.CoreV1().ServiceAccounts(key.namespace).CreateToken(ctx, key.name,
		&authenticationv1.TokenRequest{
			Spec: authenticationv1.TokenRequestSpec{
				Audiences:         []string{key.audience},
				ExpirationSeconds: &seconds,
			},
		},
		metav1.CreateOptions{},
	)
	now := t.now()
	if err == nil && resp.Status.Token == "" {
		err = errors.New("empty token in response")
	}
	if err != nil {
		retryAt := now.Add(t.retryInterval)
		return serviceAccountToken{
			err:     fmt.Errorf("requesting token for ServiceAccount %s/%s: %w", key.namespace, key.name, err),
			expiry:  retryAt,
			renewAt: retryAt,
		}
	}
	expiry := resp.Status.ExpirationTimestamp.Time
	return serviceAccountToken{
		token:   resp.Status.Token,
		expiry:  expiry,
		renewAt: now.Add(time.Duration(float64(expiry.Sub(now)) * clientAssertionRenewAfter)),
	}
}

// run renews the tokens of live GatewayExtensions until ctx is done.
func (t *serviceAccountTokens) run(ctx context.Context) {
	// Tick at half the retry interval so a retry is not delayed by a full extra period.
	ticker := time.NewTicker(max(t.retryInterval/2, time.Millisecond))
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if ctx.Err() != nil {
				return
			}
			t.renewOnce(ctx)
		}
	}
}

// renewOnce renews the tokens of live extensions that are due, drops expired tokens no
// extension uses any more, and triggers a single recomputation if a token changed.
func (t *serviceAccountTokens) renewOnce(ctx context.Context) {
	// List the live extensions outside the lock: it calls into krt.
	live := sets.New[serviceAccountTokenKey]()
	for _, ext := range t.liveExtensions() {
		if key, ok := clientAssertionKey(&ext); ok {
			live.Insert(key)
		}
	}

	now := t.now()
	var due []serviceAccountTokenKey
	t.mu.Lock()
	for key, tok := range t.cache {
		switch {
		case live.Has(key):
			if !now.Before(tok.renewAt) {
				due = append(due, key)
			}
		// A token is kept until it expires, so an extension created after the live list was
		// taken still has its token renewed on the next pass.
		case !now.Before(tok.expiry):
			delete(t.cache, key)
		}
	}
	t.mu.Unlock()

	changed := false
	for _, key := range due {
		if t.renew(ctx, key) {
			changed = true
		}
	}

	// Trigger outside t.mu: the trigger runs the dependent transform, which calls get().
	if changed {
		t.trigger.TriggerRecomputation()
	}
}

// renew requests a new token for key and reports whether the cached outcome changed. When the
// request fails, a token that has not expired yet is kept and retried later.
func (t *serviceAccountTokens) renew(ctx context.Context, key serviceAccountTokenKey) bool {
	prev, _ := t.load(key)
	next := t.request(ctx, key)
	if next.err != nil {
		logger.Warn("renewing oauth2 client assertion token failed", "key", key.String(), "error", next.err)
		if prev.err == nil && t.now().Before(prev.expiry) {
			prev.renewAt = next.renewAt
			next = prev
		}
	}
	t.store(key, next)
	return next.token != prev.token || (next.err == nil) != (prev.err == nil)
}
