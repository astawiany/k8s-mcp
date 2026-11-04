package kube

import (
	"errors"
	"fmt"
	"maps"
	"slices"
	"sync"
	"time"

	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
)

// FactoryOption configures NewFactory.
type FactoryOption func(*factory)

// WithTimeout sets the per-request timeout of every client (default
// DefaultTimeout). Non-positive values are ignored.
func WithTimeout(d time.Duration) FactoryOption {
	return func(f *factory) {
		if d > 0 {
			f.timeout = d
		}
	}
}

type factory struct {
	raw     clientcmdapi.Config
	rules   *clientcmd.ClientConfigLoadingRules
	allow   Allowlist
	timeout time.Duration

	mu      sync.Mutex
	clients map[string]Client
}

var _ Factory = (*factory)(nil)

// NewFactory loads the kubeconfig once. kubeconfigPath "" follows the
// default loading rules ($KUBECONFIG, then ~/.kube/config); a non-empty path
// is used exclusively. Clients are built lazily per context and cached;
// building one never contacts the cluster or runs an exec plugin.
func NewFactory(kubeconfigPath string, allow Allowlist, opts ...FactoryOption) (Factory, error) {
	rules := clientcmd.NewDefaultClientConfigLoadingRules()
	rules.ExplicitPath = kubeconfigPath
	raw, err := rules.Load()
	if err != nil {
		// clientcmd errors name the file and the parse problem, never values.
		return nil, fmt.Errorf("load kubeconfig: %w", err)
	}
	if len(raw.Contexts) == 0 {
		return nil, errors.New("kubeconfig has no contexts (set --kubeconfig or $KUBECONFIG)")
	}
	f := &factory{raw: *raw, rules: rules, allow: allow, timeout: DefaultTimeout, clients: map[string]Client{}}
	for _, o := range opts {
		o(f)
	}
	return f, nil
}

// Contexts implements Factory.
func (f *factory) Contexts() []ContextInfo {
	return contextInfos(slices.Collect(maps.Keys(f.raw.Contexts)), f.raw.CurrentContext, f.allow)
}

// For implements Factory.
func (f *factory) For(name string) (Client, error) {
	name, err := checkContext(name, f.raw.CurrentContext, func(n string) bool { _, ok := f.raw.Contexts[n]; return ok }, f.allow)
	if err != nil {
		return nil, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if c, ok := f.clients[name]; ok {
		return c, nil
	}
	cc := clientcmd.NewNonInteractiveClientConfig(f.raw, name, &clientcmd.ConfigOverrides{}, f.rules)
	cfg, err := cc.ClientConfig()
	if err != nil {
		// Deliberately not wrapping err: clientcmd messages can quote file
		// paths and kubeconfig entries.
		return nil, fmt.Errorf("context %q: kubeconfig entry is invalid or incomplete (inspect it with kubectl config view --minify --context %s)", name, name)
	}
	cfg.Timeout = f.timeout
	c, err := newLiveClient(cfg)
	if err != nil {
		return nil, fmt.Errorf("context %q: cannot build client", name)
	}
	f.clients[name] = c
	return c, nil
}

// contextInfos returns names sorted with current/allowed flags.
func contextInfos(names []string, current string, allow Allowlist) []ContextInfo {
	slices.Sort(names)
	out := make([]ContextInfo, 0, len(names))
	for _, n := range names {
		out = append(out, ContextInfo{Name: n, Current: n == current, Allowed: allow.Allows(n)})
	}
	return out
}

// checkContext resolves "" to current and applies existence and allowlist.
func checkContext(name, current string, exists func(string) bool, allow Allowlist) (string, error) {
	if name == "" {
		if current == "" {
			return "", fmt.Errorf("%w: no current context is set; pass a context name", ErrUnknownContext)
		}
		name = current
	}
	if !exists(name) {
		return "", fmt.Errorf("%w %q; use list_contexts to see the available ones", ErrUnknownContext, name)
	}
	if !allow.Allows(name) {
		return "", fmt.Errorf("%w: %q (allowed: %s)", ErrContextNotAllowed, name, allow)
	}
	return name, nil
}
