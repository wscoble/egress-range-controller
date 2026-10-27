/*
Copyright 2026 Greybeard Holdings LLC.

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

// Command egress-range-controller runs the controller, or a one-shot dry-run fetch.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
	"sigs.k8s.io/yaml"

	v1 "github.com/wscoble/egress-range-controller/api/v1alpha1"
	"github.com/wscoble/egress-range-controller/internal/controller"
	"github.com/wscoble/egress-range-controller/internal/engine"
	"github.com/wscoble/egress-range-controller/internal/render"
)

var version = "0.1.0"

func main() {
	var (
		watchNS      string
		metricsAddr  string
		probeAddr    string
		leaderElect  bool
		dryRun       bool
		dryRunSpec   string
		printVersion bool
	)
	flag.StringVar(&watchNS, "namespace", os.Getenv("POD_NAMESPACE"), "namespace to watch (required for namespaced RBAC)")
	flag.StringVar(&metricsAddr, "metrics-bind-address", ":8080", "metrics endpoint")
	flag.StringVar(&probeAddr, "health-probe-bind-address", ":8081", "health probe endpoint")
	flag.BoolVar(&leaderElect, "leader-elect", true, "enable leader election")
	flag.BoolVar(&dryRun, "dry-run-fetch", false, "fetch once, print the candidate set and bootstrap decision as JSON, and exit (no cluster access)")
	flag.StringVar(&dryRunSpec, "spec", "", "dry-run: path to an EgressRanges YAML (default: built-in Proton example)")
	flag.BoolVar(&printVersion, "version", false, "print version")
	opts := zap.Options{}
	opts.BindFlags(flag.CommandLine)
	flag.Parse()
	if printVersion {
		fmt.Println(version)
		return
	}
	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))

	if dryRun {
		if err := runDryRun(dryRunSpec); err != nil {
			fmt.Fprintln(os.Stderr, "dry-run:", err)
			os.Exit(1)
		}
		return
	}

	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = v1.AddToScheme(scheme)
	if watchNS == "" {
		fmt.Fprintln(os.Stderr, "--namespace (or POD_NAMESPACE) is required")
		os.Exit(2)
	}
	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:                  scheme,
		Metrics:                 metricsserver.Options{BindAddress: metricsAddr},
		HealthProbeBindAddress:  probeAddr,
		LeaderElection:          leaderElect,
		LeaderElectionID:        "egress-range-controller.egress.greybeard.support",
		LeaderElectionNamespace: watchNS,
		Cache:                   cache.Options{DefaultNamespaces: map[string]cache.Config{watchNS: {}}},
	})
	if err != nil {
		ctrl.Log.Error(err, "manager")
		os.Exit(1)
	}
	r := &controller.Reconciler{
		Client:   mgr.GetClient(),
		Scheme:   mgr.GetScheme(),
		Recorder: mgr.GetEventRecorderFor("egress-range-controller"), //nolint:staticcheck // core/v1 events keep RBAC simple
	}
	if err := r.SetupWithManager(mgr); err != nil {
		ctrl.Log.Error(err, "setup")
		os.Exit(1)
	}
	_ = mgr.AddHealthzCheck("healthz", healthz.Ping)
	_ = mgr.AddReadyzCheck("readyz", healthz.Ping)
	ctrl.Log.Info("starting", "version", version, "namespace", watchNS)
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		ctrl.Log.Error(err, "run")
		os.Exit(1)
	}
}

// ProtonExample is the built-in dry-run spec.
func ProtonExample() v1.EgressRanges {
	t := true
	return v1.EgressRanges{
		ObjectMeta: metav1.ObjectMeta{Name: "default", Namespace: "mail"},
		Spec: v1.EgressRangesSpec{
			Source:     v1.Source{Type: v1.SourceRIPEstatRPKI, RIPEstat: &v1.RIPEstatSource{ASN: 62371}},
			Pinned:     []string{"185.70.40.0/22"},
			Endpoints:  []string{"mail-api.proton.me", "account.proton.me"},
			Mode:       "minimal",
			IPFamilies: []string{"IPv4"},
			DNSSEC:     v1.DNSSECConfig{Resolvers: []string{"tls://1.1.1.1:853#cloudflare-dns.com", "tls://9.9.9.9:853#dns.quad9.net"}, RequireAD: &t},
			NetworkPolicy: v1.NetworkPolicyTemplate{
				Name:        render.DefaultPolicyName,
				PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "proton-bridge"}},
			},
		},
	}
}

func runDryRun(path string) error {
	er := ProtonExample()
	if path != "" {
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		er = v1.EgressRanges{}
		if err := yaml.UnmarshalStrict(b, &er); err != nil {
			return err
		}
	}
	cfg, err := engine.ConfigFromSpec(er.Spec)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	obs := (&controller.Observer{}).Observe(ctx, er.Spec, cfg)
	st := &v1.EgressRangesStatus{}
	evs := (&engine.Engine{}).Step(st, cfg, engine.Annotations{}, obs, time.Now().UTC(), 1)
	out := map[string]any{
		"time":              time.Now().UTC().Format(time.RFC3339),
		"source":            obs.Source.Source,
		"rpkiValid":         obs.Source.Prefixes,
		"rpkiNotAccepted":   obs.Source.Rejected,
		"resolved":          obs.Resolved,
		"fetchError":        errString(obs.FetchErr),
		"dnssecError":       errString(obs.DNSErr),
		"candidate":         st.LastFetch.Candidate,
		"candidateDigest":   st.LastFetch.CandidateDigest,
		"bootstrapEnforced": st.Enforced,
		"events":            evs,
		"conditions":        st.Conditions,
	}
	if st.LastFetch.Candidate != nil {
		out["safetyFailures"] = engine.SafetyFailures(cfg, nil, st.LastFetch.Candidate, obs.Source, obs.Resolved)
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

func errString(e error) string {
	if e == nil {
		return ""
	}
	return e.Error()
}
