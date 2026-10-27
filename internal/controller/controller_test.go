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

package controller

import (
	"context"
	"net/http"
	"testing"
	"time"

	netv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	v1 "github.com/wscoble/egress-range-controller/api/v1alpha1"
	"github.com/wscoble/egress-range-controller/internal/dnssec"
	"github.com/wscoble/egress-range-controller/internal/engine"
	"github.com/wscoble/egress-range-controller/internal/notify"
	"github.com/wscoble/egress-range-controller/internal/source"
)

func TestReconcileBootstrapsAndRendersPolicy(t *testing.T) {
	sch := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(sch)
	_ = v1.AddToScheme(sch)
	er := &v1.EgressRanges{
		ObjectMeta: metav1.ObjectMeta{Name: "default", Namespace: "mail", Generation: 1, UID: "u1"},
		Spec: v1.EgressRangesSpec{
			Source:        v1.Source{Type: v1.SourceStatic, Static: &v1.StaticSource{CIDRs: []string{"185.70.42.0/24", "79.135.106.0/24"}}},
			Pinned:        []string{"185.70.40.0/22"},
			Endpoints:     []string{"mail-api.proton.me"},
			NetworkPolicy: v1.NetworkPolicyTemplate{PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "proton-bridge"}}},
		},
	}
	c := fake.NewClientBuilder().WithScheme(sch).WithObjects(er).WithStatusSubresource(er).Build()
	now := time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)
	rec := record.NewFakeRecorder(20)
	r := &Reconciler{
		Client: c, Scheme: sch, Recorder: rec, Webhook: &notify.Webhook{},
		Now:    func() time.Time { return now },
		Engine: &engine.Engine{},
		Observer: &Observer{
			NewFetcher: func(s v1.Source, _ *http.Client) (source.Fetcher, error) { return source.New(s, nil) },
			NewResolver: func(v1.DNSSECConfig) dnssec.Resolver {
				return &dnssec.Static{Answers: map[string][]string{"mail-api.proton.me": {"185.70.42.41"}}}
			},
		},
	}
	res, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Namespace: "mail", Name: "default"}})
	if err != nil {
		t.Fatal(err)
	}
	if res.RequeueAfter != 6*time.Hour {
		t.Fatalf("requeue %v", res.RequeueAfter)
	}
	var got v1.EgressRanges
	_ = c.Get(context.Background(), types.NamespacedName{Namespace: "mail", Name: "default"}, &got)
	if len(got.Status.Enforced.CIDRs) != 2 {
		t.Fatalf("enforced %v", got.Status.Enforced.CIDRs)
	}
	var np netv1.NetworkPolicy
	if err := c.Get(context.Background(), types.NamespacedName{Namespace: "mail", Name: "proton-bridge-egress-allow"}, &np); err != nil {
		t.Fatal(err)
	}
	if len(np.OwnerReferences) != 1 || np.OwnerReferences[0].Kind != "EgressRanges" {
		t.Fatalf("owner refs %+v", np.OwnerReferences)
	}
	if len(np.Spec.Egress) != 2 || len(np.Spec.Egress[1].To) != 2 {
		t.Fatalf("policy %+v", np.Spec)
	}
	select {
	case e := <-rec.Events:
		t.Log(e)
	default:
		t.Fatal("no event recorded")
	}
	// Second reconcile before NextFetch: no fetch, still synced.
	r.Observer.NewFetcher = func(v1.Source, *http.Client) (source.Fetcher, error) { t.Fatal("fetched early"); return nil, nil }
	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Namespace: "mail", Name: "default"}}); err != nil {
		t.Fatal(err)
	}
}
