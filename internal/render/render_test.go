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

package render

import (
	"testing"

	netv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	v1 "github.com/wscoble/egress-range-controller/api/v1alpha1"
)

func TestRenderOnlyEnforced(t *testing.T) {
	er := &v1.EgressRanges{Spec: v1.EgressRangesSpec{NetworkPolicy: v1.NetworkPolicyTemplate{PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "proton-bridge"}}}}}
	er.Status.Enforced = v1.RangeSet{CIDRs: []string{"185.70.40.0/22", "185.70.42.0/24"}, Digest: "sha256:x"}
	er.Status.Pending = &v1.PendingSet{CIDRs: []string{"203.0.113.0/24"}, Digest: "sha256:y"}
	np := &netv1.NetworkPolicy{}
	Mutate(np, er)
	if len(np.Spec.Egress) != 2 {
		t.Fatalf("rules=%d", len(np.Spec.Egress))
	}
	ip := np.Spec.Egress[1]
	if len(ip.To) != 2 || ip.To[0].IPBlock.CIDR != "185.70.40.0/22" || ip.Ports[0].Port.IntVal != 443 {
		t.Fatalf("%+v", ip)
	}
	for _, r := range np.Spec.Egress {
		for _, p := range r.To {
			if p.IPBlock != nil && p.IPBlock.CIDR == "203.0.113.0/24" {
				t.Fatal("pending CIDR rendered")
			}
		}
	}
	if np.Annotations[AnnotationRenderedDigest] != "sha256:x" || PolicyName(er) != "proton-bridge-egress-allow" {
		t.Fatal("annotation/name")
	}
	er.Status.Enforced = v1.RangeSet{}
	Mutate(np, er)
	if len(np.Spec.Egress) != 1 {
		t.Fatal("empty enforced must render DNS-only")
	}
}
