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

// Package render builds the owned NetworkPolicy from status.enforced only.
package render

import (
	corev1 "k8s.io/api/core/v1"
	netv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"

	v1 "github.com/wscoble/egress-range-controller/api/v1alpha1"
)

// Annotation recording which enforced digest a policy was rendered from.
const AnnotationRenderedDigest = "egress.greybeard.support/rendered-digest"

// DefaultPolicyName is used when spec.networkPolicy.name is empty.
const DefaultPolicyName = "proton-bridge-egress-allow"

// PolicyName returns the effective name.
func PolicyName(er *v1.EgressRanges) string {
	if er.Spec.NetworkPolicy.Name != "" {
		return er.Spec.NetworkPolicy.Name
	}
	return DefaultPolicyName
}

// Mutate sets np's spec from er.Status.Enforced. It never adds CIDRs that are not enforced.
func Mutate(np *netv1.NetworkPolicy, er *v1.EgressRanges) {
	t := er.Spec.NetworkPolicy
	if np.Labels == nil {
		np.Labels = map[string]string{}
	}
	np.Labels["app.kubernetes.io/managed-by"] = "egress-range-controller"
	if np.Annotations == nil {
		np.Annotations = map[string]string{}
	}
	np.Annotations[AnnotationRenderedDigest] = er.Status.Enforced.Digest

	var rules []netv1.NetworkPolicyEgressRule
	if t.AllowDNS == nil || *t.AllowDNS {
		udp, tcp := corev1.ProtocolUDP, corev1.ProtocolTCP
		p53 := intstr.FromInt32(53)
		rules = append(rules, netv1.NetworkPolicyEgressRule{
			To: []netv1.NetworkPolicyPeer{{
				NamespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"kubernetes.io/metadata.name": "kube-system"}},
				PodSelector:       &metav1.LabelSelector{MatchLabels: map[string]string{"k8s-app": "kube-dns"}},
			}},
			Ports: []netv1.NetworkPolicyPort{{Protocol: &udp, Port: &p53}, {Protocol: &tcp, Port: &p53}},
		})
	}
	if len(er.Status.Enforced.CIDRs) > 0 {
		var peers []netv1.NetworkPolicyPeer
		for _, c := range er.Status.Enforced.CIDRs {
			peers = append(peers, netv1.NetworkPolicyPeer{IPBlock: &netv1.IPBlock{CIDR: c}})
		}
		ports := t.Ports
		if len(ports) == 0 {
			ports = []v1.PortSpec{{Protocol: "TCP", Port: 443}}
		}
		var nps []netv1.NetworkPolicyPort
		for _, p := range ports {
			proto := corev1.Protocol(p.Protocol)
			if proto == "" {
				proto = corev1.ProtocolTCP
			}
			port := intstr.FromInt32(p.Port)
			nps = append(nps, netv1.NetworkPolicyPort{Protocol: &proto, Port: &port})
		}
		rules = append(rules, netv1.NetworkPolicyEgressRule{To: peers, Ports: nps})
	}
	np.Spec = netv1.NetworkPolicySpec{
		PodSelector: t.PodSelector,
		PolicyTypes: []netv1.PolicyType{netv1.PolicyTypeEgress},
		Egress:      rules,
	}
}
