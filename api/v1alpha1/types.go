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

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Annotation keys. Writing these is the only manual override; restrict who may
// patch EgressRanges objects with RBAC.
const (
	AnnotationApproveDigest = "egress.greybeard.support/approve-digest"
	AnnotationRejectDigest  = "egress.greybeard.support/reject-digest"
)

// Condition types.
const (
	ConditionSynced                  = "Synced"
	ConditionQuarantined             = "Quarantined"
	ConditionSourceUnavailable       = "SourceUnavailable"
	ConditionEndpointOutsideEnforced = "EndpointOutsideEnforced"
	ConditionNeedsApproval           = "NeedsApproval"
)

// Source types.
const (
	SourceRIPEstatRPKI = "ripestat-rpki"
	SourceStatic       = "static"
	SourceURL          = "url"
)

// Fetch results.
const (
	FetchOK          = "OK"
	FetchUnreachable = "Unreachable"
	FetchInvalid     = "Invalid"
)

// Verification states (sec. 7). The controller never sends mail; it composes
// the message and records it. Confirmed/Denied are set from the approve/reject
// annotations.
const (
	VerificationComposed  = "Composed"
	VerificationConfirmed = "Confirmed"
	VerificationDenied    = "Denied"
	VerificationNoReply   = "NoReply"
	VerificationSkipped   = "RateLimited"
)

// RIPEstatSource polls RIPEstat announced-prefixes for an ASN and keeps only
// prefixes that RIPEstat's RPKI validator reports as "valid" for that origin.
type RIPEstatSource struct {
	// ASN whose ROA-valid announced prefixes form the source set.
	// +kubebuilder:validation:Minimum=1
	ASN int64 `json:"asn"`
	// BaseURL of the RIPEstat data API.
	// +kubebuilder:default="https://stat.ripe.net"
	// +optional
	BaseURL string `json:"baseURL,omitempty"`
	// SourceApp is sent as RIPEstat's sourceapp parameter.
	// +kubebuilder:default="egress-range-controller"
	// +optional
	SourceApp string `json:"sourceApp,omitempty"`
}

// StaticSource is a fixed list. Useful for testing and for providers that only
// publish a list on a web page. Prefixes are treated as trusted (no RPKI check).
type StaticSource struct {
	CIDRs []string `json:"cidrs"`
}

// URLSource fetches a plain-text list (one CIDR per line, '#' comments) over HTTPS.
// Prefixes are treated as trusted (no RPKI check), so the quarantine is your only protection.
type URLSource struct {
	// +kubebuilder:validation:Pattern=`^https://`
	URL string `json:"url"`
}

// Source selects where candidate prefixes come from.
type Source struct {
	// +kubebuilder:validation:Enum=ripestat-rpki;static;url
	// +kubebuilder:default=ripestat-rpki
	Type string `json:"type"`
	// +optional
	RIPEstat *RIPEstatSource `json:"ripestat,omitempty"`
	// +optional
	Static *StaticSource `json:"static,omitempty"`
	// +optional
	URL *URLSource `json:"url,omitempty"`
}

// DNSSECConfig configures endpoint resolution.
type DNSSECConfig struct {
	// Resolvers are validating recursive resolvers: "tls://ip:853#servername" (DNS over TLS, default)
	// or "ip:53" (plain DNS; the AD bit is then unauthenticated on the wire).
	// +kubebuilder:default={"tls://1.1.1.1:853#cloudflare-dns.com","tls://9.9.9.9:853#dns.quad9.net"}
	// +optional
	Resolvers []string `json:"resolvers,omitempty"`
	// RequireAD fails closed unless the resolver sets the Authenticated Data flag.
	// +kubebuilder:default=true
	// +optional
	RequireAD *bool `json:"requireAD,omitempty"`
	// +kubebuilder:default="5s"
	// +optional
	Timeout *metav1.Duration `json:"timeout,omitempty"`
}

// Approval configures how promotions are gated.
type Approval struct {
	// Mode "auto" promotes after the quarantine if all safety checks pass;
	// "manual" requires an approve-digest annotation for every change.
	// +kubebuilder:validation:Enum=auto;manual
	// +kubebuilder:default=auto
	// +optional
	Mode string `json:"mode,omitempty"`
	// MaxChangeFraction: (added+removed)/len(enforced) above this needs approval.
	// Decimal string, e.g. "0.5".
	// +kubebuilder:validation:Pattern=`^(0(\.[0-9]+)?|1(\.0+)?)$`
	// +kubebuilder:default="0.5"
	// +optional
	MaxChangeFraction string `json:"maxChangeFraction,omitempty"`
	// NoReplyPolicy applies only when verification is enabled and no
	// confirmation arrived by promoteAfter: "promote" (if safe) or "hold".
	// +kubebuilder:validation:Enum=promote;hold
	// +kubebuilder:default=promote
	// +optional
	NoReplyPolicy string `json:"noReplyPolicy,omitempty"`
}

// Verification configures the (disabled-by-default) verification email hook.
// The controller only COMPOSES the email into status and an Event; it contains
// no SMTP client. Delivery is left to an external, human-approved step.
type Verification struct {
	// +kubebuilder:default=false
	// +optional
	Enabled bool `json:"enabled,omitempty"`
	// To is the provider's network-operations contact, e.g. noc@proton.ch.
	// +optional
	To string `json:"to,omitempty"`
	// From is the sender identity shown in the composed message.
	// +optional
	From string `json:"from,omitempty"`
	// MinInterval between composed emails (rate limit across all digests).
	// +kubebuilder:default="168h"
	// +optional
	MinInterval *metav1.Duration `json:"minInterval,omitempty"`
}

// PortSpec is a destination port for the rendered policy.
type PortSpec struct {
	// +kubebuilder:validation:Enum=TCP;UDP
	// +kubebuilder:default=TCP
	// +optional
	Protocol string `json:"protocol,omitempty"`
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	Port int32 `json:"port"`
}

// NetworkPolicyTemplate describes the NetworkPolicy the controller owns.
type NetworkPolicyTemplate struct {
	// +kubebuilder:default=proton-bridge-egress-allow
	// +optional
	Name string `json:"name,omitempty"`
	// PodSelector of the workload whose egress is restricted.
	PodSelector metav1.LabelSelector `json:"podSelector"`
	// +kubebuilder:default={{protocol: TCP, port: 443}}
	// +optional
	Ports []PortSpec `json:"ports,omitempty"`
	// AllowDNS adds an egress rule to cluster DNS (kube-system/k8s-app=kube-dns, 53/UDP+TCP).
	// +kubebuilder:default=true
	// +optional
	AllowDNS *bool `json:"allowDNS,omitempty"`
}

// EgressRangesSpec defines the desired behaviour.
type EgressRangesSpec struct {
	Source Source `json:"source"`
	// Pinned ranges are always enforced and never removed automatically.
	// +optional
	Pinned []string `json:"pinned,omitempty"`
	// Endpoints are hostnames the workload must reach; their DNSSEC-validated
	// addresses must fall inside the candidate set.
	// +optional
	Endpoints []string `json:"endpoints,omitempty"`
	// Mode "minimal": pinned + source prefixes containing a resolved endpoint.
	// "all": pinned + every source prefix.
	// +kubebuilder:validation:Enum=minimal;all
	// +kubebuilder:default=minimal
	// +optional
	Mode string `json:"mode,omitempty"`
	// IPFamilies to keep from the source and resolve for endpoints.
	// +kubebuilder:default={"IPv4"}
	// +optional
	IPFamilies []string `json:"ipFamilies,omitempty"`
	// +kubebuilder:default="6h"
	// +optional
	PollInterval *metav1.Duration `json:"pollInterval,omitempty"`
	// JitterPercent randomises each poll by +/- this percent of pollInterval.
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=50
	// +kubebuilder:default=10
	// +optional
	JitterPercent int32 `json:"jitterPercent,omitempty"`
	// +kubebuilder:default="72h"
	// +optional
	QuarantinePeriod *metav1.Duration `json:"quarantinePeriod,omitempty"`
	// UnreachableAlertAfter raises reason AlertUnreachable24h after this long without a successful fetch.
	// +kubebuilder:default="24h"
	// +optional
	UnreachableAlertAfter *metav1.Duration `json:"unreachableAlertAfter,omitempty"`
	// +optional
	DNSSEC DNSSECConfig `json:"dnssec,omitempty"`
	// +optional
	Approval Approval `json:"approval,omitempty"`
	// +optional
	Verification Verification `json:"verification,omitempty"`
	// NotifyWebhook, if set, receives a JSON POST for every alert/queue event.
	// The controller's own NetworkPolicy must allow egress to it.
	// +optional
	NotifyWebhook string                `json:"notifyWebhook,omitempty"`
	NetworkPolicy NetworkPolicyTemplate `json:"networkPolicy"`
}

// RangeSet is an enforced set.
type RangeSet struct {
	CIDRs  []string     `json:"cidrs,omitempty"`
	Digest string       `json:"digest,omitempty"`
	Since  *metav1.Time `json:"since,omitempty"`
}

// VerificationRequest is the composed (never sent) verification email.
type VerificationRequest struct {
	ID         string       `json:"id"`
	State      string       `json:"state"`
	To         string       `json:"to,omitempty"`
	From       string       `json:"from,omitempty"`
	Subject    string       `json:"subject,omitempty"`
	Body       string       `json:"body,omitempty"`
	ComposedAt *metav1.Time `json:"composedAt,omitempty"`
}

// PendingSet is the quarantine slot (at most one).
type PendingSet struct {
	CIDRs          []string    `json:"cidrs,omitempty"`
	Digest         string      `json:"digest"`
	FirstSeen      metav1.Time `json:"firstSeen"`
	LastConfirmed  metav1.Time `json:"lastConfirmed"`
	PromoteAfter   metav1.Time `json:"promoteAfter"`
	Added          []string    `json:"added,omitempty"`
	Removed        []string    `json:"removed,omitempty"`
	ChangeFraction string      `json:"changeFraction,omitempty"`
	// SafetyFailures lists checks that currently block automatic promotion.
	SafetyFailures []string `json:"safetyFailures,omitempty"`
	// +optional
	Verification *VerificationRequest `json:"verification,omitempty"`
}

// FetchStatus records the last fetch attempt.
type FetchStatus struct {
	Time   metav1.Time `json:"time"`
	Result string      `json:"result"`
	Source string      `json:"source,omitempty"`
	// +optional
	Message string `json:"message,omitempty"`
	// Candidate is the candidate set computed from the last OK fetch.
	// +optional
	Candidate []string `json:"candidate,omitempty"`
	// +optional
	CandidateDigest string `json:"candidateDigest,omitempty"`
	// ResolvedEndpoints are "host=ip" pairs from the last DNSSEC-validated lookup.
	// +optional
	ResolvedEndpoints []string `json:"resolvedEndpoints,omitempty"`
}

// EgressRangesStatus is the observed state; it lives in etcd so restarts do not reset clocks.
type EgressRangesStatus struct {
	// +optional
	Enforced RangeSet `json:"enforced,omitempty"`
	// +optional
	Pending *PendingSet `json:"pending,omitempty"`
	// +optional
	LastFetch *FetchStatus `json:"lastFetch,omitempty"`
	// +optional
	LastSuccess *metav1.Time `json:"lastSuccess,omitempty"`
	// +optional
	FirstFailure *metav1.Time `json:"firstFailure,omitempty"`
	// +optional
	ConsecutiveFailures int32 `json:"consecutiveFailures,omitempty"`
	// +optional
	NextFetch *metav1.Time `json:"nextFetch,omitempty"`
	// +optional
	RejectedDigests []string `json:"rejectedDigests,omitempty"`
	// +optional
	LastVerificationAt *metav1.Time `json:"lastVerificationAt,omitempty"`
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`
	// +optional
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// EgressRanges keeps a NetworkPolicy's egress allowlist in sync with a
// provider's published ranges, behind a quarantine.
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:shortName=egr
// +kubebuilder:printcolumn:name="Enforced",type=string,JSONPath=`.status.enforced.digest`
// +kubebuilder:printcolumn:name="Pending",type=string,JSONPath=`.status.pending.digest`
// +kubebuilder:printcolumn:name="PromoteAfter",type=string,JSONPath=`.status.pending.promoteAfter`
// +kubebuilder:printcolumn:name="LastFetch",type=string,JSONPath=`.status.lastFetch.result`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`
type EgressRanges struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   EgressRangesSpec   `json:"spec,omitempty"`
	Status EgressRangesStatus `json:"status,omitempty"`
}

// EgressRangesList is a list.
// +kubebuilder:object:root=true
type EgressRangesList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []EgressRanges `json:"items"`
}

func init() {
	SchemeBuilder.Register(&EgressRanges{}, &EgressRangesList{})
}
