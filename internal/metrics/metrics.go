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

// Package metrics exposes Prometheus gauges on the controller-runtime registry.
package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	crmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"

	v1 "github.com/wscoble/egress-range-controller/api/v1alpha1"
)

var (
	labels = []string{"namespace", "name"}
	// NeedsApproval is 1 when a change is queued for a human.
	NeedsApproval           = prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "egress_range_needs_approval", Help: "1 if NeedsApproval is True"}, labels)
	Quarantined             = prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "egress_range_quarantined", Help: "1 if a change is pending in quarantine"}, labels)
	SourceUnavailable       = prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "egress_range_source_unavailable", Help: "1 if the source is failing"}, labels)
	Alert24h                = prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "egress_range_source_unreachable_alert", Help: "1 once failures exceed unreachableAlertAfter"}, labels)
	EndpointOutsideEnforced = prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "egress_range_endpoint_outside_enforced", Help: "1 if a resolved endpoint is outside the enforced set (urgent)"}, labels)
	EnforcedCIDRs           = prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "egress_range_enforced_cidrs", Help: "number of enforced CIDRs"}, labels)
	PendingPromoteAfter     = prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "egress_range_pending_promote_after_seconds", Help: "unix time when pending may promote, 0 if none"}, labels)
	LastSuccess             = prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "egress_range_last_success_timestamp_seconds", Help: "unix time of last successful fetch"}, labels)
	Fetches                 = prometheus.NewCounterVec(prometheus.CounterOpts{Name: "egress_range_fetch_total", Help: "fetch attempts by result"}, append(labels, "result"))
)

func init() {
	crmetrics.Registry.MustRegister(NeedsApproval, Quarantined, SourceUnavailable, Alert24h, EndpointOutsideEnforced, EnforcedCIDRs, PendingPromoteAfter, LastSuccess, Fetches)
}

func b(c *metav1.Condition, reason string) float64 {
	if c != nil && c.Status == metav1.ConditionTrue && (reason == "" || c.Reason == reason) {
		return 1
	}
	return 0
}

// Observe updates gauges from status.
func Observe(er *v1.EgressRanges) {
	l := prometheus.Labels{"namespace": er.Namespace, "name": er.Name}
	st := &er.Status
	NeedsApproval.With(l).Set(b(meta.FindStatusCondition(st.Conditions, v1.ConditionNeedsApproval), ""))
	Quarantined.With(l).Set(b(meta.FindStatusCondition(st.Conditions, v1.ConditionQuarantined), ""))
	SourceUnavailable.With(l).Set(b(meta.FindStatusCondition(st.Conditions, v1.ConditionSourceUnavailable), ""))
	Alert24h.With(l).Set(b(meta.FindStatusCondition(st.Conditions, v1.ConditionSourceUnavailable), "AlertUnreachable24h"))
	EndpointOutsideEnforced.With(l).Set(b(meta.FindStatusCondition(st.Conditions, v1.ConditionEndpointOutsideEnforced), ""))
	EnforcedCIDRs.With(l).Set(float64(len(st.Enforced.CIDRs)))
	if st.Pending != nil {
		PendingPromoteAfter.With(l).Set(float64(st.Pending.PromoteAfter.Unix()))
	} else {
		PendingPromoteAfter.With(l).Set(0)
	}
	if st.LastSuccess != nil {
		LastSuccess.With(l).Set(float64(st.LastSuccess.Unix()))
	}
}
