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

// Package controller wires the engine to Kubernetes.
package controller

import (
	"context"
	"fmt"
	"math/rand"
	"time"

	netv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	v1 "github.com/wscoble/egress-range-controller/api/v1alpha1"
	"github.com/wscoble/egress-range-controller/internal/engine"
	"github.com/wscoble/egress-range-controller/internal/metrics"
	"github.com/wscoble/egress-range-controller/internal/notify"
	"github.com/wscoble/egress-range-controller/internal/render"
)

// Reconciler reconciles EgressRanges.
type Reconciler struct {
	client.Client
	Scheme   *runtime.Scheme
	Recorder record.EventRecorder
	Observer *Observer
	Webhook  *notify.Webhook
	Now      func() time.Time
	Engine   *engine.Engine
}

// +kubebuilder:rbac:groups=egress.greybeard.support,resources=egressranges,verbs=get;list;watch
// +kubebuilder:rbac:groups=egress.greybeard.support,resources=egressranges/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=networking.k8s.io,resources=networkpolicies,verbs=get;list;watch;create;update;patch
// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch

// Reconcile implements reconcile.Reconciler.
func (r *Reconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	lg := log.FromContext(ctx)
	now := r.now()
	var er v1.EgressRanges
	if err := r.Get(ctx, req.NamespacedName, &er); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	cfg, err := engine.ConfigFromSpec(er.Spec)
	if err != nil {
		meta.SetStatusCondition(&er.Status.Conditions, metav1.Condition{Type: v1.ConditionSynced, Status: metav1.ConditionFalse, Reason: "InvalidSpec", Message: err.Error(), LastTransitionTime: metav1.NewTime(now)})
		_ = r.Status().Update(ctx, &er)
		return ctrl.Result{}, nil
	}
	ann := engine.Annotations{
		ApproveDigest: er.Annotations[v1.AnnotationApproveDigest],
		RejectDigest:  er.Annotations[v1.AnnotationRejectDigest],
	}
	due := er.Status.NextFetch == nil || !now.Before(er.Status.NextFetch.Time) || er.Status.ObservedGeneration != er.Generation
	var obs *engine.Observation
	if due {
		obs = r.Observer.Observe(ctx, er.Spec, cfg)
	}
	st := er.Status.DeepCopy()
	evs := r.engine().Step(st, cfg, ann, obs, now, er.Generation)
	er.Status = *st
	if obs != nil && st.LastFetch != nil {
		metrics.Fetches.WithLabelValues(er.Namespace, er.Name, st.LastFetch.Result).Inc()
	}

	// Render the NetworkPolicy strictly from status.enforced.
	np := &netv1.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: render.PolicyName(&er), Namespace: er.Namespace}}
	_, rerr := controllerutil.CreateOrUpdate(ctx, r.Client, np, func() error {
		render.Mutate(np, &er)
		return controllerutil.SetControllerReference(&er, np, r.Scheme)
	})
	if rerr != nil {
		meta.SetStatusCondition(&er.Status.Conditions, metav1.Condition{Type: v1.ConditionSynced, Status: metav1.ConditionFalse, Reason: "RenderFailed", Message: rerr.Error(), LastTransitionTime: metav1.NewTime(now), ObservedGeneration: er.Generation})
	} else {
		meta.SetStatusCondition(&er.Status.Conditions, metav1.Condition{Type: v1.ConditionSynced, Status: metav1.ConditionTrue, Reason: "Rendered", Message: fmt.Sprintf("%s rendered from %s (%d CIDRs)", np.Name, er.Status.Enforced.Digest, len(er.Status.Enforced.CIDRs)), LastTransitionTime: metav1.NewTime(now), ObservedGeneration: er.Generation})
	}

	if err := r.Status().Update(ctx, &er); err != nil {
		if apierrors.IsConflict(err) {
			return ctrl.Result{Requeue: true}, nil
		}
		return ctrl.Result{}, err
	}
	for _, e := range evs {
		r.Recorder.Event(&er, e.Type, e.Reason, e.Message)
		if e.Type == "Warning" || e.Reason == "Promoted" || e.Reason == "QuarantineStarted" || e.Reason == "QuarantineReset" || e.Reason == "VerificationComposed" {
			p := notify.Payload{Namespace: er.Namespace, Name: er.Name, Type: e.Type, Reason: e.Reason, Message: e.Message, Enforced: er.Status.Enforced.Digest, Time: now}
			if er.Status.Pending != nil {
				p.Pending = er.Status.Pending.Digest
			}
			if err := r.Webhook.Send(ctx, er.Spec.NotifyWebhook, p); err != nil {
				lg.Error(err, "webhook notify failed", "reason", e.Reason)
			}
		}
	}
	metrics.Observe(&er)
	if rerr != nil {
		return ctrl.Result{}, rerr
	}
	after := time.Minute
	if er.Status.NextFetch != nil {
		after = er.Status.NextFetch.Sub(now)
	}
	if after < time.Second {
		after = time.Second
	}
	lg.Info("reconciled", "enforced", er.Status.Enforced.Digest, "pendingSet", er.Status.Pending != nil, "fetched", obs != nil, "requeueAfter", after.String())
	return ctrl.Result{RequeueAfter: after}, nil
}

func (r *Reconciler) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

func (r *Reconciler) engine() *engine.Engine {
	if r.Engine == nil {
		r.Engine = &engine.Engine{Rand: rand.New(rand.NewSource(time.Now().UnixNano()))}
	}
	return r.Engine
}

// SetupWithManager registers the controller. Status-only writes do not retrigger
// (generation/annotation predicates); owned NetworkPolicy drift does.
func (r *Reconciler) SetupWithManager(mgr ctrl.Manager) error {
	if r.Webhook == nil {
		r.Webhook = &notify.Webhook{}
	}
	if r.Observer == nil {
		r.Observer = &Observer{}
	}
	return ctrl.NewControllerManagedBy(mgr).
		For(&v1.EgressRanges{}, builder.WithPredicates(predicate.Or(predicate.GenerationChangedPredicate{}, predicate.AnnotationChangedPredicate{}))).
		Owns(&netv1.NetworkPolicy{}).
		Named("egressranges").
		Complete(r)
}
