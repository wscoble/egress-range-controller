#!/usr/bin/env bash
# Regenerates deploy/all.yaml from config/overlays/proton-example in apply order.
set -euo pipefail
kustomize build config/overlays/proton-example | python3 -c '
import sys, yaml
docs = [d for d in yaml.safe_load_all(sys.stdin) if d]
order = {"Namespace":0,"CustomResourceDefinition":1,"Role":2,"RoleBinding":3,"ServiceAccount":4,"NetworkPolicy":5,"Deployment":6,"EgressRanges":7}
docs.sort(key=lambda d: (order[d["kind"]], d["metadata"]["name"] != "egress-range-controller"))
print("""# egress-range-controller 0.1.0: Proton Bridge example, namespace `mail`.
# Generated from config/overlays/proton-example (make deploy-bundle). Order:
# Namespace, CRD, RBAC, ServiceAccount, controller NetworkPolicy, Deployment, EgressRanges.
# BEFORE APPLYING: replace the 192.0.2.10/32 placeholder in the controller
# NetworkPolicy with your API server endpoint (kubectl get endpoints kubernetes -n default).""")
print("---\n" + "---\n".join(yaml.safe_dump(d, sort_keys=False) for d in docs), end="")
' > deploy/all.yaml
