#!/usr/bin/env bash
set -euo pipefail

# Benign app with a misconfiguration: it runs the same reads as
# category3/normal.sh, then tries to read a TLS Secret it was never granted.
# Expected: 5 allowed reads, then 3 x 403 on secrets/app-tls.

NS="${NS:-pbl-security}"
SA="pbl-crypto-platform-app"
ensure_lab_identity() {
  kubectl apply -f - >/dev/null <<YAML
apiVersion: v1
kind: ServiceAccount
metadata:
  name: pbl-crypto-platform-app
  namespace: ${NS}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: pbl-crypto-platform-reader
  namespace: ${NS}
rules:
  - apiGroups: [""]
    resources: ["pods", "services", "configmaps"]
    verbs: ["get", "list"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: pbl-crypto-platform-reader
  namespace: ${NS}
subjects:
  - kind: ServiceAccount
    name: pbl-crypto-platform-app
    namespace: ${NS}
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: pbl-crypto-platform-reader
YAML
  TOKEN="$(kubectl -n "${NS}" create token "${SA}" --duration=10m)"
  SERVER="$(kubectl config view --minify -o jsonpath='{.clusters[0].cluster.server}')"
  K=(kubectl --kubeconfig=/dev/null --server="${SERVER}" --insecure-skip-tls-verify --token="${TOKEN}" -n "${NS}")
}

ensure_lab_identity

echo "[1/5] List Pods using ${SA}."
"${K[@]}" get pods
echo "[2/5] List Services using ${SA}."
"${K[@]}" get services
echo "[3/5] List ConfigMaps using ${SA}."
"${K[@]}" get configmaps
echo "[4/5] Read the frontend Pod using ${SA}."
POD="$("${K[@]}" get pod -l app=frontend -o jsonpath='{.items[0].metadata.name}')"
"${K[@]}" get pod "${POD}" -o name

echo "[5/5] Misconfigured app tries to read Secret app-tls (no RBAC grant)."
for i in 1 2 3; do
  echo "attempt=${i}/3"
  "${K[@]}" get secret app-tls -o name || true
done

echo "Audit identity: system:serviceaccount:${NS}:${SA}"
