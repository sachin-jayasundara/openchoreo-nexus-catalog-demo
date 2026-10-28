#!/bin/sh
# Removes the config layer added by allow-nexus-catalog-kinds.sh and restarts the portal.
set -eu

CM=nexus-catalog-demo-config
VOLUME=nexus-catalog-demo-config
FILE=app-config.nexus-demo.yaml

NS="${PORTAL_NAMESPACE:-$(kubectl get deploy -A -l app.kubernetes.io/component=backstage -o jsonpath='{.items[0].metadata.namespace}')}"
DEPLOY="${PORTAL_DEPLOYMENT:-$(kubectl get deploy -n "$NS" -l app.kubernetes.io/component=backstage -o jsonpath='{.items[0].metadata.name}')}"

# Zero-based index of the line matching $2 in the newline-separated output of jsonpath $1, or empty.
index_of() {
  kubectl -n "$NS" get deploy "$DEPLOY" -o jsonpath="$1" | grep -n -x -- "$2" | head -n 1 | cut -d: -f1 | awk '{ print $1 - 1 }'
}

ARG=$(index_of '{range .spec.template.spec.containers[0].args[*]}{@}{"\n"}{end}' "$FILE")
MOUNT=$(index_of '{range .spec.template.spec.containers[0].volumeMounts[*]}{.name}{"\n"}{end}' "$VOLUME")
VOL=$(index_of '{range .spec.template.spec.volumes[*]}{.name}{"\n"}{end}' "$VOLUME")

OPS=""
add_op() { OPS="${OPS:+$OPS,}{\"op\":\"remove\",\"path\":\"$1\"}"; }
if [ -n "$ARG" ]; then
  add_op "/spec/template/spec/containers/0/args/$ARG"
  add_op "/spec/template/spec/containers/0/args/$((ARG - 1))"
fi
[ -n "$MOUNT" ] && add_op "/spec/template/spec/containers/0/volumeMounts/$MOUNT"
[ -n "$VOL" ] && add_op "/spec/template/spec/volumes/$VOL"

if [ -n "$OPS" ]; then
  kubectl -n "$NS" patch deploy "$DEPLOY" --type json -p "[$OPS]"
  kubectl -n "$NS" rollout status deploy "$DEPLOY" --timeout=300s
else
  echo "Config layer not found on $NS/$DEPLOY."
fi
kubectl -n "$NS" delete configmap "$CM" --ignore-not-found
