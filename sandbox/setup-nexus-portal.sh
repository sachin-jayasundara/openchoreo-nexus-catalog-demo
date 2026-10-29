#!/bin/sh
# Turns the OpenChoreo sandbox portal into the Nexus demo portal. Run it in the sandbox web terminal only.
#   1. Starts the live cluster demo: four namespaces that stand in for the Nexus clusters, a pause
#      container per mock Argo CD Application of the live services, and the collector that reads
#      them from the Kubernetes API and joins them with the mock GitOps versions and ACR findings.
#   2. Adds a Backstage config layer: catalog.rules that accept Domain, Group and User entities,
#      read access to the collector's catalog file, and the /nexus-insights proxy endpoint the
#      insights plugin reads from.
#   3. Replaces the portal image with the OpenChoreo portal built with the Nexus insights plugin
#      (.github/workflows/portal-image.yml). The original image is kept in an annotation.
# The portal restarts once. With the default SQLite database, entities imported earlier are gone
# after the restart; OpenChoreo's own entities sync back automatically.
# Undo everything with revert-nexus-portal.sh.
set -eu

BASE="${DEMO_BASE_URL:-https://raw.githubusercontent.com/sachin-jayasundara/openchoreo-nexus-catalog-demo/main}"
IMAGE="${PORTAL_IMAGE:-ghcr.io/sachin-jayasundara/openchoreo-portal-nexus:v1.2.2-nexus}"
CM=nexus-catalog-demo-config
VOLUME=nexus-catalog-demo-config
FILE=app-config.nexus-demo.yaml
ORIGINAL=nexus.demo/original-image
LIVE_HOST=nexus-live-collector.nexus-demo-live.svc.cluster.local

NS="${PORTAL_NAMESPACE:-$(kubectl get deploy -A -l app.kubernetes.io/component=backstage -o jsonpath='{.items[0].metadata.namespace}')}"
DEPLOY="${PORTAL_DEPLOYMENT:-$(kubectl get deploy -n "$NS" -l app.kubernetes.io/component=backstage -o jsonpath='{.items[0].metadata.name}')}"
if [ -z "$NS" ] || [ -z "$DEPLOY" ]; then
  echo "Portal deployment not found. Set PORTAL_NAMESPACE and PORTAL_DEPLOYMENT." >&2
  exit 1
fi
CONTAINER=$(kubectl -n "$NS" get deploy "$DEPLOY" -o jsonpath='{.spec.template.spec.containers[0].name}')
if [ "$CONTAINER" != "backstage" ]; then
  echo "Expected container 'backstage' first in $NS/$DEPLOY, found '$CONTAINER'. Nothing changed." >&2
  exit 1
fi
CURRENT=$(kubectl -n "$NS" get deploy "$DEPLOY" -o jsonpath='{.spec.template.spec.containers[0].image}')
SAVED=$(kubectl -n "$NS" get deploy "$DEPLOY" -o jsonpath="{.metadata.annotations.nexus\.demo/original-image}")
echo "Portal: $NS/$DEPLOY ($CURRENT)"
if [ -z "$SAVED" ]; then
  case "$CURRENT" in
    *1.2.2*) ;;
    *) echo "Warning: the Nexus portal image is built from OpenChoreo v1.2.2 and this portal runs $CURRENT." >&2 ;;
  esac
fi

echo
echo "== Live cluster demo"
kubectl apply -f "$BASE/sandbox/live/nexus-live-cluster-demo.yaml"
kubectl -n nexus-demo-live rollout status deploy/nexus-live-collector --timeout=300s

echo
echo "== Portal config layer and image"
kubectl -n "$NS" apply -f - <<EOF
apiVersion: v1
kind: ConfigMap
metadata:
  name: $CM
  labels:
    nexus.demo/dataset: nexus-catalog
data:
  $FILE: |
    backend:
      reading:
        allow:
          - host: $LIVE_HOST
    proxy:
      endpoints:
        /nexus-insights:
          target: http://$LIVE_HOST
          allowedMethods: [GET]
    catalog:
      rules:
        - allow: [Component, System, Domain, API, Resource, Location, User, Group, Environment, Template]
EOF

[ -n "$SAVED" ] || kubectl -n "$NS" annotate deploy "$DEPLOY" "$ORIGINAL=$CURRENT"
OPS="{\"op\":\"replace\",\"path\":\"/spec/template/spec/containers/0/image\",\"value\":\"$IMAGE\"}"
if ! kubectl -n "$NS" get deploy "$DEPLOY" -o jsonpath='{.spec.template.spec.containers[0].args}' | grep -q "$FILE"; then
  OPS="$OPS,
    {\"op\":\"add\",\"path\":\"/spec/template/spec/volumes/-\",\"value\":{\"name\":\"$VOLUME\",\"configMap\":{\"name\":\"$CM\"}}},
    {\"op\":\"add\",\"path\":\"/spec/template/spec/containers/0/volumeMounts/-\",\"value\":{\"name\":\"$VOLUME\",\"mountPath\":\"/app/$FILE\",\"subPath\":\"$FILE\",\"readOnly\":true}},
    {\"op\":\"add\",\"path\":\"/spec/template/spec/containers/0/args/-\",\"value\":\"--config\"},
    {\"op\":\"add\",\"path\":\"/spec/template/spec/containers/0/args/-\",\"value\":\"$FILE\"}"
fi
if [ "$CURRENT" = "$IMAGE" ] && kubectl -n "$NS" get deploy "$DEPLOY" -o jsonpath='{.spec.template.spec.containers[0].args}' | grep -q "$FILE"; then
  echo "Image and config layer already in place; restarting the portal to reload the config."
  kubectl -n "$NS" rollout restart deploy "$DEPLOY"
else
  kubectl -n "$NS" patch deploy "$DEPLOY" --type json -p "[$OPS]"
fi
if ! kubectl -n "$NS" rollout status deploy "$DEPLOY" --timeout=600s; then
  echo "The portal did not become ready. Check: kubectl -n $NS describe pod -l app.kubernetes.io/component=backstage" >&2
  echo "Undo with revert-nexus-portal.sh." >&2
  exit 1
fi

echo
kubectl get deploy -A -l nexus.demo/component -o custom-columns='CLUSTER:.metadata.namespace,SERVICE:.metadata.name,READY:.status.readyReplicas,VERSION:.metadata.annotations.nexus\.demo/chart-version'
echo
echo "Done. In the console open Catalog > Register existing component and import both:"
echo "  https://github.com/sachin-jayasundara/openchoreo-nexus-catalog-demo/blob/main/catalog-info.yaml"
echo "  http://$LIVE_HOST/catalog.yaml"
echo "Then open 'Nexus insights' in the sidebar, or the 'Nexus insights' tab of any Nexus service or project."
