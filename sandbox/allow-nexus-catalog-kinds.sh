#!/bin/sh
# Adds a Backstage config layer to the OpenChoreo portal so that catalog-import accepts
# Domain, Group and User entities. Run it in the OpenChoreo sandbox web terminal only.
#
# The chart starts the portal with several --config files and Backstage replaces arrays
# from later files, so this layer is appended last and only sets catalog.rules.
# The portal restarts. With the default SQLite database, entities that were imported
# earlier are gone after the restart; OpenChoreo's own entities sync back automatically.
set -eu

CM=nexus-catalog-demo-config
VOLUME=nexus-catalog-demo-config
FILE=app-config.nexus-demo.yaml

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
echo "Portal: $NS/$DEPLOY"

kubectl -n "$NS" apply -f - <<EOF
apiVersion: v1
kind: ConfigMap
metadata:
  name: $CM
  labels:
    demo.ifs.com/dataset: nexus-catalog
data:
  $FILE: |
    catalog:
      rules:
        - allow: [Component, System, Domain, API, Resource, Location, User, Group, Environment, Template]
EOF

if kubectl -n "$NS" get deploy "$DEPLOY" -o jsonpath='{.spec.template.spec.containers[0].args}' | grep -q "$FILE"; then
  echo "Config layer already present; restarting the portal to reload it."
  kubectl -n "$NS" rollout restart deploy "$DEPLOY"
else
  kubectl -n "$NS" patch deploy "$DEPLOY" --type json -p "[
    {\"op\":\"add\",\"path\":\"/spec/template/spec/volumes/-\",\"value\":{\"name\":\"$VOLUME\",\"configMap\":{\"name\":\"$CM\"}}},
    {\"op\":\"add\",\"path\":\"/spec/template/spec/containers/0/volumeMounts/-\",\"value\":{\"name\":\"$VOLUME\",\"mountPath\":\"/app/$FILE\",\"subPath\":\"$FILE\",\"readOnly\":true}},
    {\"op\":\"add\",\"path\":\"/spec/template/spec/containers/0/args/-\",\"value\":\"--config\"},
    {\"op\":\"add\",\"path\":\"/spec/template/spec/containers/0/args/-\",\"value\":\"$FILE\"}
  ]"
fi

kubectl -n "$NS" rollout status deploy "$DEPLOY" --timeout=300s
echo
echo "Done. In the console open Catalog > Register existing component and import:"
echo "  https://github.com/sachin-jayasundara/openchoreo-nexus-catalog-demo/blob/main/catalog-info.yaml"
