# OpenChoreo Nexus Catalog demo

Sanitized, synthetic catalog data for evaluating whether OpenChoreo's
Backstage-based portal can represent the Nexus Catalog model.

This repository contains no IFS source code, credentials, internal URLs, or
real vulnerability findings.

## Load into OpenChoreo

For the OpenChoreo sandbox, create native OpenChoreo resources from its web
terminal:

```bash
kubectl apply -f https://raw.githubusercontent.com/sachin-jayasundara/openchoreo-nexus-catalog-demo/main/openchoreo-resources.yaml
```

The OpenChoreo catalog-sync provider then projects these resources into the
Backstage catalog:

- Kubernetes/OpenChoreo Namespace → Backstage `Domain`
- OpenChoreo Project → Backstage `System`
- OpenChoreo Component → Backstage `Component`
- OpenChoreo API definition → Backstage `API`

This is the supported path for entities that should participate in OpenChoreo
project, component, build, deployment, and runtime views. The catalog import
wizard only registers external Backstage entities. Those entities do not have
the OpenChoreo annotations required by the OpenChoreo-specific tabs.

Verify the native resources:

```bash
kubectl get projects,components -n default \
  -l demo.ifs.com/dataset=nexus-catalog-mock
```

Allow approximately 30 seconds for catalog synchronization, then refresh the
Catalog page.

Cleanup:

```bash
kubectl delete projects,components -n default \
  -l demo.ifs.com/dataset=nexus-catalog-mock
```

`catalog-info.yaml` remains in this repository solely to demonstrate external
Backstage entities. The hosted sandbox's URL-import policy may reject entity
kinds that are not globally enabled. Production team synchronization requires
an organization provider and explicit `Group`/`User` catalog rules.

## Vulnerability demonstration

Each mock service has synthetic vulnerability counts in
`nexus.ifs.com/*` catalog annotations. `vulnerability-summary.json` contains
the same records plus global totals.

The standard OpenChoreo catalog can import and retain this metadata, but it
does not automatically render the Nexus service-readiness and vulnerability
screens. Matching those screens requires a custom Backstage frontend/backend
plugin that:

1. reads the per-service annotations or a vulnerability API;
2. renders a service-level vulnerability card;
3. aggregates all visible services into a global dashboard;
4. applies catalog permissions when calculating totals;
5. links findings back to the authoritative scanner.

The included counts are synthetic and must not be treated as security
evidence.
