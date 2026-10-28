# OpenChoreo Nexus Catalog demo

Sanitized, synthetic catalog data for evaluating whether OpenChoreo's
Backstage-based portal can represent the Nexus Catalog model.

This repository contains no IFS source code, credentials, internal URLs, or
real vulnerability findings.

## Import into OpenChoreo

Use this raw URL in **Catalog → Register an existing catalog entity**:

```text
https://raw.githubusercontent.com/sac3478/openchoreo-nexus-catalog-demo/main/catalog-info.yaml
```

The imported model maps:

- Nexus platform capability → Backstage `Domain`
- Nexus application → Backstage `System`
- Nexus service → Backstage `Component`
- Nexus team → Backstage `Group`
- API contract → Backstage `API`

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
