# Nexus Catalog on OpenChoreo (demo)

The Nexus Catalog model inside the OpenChoreo portal: platform capabilities, applications, services, teams, Service Readiness by stage, and deployment and vulnerability insights joined from GitOps, Argo CD and ACR vulnerability reports. Everything is pseudonymized.

- **Nexus insights plugin** (`portal/`): a portal page and a tab on every Nexus service and project, compiled into a custom OpenChoreo portal image, `ghcr.io/sachin-jayasundara/openchoreo-portal-nexus`.
- **Catalog import URL**: `https://github.com/sachin-jayasundara/openchoreo-nexus-catalog-demo/blob/main/catalog-info.yaml`.
- **Standalone dashboard** with the same data, for viewing without a sandbox: https://sachin-jayasundara.github.io/openchoreo-nexus-catalog-demo/.

The portal only reads and reports. Git stays the source of truth for versions, Argo CD stays the deployer, and Defender for Containers stays the scanner.

## What is real and what is mock

| Data | Source |
|---|---|
| Counts, service types, lifecycles, availability, ownership and parent relations of platform capabilities, applications, services and teams | Nexus Catalog snapshot |
| Names and descriptions | Pseudonymized, for example application `amber-falcon`, platform capability `onyx`, service `onyx-api`, team `bravo` |
| Service Readiness by stage and missing criteria | Computed from the catalog's `service-readiness/criteria.yaml`, attestations and exclusions with the same rules as `readiness-validator` |
| Desired versions | Mock GitOps folder `mock-sources/gitops/<stage>/rings/<ring>/chart-versions/<service>.yaml`, the same layout and `version: 0.1.0+<commit>` format as the real GitOps repository |
| Deployed versions, health and sync | Mock Argo CD exports `mock-sources/argocd/<cluster>.json`: one Application per service and cluster, with `status.sync`, `status.health`, `status.history`, `operationState` and `summary.images` as Argo CD reports them |
| Vulnerabilities | Mock Defender for Containers export `mock-sources/acr/defender-findings.json`, in the shape the Azure Resource Graph query in `mock-sources/acr/query.kql` returns. The CVE IDs are real; the affected packages and versions are illustrative |
| Live cluster state | Six `onyx` services running as pause containers in four sandbox namespaces that stand in for the clusters, read from the Kubernetes API by the collector in `tools/insights_collector.py` |

Not published: real names and descriptions, emails, Entra group IDs, Jira projects, contributors, repository and documentation links, readiness evidence and documentation bodies.

## How the insights are computed

For every service and cluster, the collector compares the version in GitOps with the version Argo CD last deployed, and then looks up the ACR findings for the image running there. Each environment gets one state, in this order of severity:

| State | Meaning |
|---|---|
| Degraded | Argo CD reports the application unhealthy, or the pod cannot start, for example `ImagePullBackOff` |
| Version drift | The running version differs from GitOps, for example after a failed sync |
| Not deployed | GitOps has a version, but the cluster has no Application or workload |
| Progressing | A rollout of the GitOps version is still running |
| Not in GitOps | Something runs that GitOps does not list |
| In sync | The running version matches GitOps and the workload is healthy |

Vulnerability counts only include findings for images that are deployed, so a CVE that is fixed in the running release no longer counts. Findings record the clusters they run on, which shows production exposure.

## What the portal shows

OpenChoreo's portal labels Backstage Domains as **Namespaces** and Systems as **Projects**.

| Where | What |
|---|---|
| Sidebar > **Nexus insights** | Overview with deployment and vulnerability totals per cluster, the highest-risk services and the most widespread CVEs. Also tabs for the deployment matrix (filter by state and cluster), vulnerabilities by CVE and team, Service Readiness, and the live sandbox cluster |
| Service page > **Overview** | Card with deployment state, vulnerability counts and readiness. OpenChoreo's build and deploy cards are hidden for Nexus services |
| Service page > **Nexus insights** | Version, health and state per cluster. Live Kubernetes state for the onyx services. Findings with package, installed and fixed version, and clusters. Readiness per stage with the missing criteria |
| Project page > **Nexus insights** | The same for every service of a platform capability or application |
| Catalog > Component | Services, with tags `deploy:<state>`, `vulns:critical`, `vulns:high`, `readiness:<state>` and `lifecycle:<value>` for filtering |
| Catalog > Group | Teams, with the ownership card |
| Catalog > Resource | `<service>-insights` per service, and `nexus-vulnerability-summary`, `nexus-deployment-summary`, `nexus-service-readiness-summary` and the cluster Resources. These carry the same information as markdown for portals without the plugin |
| Catalog > Resource > `<service>-live-status` | Live cluster status from the collector's catalog file, refreshed when the portal re-reads it |

The plugin reads the dataset through the portal's proxy at `/api/proxy/nexus-insights/data.json`. The collector serves `docs/data.json` with the live Kubernetes state merged into the onyx services, and refreshes it every 30 seconds.

## Run it in the OpenChoreo sandbox

The setup script only changes the sandbox's own portal deployment. Run it in the sandbox web terminal, not against another cluster.

1. Start the live demo and switch the portal to the Nexus image:

   ```sh
   curl -fsSL https://raw.githubusercontent.com/sachin-jayasundara/openchoreo-nexus-catalog-demo/main/sandbox/setup-nexus-portal.sh | sh
   ```

   The script does three things:
   - It starts the collector and the mock workloads.
   - It adds a Backstage config layer with three entries: catalog rules that accept Domain and Group entities, read access to the collector, and the `/nexus-insights` proxy endpoint.
   - It replaces the portal image, keeping the original in the annotation `nexus.demo/original-image`, and restarts the portal once.

2. Reload the console and sign in again if asked. Open **Catalog > Register existing component** (or `/catalog-import`). Import the catalog URL above, then `http://nexus-live-collector.nexus-demo-live.svc.cluster.local/catalog.yaml`.
3. Processing takes about a minute. Open **Nexus insights** in the sidebar, or the **Nexus insights** tab of any service.

To watch the live view change, break a workload or fix it, and see the state within 30 seconds:

```sh
kubectl -n nexus-prd-euno-01 set image deploy/onyx-worker app=registry.k8s.io/pause:nexus-demo-missing-tag   # Degraded
kubectl -n nexus-prd-euno-01 scale deploy/onyx-worker --replicas=0                                           # Suspended
kubectl -n nexus-dev-euno-01 set image deploy/onyx-api app=registry.k8s.io/pause:3.10                        # healthy again
```

To undo everything: `curl -fsSL https://raw.githubusercontent.com/sachin-jayasundara/openchoreo-nexus-catalog-demo/main/sandbox/revert-nexus-portal.sh | sh`. It restores the original image and configuration, and deletes the demo namespaces. To remove the imported data, unregister the two locations from their entity pages.

With the default SQLite database, the restart drops entities imported earlier, so import after setup.

## Build the portal image

`.github/workflows/portal-image.yml` builds the image whenever `portal/` changes, or on demand:
1. It checks out `openchoreo/backstage-plugins` at `v1.2.2`.
2. It runs `portal/apply_overlay.py`, which adds the plugin to `packages/app` and wires it into `App.tsx`, `Root.tsx` and `EntityPage.tsx`.
3. It type-checks with `yarn tsc`.
4. It builds the upstream `packages/backend/Dockerfile` unchanged.

The overlay script stops if an anchor it edits is missing, so a new OpenChoreo release needs a checked update instead of a broken page. Tags are `v1.2.2-nexus` and `v1.2.2-nexus.<run number>`.

## Limits

- This is a demo. A production version would replace the collector with a Backstage backend plugin, or a service in the platform cluster, that reads the real sources:
  - the GitOps repository;
  - the Argo CD API, or the `Application` resources of each cluster;
  - Azure Resource Graph with the query in `mock-sources/acr/query.kql`.
- The live view covers six services. The other services use the Argo CD exports, which are generated once.
- The custom image has to be rebuilt for every OpenChoreo release, as with any Backstage portal that adds frontend plugins.
- TechDocs is enabled, but it builds with Docker, which the hosted portal cannot run. The demo only lists which documents each platform capability has.

## Regenerate

```sh
python tools/generate_from_nexus_catalog.py --catalog ../nexus-catalog --out . --pseudonymize --write-mock-sources \
  --dashboard-url https://sachin-jayasundara.github.io/openchoreo-nexus-catalog-demo/
```

This command writes the following:
- `catalog/*.yaml`;
- `docs/data.json` and `docs/index.html`;
- `mock-sources/`;
- the sandbox manifest `sandbox/live/nexus-live-cluster-demo.yaml`.

To join real exports instead of mock ones, leave out `--write-mock-sources` and pass `--sources <dir>` with the same layout. Without `--pseudonymize` the output keeps the real names and links to the Bitbucket repositories and documents; keep that output private.
