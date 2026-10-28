# Nexus Catalog on OpenChoreo (demo)

The Nexus Catalog model imported into the OpenChoreo portal through catalog-import: platform capabilities, applications, services, teams, Service Readiness by stage, per-service vulnerability summaries and a global vulnerability summary.

- Import URL: `https://github.com/sachin-jayasundara/openchoreo-nexus-catalog-demo/blob/main/catalog-info.yaml`
- Insights dashboard: https://sachin-jayasundara.github.io/openchoreo-nexus-catalog-demo/

## What is real and what is mock

| Data | Source |
|---|---|
| Counts, service types, lifecycles, availability, ownership and parent relations of platform capabilities, applications, services and teams | Nexus Catalog snapshot |
| Names and descriptions | Pseudonymized, for example application `amber-falcon`, platform capability `aurora`, service `amber-falcon-api`, team `bravo` |
| Service Readiness by stage and missing criteria | Computed from the catalog's `service-readiness/criteria.yaml`, attestations and exclusions with the same rules as `readiness-validator` |
| Vulnerabilities, deployments, clusters | Mock, generated deterministically per service |

Not published: real names and descriptions, emails, Entra group IDs, Jira projects, contributors, repository and documentation links, readiness evidence and documentation bodies.

## How the Nexus model maps to the portal

OpenChoreo's portal labels Backstage Domains as **Namespaces** and Systems as **Projects**.

| Nexus Catalog | Portal entity | Where to find it |
|---|---|---|
| Platform capability | Project (System) in namespace `nexus-platform-capabilities` | Catalog > Project |
| Application | Project (System) in namespace `nexus-applications` | Catalog > Project |
| Service | Component in its parent's namespace, or `nexus-standalone-services` | Catalog > Component. The description starts with the vulnerability counts and current-stage readiness |
| Team | Group in namespace `nexus-teams` | Catalog > Group. The ownership card lists what the team owns |
| Service Readiness and security insights | Resource `<service>-insights` (type `service-insights`) in `nexus-insights` | Linked from each service's relations graph. Lists readiness per stage, missing criteria and vulnerability counts |
| Global vulnerability summary | Resource `nexus-vulnerability-summary` | Catalog > Resource |
| Service Readiness summary | Resource `nexus-service-readiness-summary` | Catalog > Resource |
| Runs on | Resources `nexus-{dev,tst,prd}-cluster`, linked by `dependsOn` | Service relations graph |

Tags support filtering and search: `readiness:ready`, `readiness:not-ready`, `readiness:not-applicable`, `vulns:critical`, `vulns:high`, `lifecycle:<value>`.

## Load it into the OpenChoreo sandbox

The sandbox's catalog rules reject `Group` (and `Domain`) entities from catalog-import. The script adds a Backstage config layer that allows them. It only changes the sandbox's own portal deployment and restarts it.

1. In the sandbox web terminal:

   ```sh
   curl -fsSL https://raw.githubusercontent.com/sachin-jayasundara/openchoreo-nexus-catalog-demo/main/sandbox/allow-nexus-catalog-kinds.sh | sh
   ```

2. Reload the console and sign in again if asked. Open **Catalog > Register existing component** (or `/catalog-import`), paste the import URL above, select **Analyze** and then **Import**.
3. Processing takes about a minute. Start at **Catalog > Resource > Nexus · Global vulnerability summary**, or **Catalog > Project** for the capabilities and applications.

To undo the change: `curl -fsSL https://raw.githubusercontent.com/sachin-jayasundara/openchoreo-nexus-catalog-demo/main/sandbox/revert-nexus-catalog-kinds.sh | sh`. To remove the data, unregister the `nexus-catalog-demo` location from its entity page.

If the script cannot change the portal, import `catalog-info-without-domains-groups.yaml` instead. It leaves out teams and namespaces, so owner links do not resolve.

## Limits of the stock portal

- Imported Components still show OpenChoreo's Build, Deploy and runtime cards, which report that no OpenChoreo metadata exists, because the services are not deployed by OpenChoreo.
- Readiness and vulnerability cards on the service page, and a global dashboard page inside the portal, need a custom Backstage frontend plugin in a self-hosted portal image. Until then the `-insights` Resources, the summary Resources and the dashboard carry that information.
- TechDocs is enabled but builds with Docker, which the hosted portal cannot run, so the demo only lists which documents each platform capability has.

## Regenerate

```sh
python tools/generate_from_nexus_catalog.py --catalog ../nexus-catalog --out . --pseudonymize \
  --dashboard-url https://sachin-jayasundara.github.io/openchoreo-nexus-catalog-demo/
```

This writes `catalog/*.yaml`, `docs/data.json` and `docs/index.html`. Without `--pseudonymize` the output keeps the real names and links to the Bitbucket repositories and documents; keep that output private.
