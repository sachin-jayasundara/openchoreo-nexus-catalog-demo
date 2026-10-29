#!/usr/bin/env python3
"""Generate an OpenChoreo (Backstage) catalog and an insights dashboard from a Nexus Catalog checkout.

Readiness is evaluated with the same rules as nexus-ci/src/readiness-validator. Deployment status,
versions and vulnerabilities come from tools/insights_collector.py joining mock exports of GitOps,
Argo CD and Azure Resource Graph (Defender for Containers) in mock-sources/.

Never copied: team emails, Entra group IDs, Jira projects, contributors, readiness evidence
links, exclusion references and documentation bodies.
"""

import argparse
import datetime as dt
import glob
import hashlib
import json
import os
import re
import subprocess
from collections import Counter

import yaml

import insights_collector as ic
import mock_sources

STAGES = ["preview", "early-access", "general-availability"]
STAGE_LABELS = {"preview": "Preview", "early-access": "Early access", "general-availability": "General availability"}
SEVERITIES = ["critical", "high", "medium", "low"]

NS_CAPABILITIES = "nexus-platform-capabilities"
NS_APPLICATIONS = "nexus-applications"
NS_STANDALONE = "nexus-standalone-services"
NS_TEAMS = "nexus-teams"
NS_INSIGHTS = "nexus-insights"
NS_RUNTIME = "nexus-runtime"

# Mock clusters. "lag" is how many releases a cluster may trail the previous one in promotion order.
CLUSTERS = {
    "nexus-dev-euno-01": {"title": "DEV euno-01", "stage": "dev", "ring": "one", "region": "North Europe", "lag": [0]},
    "nexus-tst-euno-01": {"title": "TST euno-01", "stage": "tst", "ring": "one", "region": "North Europe", "lag": [0, 0, 1]},
    "nexus-prd-euno-01": {"title": "PRD euno-01 (ring one)", "stage": "prd", "ring": "one", "region": "North Europe", "lag": [0, 1, 1, 2]},
    "nexus-prd-usea-01": {"title": "PRD usea-01 (ring two)", "stage": "prd", "ring": "two", "region": "East US", "lag": [0, 0, 1]},
}
CLUSTERS_BY_LIFECYCLE = {
    "test": ["nexus-dev-euno-01"],
    "staging": ["nexus-dev-euno-01", "nexus-tst-euno-01"],
    "production": list(CLUSTERS),
}
LIVE_SCENARIOS = ["in-sync", "sync-failed", "in-sync", "in-sync", "degraded", "in-sync", "not-deployed", "in-sync"]
LIVE_NAMESPACE = "nexus-demo-live"
LIVE_HOST = f"nexus-live-collector.{LIVE_NAMESPACE}.svc.cluster.local"
PAUSE_IMAGE = "registry.k8s.io/pause:3.10"
BROKEN_IMAGE = "registry.k8s.io/pause:nexus-demo-missing-tag"

ENTITY_NAME = re.compile(r"^([a-zA-Z0-9]+[-_.])*[a-zA-Z0-9]+$")
TAG = re.compile(r"^[a-z0-9:+#]+(-[a-z0-9:+#]+)*$")
PERIOD = re.compile(r"^([1-9][0-9]*)([dwy])$")


def load_dir(root, name):
    entries = {}
    for path in sorted(glob.glob(os.path.join(root, name, "*.yaml"))):
        with open(path, encoding="utf-8") as f:
            entries[os.path.splitext(os.path.basename(path))[0]] = yaml.safe_load(f) or {}
    return entries


def as_datetime(value):
    if value is None or value == "":
        return None
    if isinstance(value, dt.datetime):
        return value if value.tzinfo else value.replace(tzinfo=dt.timezone.utc)
    if isinstance(value, dt.date):
        return dt.datetime(value.year, value.month, value.day, tzinfo=dt.timezone.utc)
    return dt.datetime.fromisoformat(str(value).replace("Z", "+00:00"))


def period_end(start, period):
    match = PERIOD.match(period or "")
    if not match:
        raise ValueError(f"invalid period {period!r}")
    n, unit = int(match.group(1)), match.group(2)
    if unit == "y":
        try:
            return start.replace(year=start.year + n)
        except ValueError:
            return start.replace(year=start.year + n, day=28)
    return start + dt.timedelta(days=n * (7 if unit == "w" else 1))


def evaluate_criterion(crit, attestation, exclusion, service_type, stage, now):
    enforcement = crit.get("enforcement") or {}
    if service_type not in (enforcement.get("service-types") or []) or stage not in (enforcement.get("availability") or []):
        return None
    problems = []
    if attestation is not None:
        if not attestation.get("evidence"):
            problems.append("no evidence")
        attested_at = as_datetime(attestation.get("attestedAt"))
        if attested_at is None:
            problems.append("no attestedAt timestamp")
        elif enforcement.get("span") == "periodic":
            end = period_end(attested_at, enforcement.get("period"))
            if now >= end:
                problems.append(f"expired on {end.date().isoformat()}")
        elif enforcement.get("span") == "version":
            problems.append("version-span attestation cannot be judged without a promoted version")
    complete = attestation is not None and not problems

    excluded = False
    if exclusion is not None and exclusion.get("reason"):
        expires = as_datetime(exclusion.get("expiresAt"))
        permanent = bool(exclusion.get("permanent"))
        excluded = (permanent and expires is None) or (not permanent and expires is not None and now < expires)

    if complete:
        status, reason = "satisfied", ""
    elif excluded:
        status, reason = "excluded", "excluded permanently" if exclusion.get("permanent") else f"excluded until {as_datetime(exclusion.get('expiresAt')).date().isoformat()}"
    else:
        status = "missing" if enforcement.get("level") == "mandatory" else "warning"
        reason = "no attestation recorded" if attestation is None else "attestation " + ", ".join(problems)
    return {"status": status, "reason": reason, "level": enforcement.get("level")}


def evaluate_service(svc, criteria, exclusions, now):
    attestations = svc.get("readiness") or {}
    stages = {}
    for stage in STAGES:
        results = []
        for cid in sorted(criteria):
            res = evaluate_criterion(criteria[cid], attestations.get(cid), exclusions.get(cid), svc.get("type"), stage, now)
            if res is not None:
                results.append({"id": cid, "name": criteria[cid].get("name", cid), **res})
        if not results:
            continue
        met = sum(1 for r in results if r["status"] in ("satisfied", "excluded"))
        missing = [r for r in results if r["status"] == "missing"]
        stages[stage] = {
            "applicable": len(results),
            "met": met,
            "percent": round(100 * met / len(results)),
            "missing": len(missing),
            "warnings": sum(1 for r in results if r["status"] == "warning"),
            "passed": not missing,
            "criteria": results,
        }
    return stages


def titleize(name):
    return " ".join(part.upper() if len(part) <= 3 and part not in ("and", "for", "the") else part.capitalize() for part in name.split("-"))


def vuln_text(v):
    return f"Vulns C{v['critical']}/H{v['high']}/M{v['medium']}/L{v['low']}"


def sev_cell(v):
    return f"{v['critical']}/{v['high']}/{v['medium']}/{v['low']}"


def md_table(header, rows):
    return ic.md_table(header, rows)


class LiteralDumper(yaml.SafeDumper):
    pass


LiteralDumper.add_representer(str, lambda d, s: d.represent_scalar("tag:yaml.org,2002:str", s, style="|" if "\n" in s else None))


def risk_score(v):
    return v["critical"] * 100 + v["high"] * 10 + v["medium"] + v["low"] * 0.1


def rollup(rows):
    total = {s: sum(r["vulnerabilities"][s] for r in rows) for s in SEVERITIES}
    total["open"] = sum(total.values())
    total["services"] = len(rows)
    total["servicesWithCritical"] = sum(1 for r in rows if r["vulnerabilities"]["critical"])
    return total


def entity(kind, name, namespace, spec, title=None, description=None, annotations=None, tags=None, links=None, labels=None):
    if not ENTITY_NAME.match(name) or len(name) > 63:
        raise ValueError(f"invalid entity name {name!r}")
    for tag in tags or []:
        if not TAG.match(tag) or len(tag) > 63:
            raise ValueError(f"invalid tag {tag!r} on {name}")
    metadata = {"name": name, "namespace": namespace}
    if title:
        metadata["title"] = title
    if description:
        metadata["description"] = description
    if labels:
        metadata["labels"] = labels
    if annotations:
        metadata["annotations"] = annotations
    if tags:
        metadata["tags"] = tags
    if links:
        metadata["links"] = links
    return {"apiVersion": "backstage.io/v1alpha1", "kind": kind, "metadata": metadata, "spec": spec}


CAPABILITY_WORDS = ["aurora", "basalt", "cascade", "delta", "ember", "fjord", "glacier", "harbor", "iris", "juniper", "krypton", "lumen",
                    "meridian", "nimbus", "onyx", "prism", "quartz", "radiant", "summit", "tundra", "umbra", "vertex", "willow", "zenith"]
APPLICATION_ADJECTIVES = ["amber", "azure", "bright", "cedar", "coral", "crimson", "dusk", "golden", "indigo", "ivory", "jade", "lunar", "maple", "polar", "silver"]
APPLICATION_NOUNS = ["falcon", "lantern", "meadow", "orbit", "pioneer", "river", "signal", "vista", "beacon", "compass"]
TEAM_WORDS = ["alpha", "bravo", "charlie", "delta", "echo", "foxtrot", "golf", "hotel", "india", "juliett", "kilo", "lima", "mike",
              "november", "oscar", "papa", "quebec", "romeo", "sierra", "tango", "uniform", "victor", "whiskey", "xray", "yankee", "zulu"]
SERVICE_ROLES = ["api", "worker", "adapter", "gateway", "sync", "portal", "scheduler", "processor", "connector", "registry", "broker",
                 "indexer", "exporter", "operator", "config", "agent", "store", "notifier", "importer", "monitor"]


def pseudonymize(services, applications, capabilities, teams, exclusions):
    """Rename every entry deterministically and replace free text, keeping types, relations and readiness."""
    team_map = {old: TEAM_WORDS[i % 26] + ("" if i < 26 else f"-{i // 26 + 1}") for i, old in enumerate(sorted(teams))}
    cap_map = {old: CAPABILITY_WORDS[i] if i < len(CAPABILITY_WORDS) else f"capability-{i + 1:02d}" for i, old in enumerate(sorted(capabilities))}
    pairs = [f"{a}-{n}" for n in APPLICATION_NOUNS for a in APPLICATION_ADJECTIVES]
    app_map = {old: pairs[(i * 7) % len(pairs)] for i, old in enumerate(sorted(applications))}
    if len(set(app_map.values())) != len(app_map):
        raise ValueError("application pseudonyms collide")

    new_teams = {team_map[k]: {"displayName": f"Team {titleize(team_map[k])}", "description": "Pseudonymized team."} for k in teams}
    new_caps = {cap_map[k]: {**{f: v[f] for f in ("type", "availability") if f in v}, "owningTeam": team_map[v["owningTeam"]],
                             "displayName": f"{titleize(cap_map[k])} capability", "docs": {d: "" for d in (v.get("docs") or {})}}
                for k, v in capabilities.items()}
    new_apps = {app_map[k]: {**{f: v[f] for f in ("type", "availability") if f in v}, "owningTeam": team_map[v["owningTeam"]],
                             "displayName": titleize(app_map[k]), "description": "Pseudonymized application."}
                for k, v in applications.items()}

    used, svc_map, new_services = Counter(), {}, {}
    for old in sorted(services):
        svc = services[old]
        belongs = svc.get("belongsTo") or {}
        if belongs.get("application") in app_map:
            prefix, parent_title, new_belongs = app_map[belongs["application"]], titleize(app_map[belongs["application"]]), {"application": app_map[belongs["application"]]}
        elif belongs.get("platformCapability") in cap_map:
            prefix, parent_title, new_belongs = cap_map[belongs["platformCapability"]], f"{titleize(cap_map[belongs['platformCapability']])} capability", {"platformCapability": cap_map[belongs["platformCapability"]]}
        else:
            prefix, parent_title, new_belongs = "standalone", None, {}
        n = used[prefix]
        used[prefix] += 1
        role = SERVICE_ROLES[n % len(SERVICE_ROLES)]
        name = f"{prefix}-{role}" + ("" if n < len(SERVICE_ROLES) else f"-{n // len(SERVICE_ROLES) + 1}")
        svc_map[old] = name
        new_services[name] = {
            "type": svc.get("type"), "lifecycle": svc.get("lifecycle"), "managed": svc.get("managed", True),
            "owningTeam": team_map[svc["owningTeam"]], "belongsTo": new_belongs, "readiness": svc.get("readiness") or {},
            "displayName": titleize(name),
            "description": f"Pseudonymized {svc.get('type')} ({role})" + (f" of {parent_title}." if parent_title else "."),
        }
    new_exclusions = {svc_map[k]: v for k, v in exclusions.items() if k in svc_map}
    return new_services, new_apps, new_caps, new_teams, new_exclusions, {"team": team_map, "capability": cap_map}


def build(args):
    root = args.catalog
    now = dt.datetime.now(dt.timezone.utc)
    today = now.date()
    dashboard = args.dashboard_url.rstrip("/") + "/"
    bitbucket = args.repo_base_url.rstrip("/")
    link_sources = not args.pseudonymize

    services = load_dir(root, "services")
    applications = load_dir(root, "applications")
    capabilities = load_dir(root, "platform-capabilities")
    teams = load_dir(root, "teams")
    with open(os.path.join(root, "service-readiness", "criteria.yaml"), encoding="utf-8") as f:
        criteria = (yaml.safe_load(f) or {}).get("criteria") or {}
    exclusions = {}
    for path in glob.glob(os.path.join(root, "service-readiness", "exclusions", "*.yaml")):
        with open(path, encoding="utf-8") as f:
            exclusions[os.path.splitext(os.path.basename(path))[0]] = ((yaml.safe_load(f) or {}).get("exclusions") or {})
    team_map, cap_map = {t: t for t in teams}, {c: c for c in capabilities}
    if args.pseudonymize:
        services, applications, capabilities, teams, exclusions, maps = pseudonymize(services, applications, capabilities, teams, exclusions)
        team_map, cap_map = maps["team"], maps["capability"]
    catalog_owner, infra_owner, runtime_system = team_map["engineering-journey"], team_map["nexus-infra"], cap_map["nexus-core"]
    try:
        commit = subprocess.run(["git", "-C", root, "log", "-1", "--format=%h %cs"], capture_output=True, text=True, check=True).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        commit = "unknown"

    def team_ref(team):
        if team not in teams:
            raise ValueError(f"unknown team {team!r}")
        return f"group:{NS_TEAMS}/{team}"

    # ---- service rows -------------------------------------------------------
    rows = []
    for name, svc in services.items():
        belongs = svc.get("belongsTo") or {}
        parent_kind, parent, availability = None, None, None
        if belongs.get("application") in applications:
            parent_kind, parent = "application", belongs["application"]
            availability = applications[parent].get("availability")
        elif belongs.get("platformCapability") in capabilities:
            parent_kind, parent = "platform-capability", belongs["platformCapability"]
            availability = capabilities[parent].get("availability")
        namespace = {"application": NS_APPLICATIONS, "platform-capability": NS_CAPABILITIES}.get(parent_kind, NS_STANDALONE)
        stages = evaluate_service(svc, criteria, exclusions.get(name, {}), now)
        current = stages.get(availability) if availability else None
        lifecycle = svc.get("lifecycle", "test")
        repo = ((svc.get("overrides") or {}).get("repo") or f"{bitbucket}/{name}") if link_sources else None
        rows.append({
            "name": name,
            "title": svc.get("displayName") or name,
            "description": (svc.get("description") or "").strip(),
            "type": svc.get("type"),
            "lifecycle": lifecycle,
            "managed": svc.get("managed", True),
            "team": svc.get("owningTeam"),
            "namespace": namespace,
            "parentKind": parent_kind,
            "parent": parent,
            "availability": availability,
            "repository": repo,
            "readiness": {"inScope": bool(stages), "currentStage": availability if current else None, "stages": stages},
        })
    by_name = {r["name"]: r for r in rows}

    # ---- deployments, versions and vulnerabilities from the source exports ---------------------
    scope = {r["name"]: CLUSTERS_BY_LIFECYCLE.get(r["lifecycle"], CLUSTERS_BY_LIFECYCLE["test"]) for r in rows}
    lifecycles_by_parent = {}
    for r in rows:
        if r["parent"]:
            lifecycles_by_parent.setdefault(r["parent"], []).append(r["lifecycle"])
    live_parent = args.live_parent or max(
        (p for p, lc in sorted(lifecycles_by_parent.items()) if 4 <= len(lc) <= args.live_max + 2),
        key=lambda p: (len(set(lifecycles_by_parent[p])), lifecycles_by_parent[p].count("production")))
    live_rows = sorted((r for r in rows if r["parent"] == live_parent), key=lambda r: (r["lifecycle"] != "production", r["name"]))[:args.live_max]
    pairs = [(r["name"], c) for r in live_rows for c in scope[r["name"]]]
    forced = {pair: LIVE_SCENARIOS[i % len(LIVE_SCENARIOS)] for i, pair in enumerate(pairs)}
    sources = args.sources or os.path.join(args.out, "mock-sources")
    if args.write_mock_sources:
        print(json.dumps({"mockSources": mock_sources.write(sources, scope, CLUSTERS, now, forced)}))
    desired = ic.read_gitops_dir(os.path.join(sources, "gitops"))
    live = {}
    for path in sorted(glob.glob(os.path.join(sources, "argocd", "*.json"))):
        with open(path, encoding="utf-8") as f:
            live.update(ic.from_argocd(json.load(f)))
    with open(os.path.join(sources, "acr", "defender-findings.json"), encoding="utf-8") as f:
        findings_index = ic.index_findings(json.load(f))
    joined = ic.join(scope, CLUSTERS, desired, live, findings_index)
    for r in rows:
        j = joined[r["name"]]
        r.update(environments=j["environments"], deployState=j["worstState"], vulnerabilities=j["vulnerabilities"], findings=j["findings"])

    def readiness_text(r):
        rd = r["readiness"]
        if not rd["inScope"]:
            return "Readiness n/a"
        if not rd["currentStage"]:
            return "Readiness: no parent availability"
        st = rd["stages"][rd["currentStage"]]
        return f"{STAGE_LABELS[rd['currentStage']]} readiness {st['percent']}% ({st['missing']} missing)"

    def readiness_tag(r):
        rd = r["readiness"]
        if not rd["inScope"]:
            return "readiness:not-applicable"
        if not rd["currentStage"]:
            return "readiness:unknown-stage"
        return "readiness:ready" if rd["stages"][rd["currentStage"]]["passed"] else "readiness:not-ready"

    def vuln_tag(v):
        for sev in ("critical", "high"):
            if v[sev]:
                return f"vulns:{sev}"
        return "vulns:no-critical-or-high"

    entities = []

    # ---- domains --------------------------------------------------------------
    owner_catalog = team_ref(catalog_owner)
    domains = [
        (NS_CAPABILITIES, "Nexus · Platform Capabilities", f"{len(capabilities)} platform capabilities and the services that belong to them."),
        (NS_APPLICATIONS, "Nexus · Applications", f"{len(applications)} applications and the services that belong to them."),
        (NS_STANDALONE, "Nexus · Services without a parent", "Services with no belongsTo application or platform capability."),
        (NS_TEAMS, "Nexus · Teams", f"{len(teams)} owning teams."),
        (NS_INSIGHTS, "Nexus · Readiness and Security Insights", "Global Service Readiness and vulnerability summaries. Per-service insights sit next to each service."),
        (NS_RUNTIME, "Nexus · Runtime clusters (mock)", "Clusters the services run on (mock)."),
    ]
    for name, title, desc in domains:
        entities.append(entity("Domain", name, "default", {"owner": owner_catalog}, title=title, description=desc,
                               links=[{"url": dashboard, "title": "Nexus insights dashboard"}]))

    # ---- teams ----------------------------------------------------------------
    for name, team in teams.items():
        owned = [r for r in rows if r["team"] == name]
        roll = rollup(owned)
        entities.append(entity(
            "Group", name, NS_TEAMS,
            {"type": "team", "profile": {"displayName": team.get("displayName") or titleize(name)}, "children": []},
            title=team.get("displayName") or titleize(name),
            description=f"{(team.get('description') or '').strip()} · {len(owned)} services · {vuln_text(roll)}".strip(" ·"),
            links=[{"url": f"{dashboard}#team={name}", "title": "Team readiness and vulnerabilities"}],
        ))

    # ---- platform capabilities and applications ---------------------------------
    def parent_system(kind, name, item, namespace, domain):
        members = [r for r in rows if r["parentKind"] == kind and r["parent"] == name]
        roll = rollup(members)
        availability = item.get("availability")
        kind_label = "Platform capability" if kind == "platform-capability" else "Application"
        # The portal's Project Contents card lists Components and Resources whose spec.system is this
        # name, in the namespace named by this annotation.
        annotations = {"nexus.demo/entity-kind": kind, "nexus.demo/availability": availability or "unknown",
                       "openchoreo.io/namespace": namespace}
        links = [{"url": f"{dashboard}#parent={kind}:{name}", "title": "Readiness and vulnerabilities"}]
        if kind == "platform-capability" and link_sources:
            annotations["backstage.io/source-location"] = f"url:{bitbucket}/nexus-catalog/src/main/docs/platform-capabilities/{name}/"
            for key, path in (item.get("docs") or {}).items():
                links.append({"url": f"{bitbucket}/nexus-catalog/src/main/{path}", "title": f"Docs: {titleize(re.sub(r'(?<!^)(?=[A-Z])', '-', key).lower())}"})
        desc = item.get("description") or ""
        summary = f"{kind_label} · {STAGE_LABELS.get(availability, availability)} · {len(members)} services · {vuln_text(roll)}"
        return entity("System", name, namespace,
                      {"owner": team_ref(item["owningTeam"]), "domain": f"default/{domain}", "type": kind},
                      title=item.get("displayName") or titleize(name),
                      description=f"{summary}. {desc}".strip(),
                      annotations=annotations,
                      tags=[kind, f"availability:{availability}"],
                      links=links)

    for name, cap in capabilities.items():
        entities.append(parent_system("platform-capability", name, cap, NS_CAPABILITIES, NS_CAPABILITIES))
    for name, app in applications.items():
        entities.append(parent_system("application", name, app, NS_APPLICATIONS, NS_APPLICATIONS))

    # ---- clusters ---------------------------------------------------------------
    def on_cluster(name):
        return [(r, e) for r in rows for e in r["environments"] if e["cluster"] == name]

    for name, c in CLUSTERS.items():
        apps = on_cluster(name)
        states = Counter(e["state"] for _, e in apps)
        problems = sorted(((r, e) for r, e in apps if e["state"] != "in-sync"), key=lambda x: (ic.STATES.index(x[1]["state"]), x[0]["name"]))
        lines = [f"**Mock {c['stage'].upper()} cluster** in {c['region']}, ring `{c['ring']}`. GitOps path `{c['stage']}/rings/{c['ring']}/chart-versions/`.", ""]
        lines += md_table(["Services", "In sync", "Version drift", "Degraded", "Progressing", "Not deployed"],
                          [[len(apps), states["in-sync"], states["drift"], states["degraded"], states["progressing"], states["not-deployed"]]])
        if problems:
            lines += ["", "**Needs attention**"] + [
                f"- {r['title']}: {ic.STATE_LABELS[e['state']]}" + (f", running {ic.short_version(e['liveVersion'])}, GitOps {ic.short_version(e['desiredVersion'])}" if e["state"] == "drift" else "")
                + (f" ({e['message']})" if e["message"] else "") for r, e in problems[:12]]
            if len(problems) > 12:
                lines.append(f"- and {len(problems) - 12} more on the dashboard")
        entities.append(entity("Resource", name, NS_RUNTIME,
                               {"type": "kubernetes-cluster", "owner": team_ref(infra_owner), "system": f"{NS_CAPABILITIES}/{runtime_system}"},
                               title=f"Nexus {c['title']} (mock)",
                               description="\n".join(lines),
                               tags=[f"environment:{c['stage']}", f"ring:{c['ring']}", "mock-data"],
                               links=[{"url": f"{dashboard}#cluster={name}", "title": "Deployments on this cluster"}]))

    # ---- services and their insights ---------------------------------------------
    for r in rows:
        v, envs = r["vulnerabilities"], r["environments"]
        annotations = {
            "nexus.demo/service-type": r["type"],
            "nexus.demo/availability": r["availability"] or "none",
            "nexus.demo/readiness": readiness_text(r),
            "nexus.demo/vulnerabilities": f"critical={v['critical']},high={v['high']},medium={v['medium']},low={v['low']},fixable={v['fixable']}",
            "nexus.demo/deployments": ",".join(f"{e['cluster']}={ic.short_version(e['liveVersion']) or 'none'}:{e['state']}" for e in envs),
            "nexus.demo/data-note": "deployments, versions and vulnerabilities come from mock GitOps, Argo CD and ACR exports",
        }
        if r["repository"]:
            annotations["backstage.io/source-location"] = f"url:{r['repository'].rstrip('/')}/src/main/"
        if r["parent"]:
            annotations["openchoreo.io/project"] = r["parent"]
        spec = {"type": r["type"], "lifecycle": r["lifecycle"], "owner": team_ref(r["team"]),
                "dependsOn": [f"resource:{NS_RUNTIME}/{e['cluster']}" for e in envs if e["state"] != "not-deployed"]}
        if r["parent"]:
            spec["system"] = r["parent"]
        entities.append(entity(
            "Component", r["name"], r["namespace"], spec,
            title=r["title"],
            description=f"{vuln_text(v)} · {readiness_text(r)} · {ic.deploy_text(envs)} · {r['description']}",
            annotations=annotations,
            tags=[readiness_tag(r), vuln_tag(v), f"deploy:{r['deployState']}", f"lifecycle:{r['lifecycle']}"],
            links=[{"url": f"{dashboard}#service={r['name']}", "title": "Deployments, readiness and vulnerabilities"}],
        ))

        lines = []
        rd = r["readiness"]
        if not rd["inScope"]:
            lines.append(f"**Service readiness:** no criteria apply to service type `{r['type']}`.")
        else:
            current = STAGE_LABELS.get(rd["currentStage"], "unknown (no parent availability)")
            lines.append(f"**Service readiness** (current stage: {current})")
            for stage in STAGES:
                st = rd["stages"].get(stage)
                if not st:
                    continue
                missing = [c["name"] for c in st["criteria"] if c["status"] == "missing"]
                marker = " ← current" if stage == rd["currentStage"] else ""
                line = f"- {STAGE_LABELS[stage]}{marker}: {st['met']}/{st['applicable']} met ({st['percent']}%)"
                if missing:
                    shown = ", ".join(missing[:6]) + (f", and {len(missing) - 6} more" if len(missing) > 6 else "")
                    line += f". Missing: {shown}"
                lines.append(line)
        lines += ["", "**Deployments**: GitOps desired version against what Argo CD reports running (mock exports)", ""]
        if envs:
            lines += md_table(["Cluster", "GitOps desired", "Running", "Sync", "Health", "Vulns C/H/M/L"],
                              [[CLUSTERS[e["cluster"]]["title"], ic.short_version(e["desiredVersion"]) or "not in GitOps",
                                ic.short_version(e["liveVersion"]) or "not deployed", e["sync"] or "—", e["health"], sev_cell(e["vulnerabilities"])] for e in envs])
            notes = [f"- {CLUSTERS[e['cluster']]['title']}: {ic.STATE_LABELS[e['state']]}" + (f". {e['message']}" if e["message"] else "")
                     for e in envs if e["state"] != "in-sync"]
            lines += ([""] + notes) if notes else []
        else:
            lines.append("No GitOps version and no Application on any cluster.")
        lines += ["", f"**Vulnerabilities in running images**: Microsoft Defender for Containers findings from ACR (mock, last scan {v['lastScanned'] or 'n/a'})",
                  f"- Critical {v['critical']} · High {v['high']} · Medium {v['medium']} · Low {v['low']} · Open {v['open']} · Fix available for {v['fixable']}",
                  f"- In production images: {vuln_text(v['production'])}"]
        top_findings = [f for f in r["findings"] if f["severity"] in ("critical", "high")][:8]
        if top_findings:
            lines += [""] + md_table(["CVE", "Severity", "Package", "Installed", "Fixed in", "Running on"],
                                     [[f["cve"], f["severity"].capitalize(), f["package"], f["installed"], f["fixed"] or "no fix yet",
                                       ", ".join(CLUSTERS[c]["title"] for c in f["clusters"])] for f in top_findings])
        res_spec = {"type": "service-insights", "owner": team_ref(r["team"]),
                    "dependencyOf": [f"component:{r['namespace']}/{r['name']}"]}
        if r["parent"]:
            res_spec["system"] = r["parent"]
        entities.append(entity(
            "Resource", f"{r['name']}-insights", r["namespace"], res_spec,
            title=f"{r['title']} · deployments, readiness and security",
            description="\n".join(lines),
            annotations={"openchoreo.io/project": r["parent"]} if r["parent"] else None,
            tags=[readiness_tag(r), vuln_tag(v), f"deploy:{r['deployState']}", "mock-source-data"],
            links=[{"url": f"{dashboard}#service={r['name']}", "title": "Full deployment, readiness and vulnerability report"}]
                  + ([{"url": r["repository"], "title": "Repository"}] if r["repository"] else []),
        ))

    # ---- global summaries -----------------------------------------------------------
    total = rollup(rows)
    top = sorted(rows, key=lambda x: risk_score(x["vulnerabilities"]), reverse=True)[:10]
    by_parent_kind = {k: rollup([r for r in rows if r["parentKind"] == k]) for k in ("platform-capability", "application", None)}
    cves = {}
    for r in rows:
        for f in r["findings"]:
            c = cves.setdefault(f["cve"], {"severity": f["severity"], "cvss": f["cvss"], "package": f["package"], "services": set(), "production": set(), "fixable": False})
            c["services"].add(r["name"])
            c["fixable"] |= bool(f["fixed"])
            if any(CLUSTERS[x]["stage"] == "prd" for x in f["clusters"]):
                c["production"].add(r["name"])
    top_cves = sorted(cves.items(), key=lambda kv: (ic.SEVERITIES.index(kv[1]["severity"]), -len(kv[1]["services"]), kv[0]))[:12]
    fixable = sum(r["vulnerabilities"]["fixable"] for r in rows)
    vuln_lines = [
        f"**Global vulnerability summary** across {total['services']} services: Microsoft Defender for Containers findings for the images "
        f"running on each cluster, matched through Argo CD's image list (mock ACR export)",
        f"- Critical {total['critical']} · High {total['high']} · Medium {total['medium']} · Low {total['low']} · Open findings {total['open']}",
        f"- Fix available for {fixable} of {total['open']} findings · {len(cves)} distinct CVEs",
        f"- Services with critical findings: {total['servicesWithCritical']}",
        f"- Running in production: {vuln_text(rollup([{'vulnerabilities': r['vulnerabilities']['production']} for r in rows]))}",
        f"- Platform capability services: {vuln_text(by_parent_kind['platform-capability'])}",
        f"- Application services: {vuln_text(by_parent_kind['application'])}",
        f"- Services without a parent: {vuln_text(by_parent_kind[None])}",
        "",
        "**Most widespread critical and high CVEs**",
        "",
    ] + md_table(["CVE", "Severity", "Package", "Services", "In production", "Fix available"],
                 [[k, c["severity"].capitalize(), c["package"], len(c["services"]), len(c["production"]), "yes" if c["fixable"] else "no"] for k, c in top_cves]) + [
        "",
        "**Highest risk services**",
    ] + [f"- {x['title']}: {vuln_text(x['vulnerabilities'])}" for x in top]
    entities.append(entity("Resource", "nexus-vulnerability-summary", NS_INSIGHTS,
                           {"type": "security-summary", "owner": owner_catalog},
                           title="Nexus · Global vulnerability summary",
                           description="\n".join(vuln_lines),
                           tags=["global-summary", "mock-source-data"],
                           links=[{"url": f"{dashboard}#security", "title": "Global vulnerability dashboard"}]))

    deploy_rows, drift, degraded = [], [], []
    for name, c in CLUSTERS.items():
        states = Counter(e["state"] for _, e in on_cluster(name))
        deploy_rows.append([c["title"], sum(states.values()), states["in-sync"], states["drift"], states["degraded"], states["progressing"], states["not-deployed"]])
        drift += [(r, e) for r, e in on_cluster(name) if e["state"] == "drift"]
        degraded += [(r, e) for r, e in on_cluster(name) if e["state"] == "degraded"]
    deploy_lines = [
        f"**Deployment status** of {len(rows)} services on {len(CLUSTERS)} clusters. The desired version comes from GitOps "
        "(`<stage>/rings/<ring>/chart-versions/<service>.yaml`); running version, sync and health come from Argo CD (mock exports).",
        "",
    ] + md_table(["Cluster", "Services", "In sync", "Version drift", "Degraded", "Progressing", "Not deployed"], deploy_rows) + [
        "", f"**Version drift**: {len(drift)} deployments run a different version than GitOps", "",
    ] + md_table(["Service", "Cluster", "Running", "GitOps desired", "Reason"],
                 [[r["title"], CLUSTERS[e["cluster"]]["title"], ic.short_version(e["liveVersion"]), ic.short_version(e["desiredVersion"]), e["message"] or "—"]
                  for r, e in drift[:15]]) + [
        "", f"**Degraded**: {len(degraded)} deployments", "",
    ] + [f"- {r['title']} on {CLUSTERS[e['cluster']]['title']}: {e['message']}" for r, e in degraded[:15]]
    entities.append(entity("Resource", "nexus-deployment-summary", NS_INSIGHTS,
                           {"type": "deployment-summary", "owner": owner_catalog},
                           title="Nexus · Deployment status and version drift",
                           description="\n".join(deploy_lines),
                           tags=["global-summary", "mock-source-data"],
                           links=[{"url": f"{dashboard}#deployments", "title": "Deployments dashboard"}]))

    in_scope = [r for r in rows if r["readiness"]["inScope"]]
    staged = [r for r in in_scope if r["readiness"]["currentStage"]]
    ready = [r for r in staged if r["readiness"]["stages"][r["readiness"]["currentStage"]]["passed"]]
    missed = Counter()
    for r in staged:
        for c in r["readiness"]["stages"][r["readiness"]["currentStage"]]["criteria"]:
            if c["status"] == "missing":
                missed[c["name"]] += 1
    by_stage = Counter(r["readiness"]["currentStage"] for r in staged)
    ready_lines = [
        f"**Service Readiness summary** ({len(criteria)} criteria, catalog snapshot {commit})",
        f"- Services subject to criteria: {len(in_scope)} of {len(rows)}",
        f"- Ready for their current stage: {len(ready)} of {len(staged)}",
    ] + [f"- {STAGE_LABELS[s]}: {by_stage.get(s, 0)} services" for s in STAGES] + [
        "", "**Most often missing at the current stage**",
    ] + [f"- {name}: {count} services" for name, count in missed.most_common(10)]
    entities.append(entity("Resource", "nexus-service-readiness-summary", NS_INSIGHTS,
                           {"type": "readiness-summary", "owner": owner_catalog},
                           title="Nexus · Service Readiness summary",
                           description="\n".join(ready_lines),
                           tags=["global-summary"],
                           links=[{"url": f"{dashboard}#readiness", "title": "Service Readiness dashboard"}]))

    # ---- reference check ------------------------------------------------------------------
    known = {(e["kind"].lower(), e["metadata"]["namespace"], e["metadata"]["name"]) for e in entities}

    def check(ref, default_kind, default_ns):
        kind, rest = (ref.split(":", 1) if ":" in ref else (default_kind, ref))
        ns, name = (rest.split("/", 1) if "/" in rest else (default_ns, rest))
        if (kind.lower(), ns, name) not in known:
            raise ValueError(f"dangling reference {ref}")

    for e in entities:
        ns, spec = e["metadata"]["namespace"], e["spec"]
        if "owner" in spec:
            check(spec["owner"], "group", ns)
        if "system" in spec:
            check(spec["system"], "system", ns)
        if "domain" in spec:
            check(spec["domain"], "domain", ns)
        for ref in spec.get("dependsOn", []) + spec.get("dependencyOf", []):
            check(ref, "component", ns)

    snapshot = {
        "generatedAt": now.isoformat(timespec="seconds"),
        "catalogCommit": commit,
        "notes": "Readiness is computed from the Nexus Catalog snapshot. Deployments, versions and vulnerabilities come from mock GitOps, Argo CD and ACR (Defender) exports.",
        "counts": {"platformCapabilities": len(capabilities), "applications": len(applications), "services": len(rows), "teams": len(teams), "criteria": len(criteria)},
        "stageLabels": STAGE_LABELS,
        "stateLabels": ic.STATE_LABELS,
        "clusters": {k: {f: v[f] for f in ("title", "stage", "ring", "region")} for k, v in CLUSTERS.items()},
        "cves": {k: {"severity": c["severity"], "cvss": c["cvss"]} for k, c in cves.items()},
        "liveServices": [r["name"] for r in live_rows],
        "capabilities": {k: {"title": v.get("displayName") or titleize(k), "availability": v.get("availability"), "team": v.get("owningTeam"),
                             "docs": {dk: f"{bitbucket}/nexus-catalog/src/main/{dp}" if link_sources else "" for dk, dp in (v.get("docs") or {}).items()}} for k, v in capabilities.items()},
        "applications": {k: {"title": v.get("displayName") or titleize(k), "availability": v.get("availability"), "team": v.get("owningTeam"),
                             "description": v.get("description") or ""} for k, v in applications.items()},
        "teams": {k: {"title": v.get("displayName") or titleize(k), "description": (v.get("description") or "").strip()} for k, v in teams.items()},
        "services": rows,
    }
    manifest = live_manifest(args, live_rows, scope, live, catalog_owner)
    return entities, snapshot, manifest


def live_manifest(args, live_rows, scope, live, catalog_owner):
    """Kubernetes objects for the sandbox: one mock workload per Argo CD Application of the live services, and the collector."""
    labels = {"nexus.demo/dataset": "nexus-catalog"}
    docs = [{"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": ns, "labels": labels}} for ns in [LIVE_NAMESPACE, *CLUSTERS]]
    for r in live_rows:
        for cluster in scope[r["name"]]:
            app = live.get((r["name"], cluster))
            if not app:
                continue
            pod_labels = {ic.LABEL_COMPONENT: r["name"], "app.kubernetes.io/name": r["name"]}
            docs.append({
                "apiVersion": "apps/v1", "kind": "Deployment",
                "metadata": {"name": r["name"], "namespace": cluster, "labels": {**labels, **pod_labels},
                             "annotations": {ic.ANNOTATION_CHART_VERSION: app["liveVersion"], ic.ANNOTATION_IMAGE: app["images"][0],
                                             ic.ANNOTATION_DEPLOYED_AT: app["deployedAt"]}},
                "spec": {"replicas": 1, "progressDeadlineSeconds": 60, "selector": {"matchLabels": {ic.LABEL_COMPONENT: r["name"]}},
                         "template": {"metadata": {"labels": pod_labels}, "spec": {
                             "automountServiceAccountToken": False,
                             "securityContext": {"runAsNonRoot": True, "runAsUser": 65535, "seccompProfile": {"type": "RuntimeDefault"}},
                             "containers": [{"name": "app", "image": BROKEN_IMAGE if app["health"] == "Degraded" else PAUSE_IMAGE,
                                             "resources": {"requests": {"cpu": "1m", "memory": "4Mi"}, "limits": {"memory": "16Mi"}},
                                             "securityContext": {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True, "capabilities": {"drop": ["ALL"]}}}]}}},
            })
    config = {
        "gitopsBaseUrl": f"{args.source_base_url.rstrip('/')}/gitops",
        "acrFindingsUrl": f"{args.source_base_url.rstrip('/')}/acr/defender-findings.json",
        "datasetUrl": args.dataset_url,
        "intervalSeconds": 30, "sourceRefreshSeconds": 300,
        "teamNamespace": NS_TEAMS, "insightsNamespace": NS_INSIGHTS, "catalogOwner": catalog_owner,
        "clusters": {k: {"title": f"{c['title']} (ns {k})", "stage": c["stage"], "ring": c["ring"], "namespace": k} for k, c in CLUSTERS.items()},
        "services": [{"name": r["name"], "title": r["title"], "namespace": r["namespace"], "parent": r["parent"], "team": r["team"],
                      "clusters": scope[r["name"]]} for r in live_rows],
    }
    with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "insights_collector.py"), encoding="utf-8") as f:
        code = f.read()
    data = {"collector.py": code, "config.json": json.dumps(config, indent=1) + "\n"}
    checksum = hashlib.sha256(json.dumps(data, sort_keys=True).encode()).hexdigest()[:16]
    app_labels = {"app.kubernetes.io/name": "nexus-live-collector"}
    docs.append({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": "nexus-live-collector", "namespace": LIVE_NAMESPACE, "labels": labels}, "data": data})
    docs.append({"apiVersion": "v1", "kind": "ServiceAccount", "metadata": {"name": "nexus-live-collector", "namespace": LIVE_NAMESPACE, "labels": labels}})
    for ns in CLUSTERS:
        docs.append({"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role", "metadata": {"name": "nexus-live-collector-read", "namespace": ns, "labels": labels},
                     "rules": [{"apiGroups": ["apps"], "resources": ["deployments"], "verbs": ["get", "list"]},
                               {"apiGroups": [""], "resources": ["pods"], "verbs": ["get", "list"]}]})
        docs.append({"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "RoleBinding", "metadata": {"name": "nexus-live-collector-read", "namespace": ns, "labels": labels},
                     "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": "nexus-live-collector-read"},
                     "subjects": [{"kind": "ServiceAccount", "name": "nexus-live-collector", "namespace": LIVE_NAMESPACE}]})
    docs.append({
        "apiVersion": "apps/v1", "kind": "Deployment",
        "metadata": {"name": "nexus-live-collector", "namespace": LIVE_NAMESPACE, "labels": {**labels, **app_labels}},
        "spec": {"replicas": 1, "selector": {"matchLabels": app_labels}, "template": {
            "metadata": {"labels": app_labels, "annotations": {"nexus.demo/config-checksum": checksum}},
            "spec": {
                "serviceAccountName": "nexus-live-collector",
                "securityContext": {"runAsNonRoot": True, "runAsUser": 65534, "runAsGroup": 65534, "seccompProfile": {"type": "RuntimeDefault"}},
                "containers": [{
                    "name": "collector", "image": "python:3.12-alpine",
                    "command": ["python", "/app/collector.py", "serve", "--config", "/app/config.json", "--port", "8080"],
                    "env": [{"name": "PYTHONDONTWRITEBYTECODE", "value": "1"}, {"name": "PYTHONUNBUFFERED", "value": "1"}],
                    "ports": [{"name": "http", "containerPort": 8080}],
                    "readinessProbe": {"httpGet": {"path": "/healthz", "port": "http"}, "periodSeconds": 5},
                    "resources": {"requests": {"cpu": "10m", "memory": "64Mi"}, "limits": {"memory": "256Mi"}},
                    "securityContext": {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True, "capabilities": {"drop": ["ALL"]}},
                    "volumeMounts": [{"name": "app", "mountPath": "/app", "readOnly": True}],
                }],
                "volumes": [{"name": "app", "configMap": {"name": "nexus-live-collector"}}],
            }}},
    })
    docs.append({"apiVersion": "v1", "kind": "Service", "metadata": {"name": "nexus-live-collector", "namespace": LIVE_NAMESPACE, "labels": labels},
                 "spec": {"selector": app_labels, "ports": [{"name": "http", "port": 80, "targetPort": "http"}]}})
    return docs


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--catalog", required=True, help="path to a nexus-catalog checkout")
    parser.add_argument("--out", required=True, help="output repository root")
    parser.add_argument("--dashboard-url", required=True)
    parser.add_argument("--repo-base-url", default="https://bitbucket.org/ifs-pd")
    parser.add_argument("--pseudonymize", action="store_true", help="replace names and descriptions and drop repository and documentation links")
    parser.add_argument("--sources", help="directory with gitops/, argocd/ and acr/ exports (default: <out>/mock-sources)")
    parser.add_argument("--write-mock-sources", action="store_true", help="regenerate the mock exports in --sources first")
    parser.add_argument("--live-parent", help="platform capability or application whose services run as live workloads in the sandbox")
    parser.add_argument("--live-max", type=int, default=6)
    parser.add_argument("--source-base-url", default="https://raw.githubusercontent.com/sachin-jayasundara/openchoreo-nexus-catalog-demo/main/mock-sources",
                        help="where the sandbox collector reads the GitOps and ACR exports")
    parser.add_argument("--dataset-url", default="https://raw.githubusercontent.com/sachin-jayasundara/openchoreo-nexus-catalog-demo/main/docs/data.json",
                        help="insights dataset the sandbox collector serves to the portal plugin, with live state merged in")
    args = parser.parse_args()

    entities, snapshot, manifest = build(args)
    os.makedirs(os.path.join(args.out, "sandbox", "live"), exist_ok=True)
    with open(os.path.join(args.out, "sandbox", "live", "nexus-live-cluster-demo.yaml"), "w", encoding="utf-8", newline="\n") as f:
        f.write("# Generated by tools/generate_from_nexus_catalog.py. Applied by sandbox/setup-nexus-portal.sh.\n")
        yaml.dump_all(manifest, f, Dumper=LiteralDumper, sort_keys=False, allow_unicode=True, explicit_start=True, width=4096)
    os.makedirs(os.path.join(args.out, "catalog"), exist_ok=True)
    os.makedirs(os.path.join(args.out, "docs"), exist_ok=True)
    variants = {
        "nexus-catalog.yaml": entities,
        # For portals whose catalog.rules cannot be changed to allow Domain and Group.
        "nexus-catalog-without-domains-groups.yaml": [e for e in entities if e["kind"] not in ("Domain", "Group")],
    }
    for filename, items in variants.items():
        with open(os.path.join(args.out, "catalog", filename), "w", encoding="utf-8", newline="\n") as f:
            f.write("# Generated by tools/generate_from_nexus_catalog.py. Do not edit by hand.\n")
            yaml.safe_dump_all(items, f, sort_keys=False, allow_unicode=True, explicit_start=True, width=4096)
    data = json.dumps(snapshot, ensure_ascii=False, separators=(",", ":"), default=str)
    with open(os.path.join(args.out, "docs", "data.json"), "w", encoding="utf-8", newline="\n") as f:
        f.write(data)
    template_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "dashboard.template.html")
    with open(template_path, encoding="utf-8") as f:
        html = f.read().replace("/*__NEXUS_DATA__*/null", data.replace("</", "<\\/"))
    with open(os.path.join(args.out, "docs", "index.html"), "w", encoding="utf-8", newline="\n") as f:
        f.write(html)
    print(json.dumps({"entities": dict(Counter(e["kind"] for e in entities)), **snapshot["counts"]}))


if __name__ == "__main__":
    main()
