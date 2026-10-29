#!/usr/bin/env python3
"""Generate an OpenChoreo (Backstage) catalog and an insights dashboard from a Nexus Catalog checkout.

Readiness is evaluated with the same rules as nexus-ci/src/readiness-validator. Vulnerability,
deployment and cluster data are mock values derived deterministically from each service name.

Never copied: team emails, Entra group IDs, Jira projects, contributors, readiness evidence
links, exclusion references and documentation bodies.
"""

import argparse
import datetime as dt
import glob
import hashlib
import json
import os
import random
import re
import subprocess
from collections import Counter, defaultdict

import yaml

STAGES = ["preview", "early-access", "general-availability"]
STAGE_LABELS = {"preview": "Preview", "early-access": "Early access", "general-availability": "General availability"}
SEVERITIES = ["critical", "high", "medium", "low"]

NS_CAPABILITIES = "nexus-platform-capabilities"
NS_APPLICATIONS = "nexus-applications"
NS_STANDALONE = "nexus-standalone-services"
NS_TEAMS = "nexus-teams"
NS_INSIGHTS = "nexus-insights"
NS_RUNTIME = "nexus-runtime"

CLUSTERS = {
    "nexus-dev-cluster": ("Nexus DEV cluster (mock)", "dev"),
    "nexus-tst-cluster": ("Nexus TST cluster (mock)", "tst"),
    "nexus-prd-cluster": ("Nexus PRD cluster (mock)", "prd"),
}
CLUSTERS_BY_LIFECYCLE = {
    "test": ["nexus-dev-cluster"],
    "staging": ["nexus-dev-cluster", "nexus-tst-cluster"],
    "production": ["nexus-dev-cluster", "nexus-tst-cluster", "nexus-prd-cluster"],
}

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


def seeded(name, salt):
    return random.Random(int(hashlib.sha256(f"{salt}:{name}".encode()).hexdigest()[:16], 16))


def mock_vulnerabilities(name, lifecycle, today):
    rnd = seeded(name, "vulns")
    critical = rnd.choices([0, 1, 2, 3, 4], weights=[70, 15, 9, 4, 2])[0]
    high = rnd.choices(range(0, 12), weights=[22, 14, 12, 10, 9, 8, 7, 6, 5, 3, 2, 2])[0]
    medium = rnd.randint(0, 6) + rnd.randint(0, 22)
    low = rnd.randint(0, 10) + rnd.randint(0, 28)
    if lifecycle == "production" and critical and rnd.random() < 0.4:
        critical -= 1
    return {
        "critical": critical,
        "high": high,
        "medium": medium,
        "low": low,
        "open": critical + high + medium + low,
        "lastScanned": (today - dt.timedelta(days=rnd.randint(0, 13))).isoformat(),
        "scanner": "Trivy image scan (mock data)",
    }


def mock_deployments(name, lifecycle):
    rnd = seeded(name, "deployments")
    deployments = []
    for cluster in CLUSTERS_BY_LIFECYCLE.get(lifecycle, ["nexus-dev-cluster"]):
        status = rnd.choices(["Healthy", "Progressing", "Degraded"], weights=[90, 6, 4])[0]
        deployments.append({"cluster": cluster, "status": status, "sync": "Synced" if status == "Healthy" else "OutOfSync"})
    return deployments


def titleize(name):
    return " ".join(part.upper() if len(part) <= 3 and part not in ("and", "for", "the") else part.capitalize() for part in name.split("-"))


def vuln_text(v):
    return f"Vulns C{v['critical']}/H{v['high']}/M{v['medium']}/L{v['low']}"


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
            "vulnerabilities": mock_vulnerabilities(name, lifecycle, today),
            "deployments": mock_deployments(name, lifecycle),
        })
    by_name = {r["name"]: r for r in rows}

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
    for name, (title, env) in CLUSTERS.items():
        running = [r for r in rows if any(d["cluster"] == name for d in r["deployments"])]
        entities.append(entity("Resource", name, NS_RUNTIME,
                               {"type": "kubernetes-cluster", "owner": team_ref(infra_owner), "system": f"{NS_CAPABILITIES}/{runtime_system}"},
                               title=title,
                               description=f"Mock {env.upper()} cluster. {len(running)} services deployed.",
                               tags=[f"environment:{env}", "mock-data"],
                               links=[{"url": f"{dashboard}#cluster={name}", "title": "Deployments on this cluster"}]))

    # ---- services and their insights ---------------------------------------------
    for r in rows:
        v = r["vulnerabilities"]
        annotations = {
            "nexus.demo/service-type": r["type"],
            "nexus.demo/availability": r["availability"] or "none",
            "nexus.demo/readiness": readiness_text(r),
            "nexus.demo/vulnerabilities": f"critical={v['critical']},high={v['high']},medium={v['medium']},low={v['low']}",
            "nexus.demo/data-note": "vulnerabilities and deployments are mock data",
        }
        if r["repository"]:
            annotations["backstage.io/source-location"] = f"url:{r['repository'].rstrip('/')}/src/main/"
        if r["parent"]:
            annotations["openchoreo.io/project"] = r["parent"]
        spec = {"type": r["type"], "lifecycle": r["lifecycle"], "owner": team_ref(r["team"]),
                "dependsOn": [f"resource:{NS_RUNTIME}/{d['cluster']}" for d in r["deployments"]]}
        if r["parent"]:
            spec["system"] = r["parent"]
        entities.append(entity(
            "Component", r["name"], r["namespace"], spec,
            title=r["title"],
            description=f"{vuln_text(v)} · {readiness_text(r)} · {r['description']}",
            annotations=annotations,
            tags=[readiness_tag(r), vuln_tag(v), f"lifecycle:{r['lifecycle']}"],
            links=[{"url": f"{dashboard}#service={r['name']}", "title": "Readiness and vulnerability report"}],
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
        lines.append("")
        lines.append(f"**Security insights** (mock scan {v['lastScanned']})")
        lines.append(f"- Critical {v['critical']} · High {v['high']} · Medium {v['medium']} · Low {v['low']} · Open findings {v['open']}")
        lines.append("- Runs on: " + ", ".join(f"{CLUSTERS[d['cluster']][1].upper()} ({d['status']})" for d in r["deployments"]))
        res_spec = {"type": "service-insights", "owner": team_ref(r["team"]),
                    "dependencyOf": [f"component:{r['namespace']}/{r['name']}"]}
        if r["parent"]:
            res_spec["system"] = r["parent"]
        entities.append(entity(
            "Resource", f"{r['name']}-insights", r["namespace"], res_spec,
            title=f"{r['title']} · readiness and security",
            description="\n".join(lines),
            annotations={"openchoreo.io/project": r["parent"]} if r["parent"] else None,
            tags=[readiness_tag(r), vuln_tag(v), "mock-vulnerability-data"],
            links=[{"url": f"{dashboard}#service={r['name']}", "title": "Full readiness and vulnerability report"}]
                  + ([{"url": r["repository"], "title": "Repository"}] if r["repository"] else []),
        ))

    # ---- global summaries -----------------------------------------------------------
    total = rollup(rows)
    top = sorted(rows, key=lambda x: risk_score(x["vulnerabilities"]), reverse=True)[:10]
    by_parent_kind = {k: rollup([r for r in rows if r["parentKind"] == k]) for k in ("platform-capability", "application", None)}
    vuln_lines = [
        f"**Global vulnerability summary** across {total['services']} services (mock scan data)",
        f"- Critical {total['critical']} · High {total['high']} · Medium {total['medium']} · Low {total['low']} · Open findings {total['open']}",
        f"- Services with critical findings: {total['servicesWithCritical']}",
        f"- Platform capability services: {vuln_text(by_parent_kind['platform-capability'])}",
        f"- Application services: {vuln_text(by_parent_kind['application'])}",
        f"- Services without a parent: {vuln_text(by_parent_kind[None])}",
        "",
        "**Highest risk services**",
    ] + [f"- {x['title']}: {vuln_text(x['vulnerabilities'])}" for x in top]
    entities.append(entity("Resource", "nexus-vulnerability-summary", NS_INSIGHTS,
                           {"type": "security-summary", "owner": owner_catalog},
                           title="Nexus · Global vulnerability summary",
                           description="\n".join(vuln_lines),
                           tags=["global-summary", "mock-vulnerability-data"],
                           links=[{"url": f"{dashboard}#security", "title": "Global vulnerability dashboard"}]))

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
        "notes": "Readiness is computed from the Nexus Catalog snapshot. Vulnerabilities, deployments and clusters are mock data.",
        "counts": {"platformCapabilities": len(capabilities), "applications": len(applications), "services": len(rows), "teams": len(teams), "criteria": len(criteria)},
        "stageLabels": STAGE_LABELS,
        "clusters": {k: {"title": t, "env": e} for k, (t, e) in CLUSTERS.items()},
        "capabilities": {k: {"title": v.get("displayName") or titleize(k), "availability": v.get("availability"), "team": v.get("owningTeam"),
                             "docs": {dk: f"{bitbucket}/nexus-catalog/src/main/{dp}" if link_sources else "" for dk, dp in (v.get("docs") or {}).items()}} for k, v in capabilities.items()},
        "applications": {k: {"title": v.get("displayName") or titleize(k), "availability": v.get("availability"), "team": v.get("owningTeam"),
                             "description": v.get("description") or ""} for k, v in applications.items()},
        "teams": {k: {"title": v.get("displayName") or titleize(k), "description": (v.get("description") or "").strip()} for k, v in teams.items()},
        "services": rows,
    }
    return entities, snapshot


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--catalog", required=True, help="path to a nexus-catalog checkout")
    parser.add_argument("--out", required=True, help="output repository root")
    parser.add_argument("--dashboard-url", required=True)
    parser.add_argument("--repo-base-url", default="https://bitbucket.org/ifs-pd")
    parser.add_argument("--pseudonymize", action="store_true", help="replace names and descriptions and drop repository and documentation links")
    args = parser.parse_args()

    entities, snapshot = build(args)
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
