"""Write mock exports of the three source systems the insights collector reads.

  mock-sources/gitops/<stage>/rings/<ring>/chart-versions/<service>.yaml   GitOps desired chart versions
  mock-sources/argocd/<cluster>.json                                       Argo CD ApplicationList per destination cluster
  mock-sources/acr/defender-findings.json                                  Azure Resource Graph result of acr/query.kql

Everything is generated deterministically per service name. CVE identifiers are real public CVEs so the
findings look familiar; which images contain them, and the installed and fixed package versions, are illustrative.
"""

import datetime as dt
import hashlib
import json
import os
import random
import shutil

from insights_collector import LABEL_CLUSTER, LABEL_COMPONENT, gitops_path

REGISTRY = "nexusdemoacr.azurecr.io"
ASSESSMENT_KEY = "c0b7cfc6-3172-465a-b378-53c7ff2cc0d5"

SCENARIOS = [("in-sync", 82), ("sync-failed", 5), ("rolling-out", 4), ("degraded", 6), ("not-deployed", 3)]
DEGRADED = ['Deployment "{s}" exceeded its progress deadline',
            "back-off 5m0s restarting failed container={s} pod={s}-7d9c5b6f4-x2kqp",
            "Readiness probe failed: HTTP probe failed with statuscode: 503"]
SYNC_FAILED = ['one or more objects failed to apply, reason: admission webhook "validation.gatekeeper.sh" denied the request: '
               '[container-must-have-limits] container <{s}> has no memory limit',
               'one or more synchronization tasks are not valid (retried 5 times)',
               'ComparisonError: failed to load target state: failed to pull chart nexus-demo/{s}/chart: unauthorized']

# (CVE, severity, CVSS 3 base, package, installed version, fixed version or "", published)
DEBIAN = [
    ("CVE-2023-38545", "Critical", 9.8, "libcurl4", "7.88.1-10+deb12u3", "7.88.1-10+deb12u4", "2023-10-18"),
    ("CVE-2023-45853", "Critical", 9.8, "zlib1g", "1:1.2.13.dfsg-1", "", "2023-10-14"),
    ("CVE-2024-45491", "Critical", 9.8, "libexpat1", "2.5.0-1", "2.5.0-1+deb12u1", "2024-08-30"),
    ("CVE-2024-37371", "Critical", 9.1, "libkrb5-3", "1.20.1-2+deb12u1", "1.20.1-2+deb12u2", "2024-06-28"),
    ("CVE-2023-4911", "High", 7.8, "libc6", "2.36-9+deb12u1", "2.36-9+deb12u3", "2023-10-03"),
    ("CVE-2023-6246", "High", 7.8, "libc6", "2.36-9+deb12u3", "2.36-9+deb12u4", "2024-01-31"),
    ("CVE-2024-2961", "High", 7.3, "libc6", "2.36-9+deb12u4", "2.36-9+deb12u7", "2024-04-17"),
    ("CVE-2023-5363", "High", 7.5, "libssl3", "3.0.11-1~deb12u1", "3.0.11-1~deb12u2", "2023-10-25"),
    ("CVE-2023-52425", "High", 7.5, "libexpat1", "2.5.0-1", "2.5.0-1+deb12u1", "2024-02-04"),
    ("CVE-2023-44487", "High", 7.5, "libnghttp2-14", "1.52.0-1", "1.52.0-1+deb12u1", "2023-10-10"),
    ("CVE-2023-29491", "High", 7.8, "libncursesw6", "6.4-4", "", "2023-04-14"),
    ("CVE-2023-31484", "High", 8.1, "perl-base", "5.36.0-7+deb12u1", "", "2023-04-29"),
    ("CVE-2024-0727", "Medium", 5.5, "libssl3", "3.0.11-1~deb12u2", "3.0.13-1~deb12u1", "2024-01-26"),
    ("CVE-2024-28182", "Medium", 5.3, "libnghttp2-14", "1.52.0-1+deb12u1", "1.52.0-1+deb12u2", "2024-04-04"),
    ("CVE-2023-50495", "Medium", 6.5, "libncursesw6", "6.4-4", "", "2023-12-12"),
    ("CVE-2023-4039", "Medium", 4.8, "libgcc-s1", "12.2.0-14", "", "2023-09-13"),
    ("CVE-2022-27943", "Medium", 5.5, "libstdc++6", "12.2.0-14", "", "2022-03-26"),
    ("CVE-2022-48303", "Medium", 5.5, "tar", "1.34+dfsg-1.2", "", "2023-01-30"),
    ("CVE-2024-22365", "Medium", 5.5, "libpam-modules", "1.5.2-6", "1.5.2-6+deb12u1", "2024-02-06"),
    ("CVE-2024-26462", "Medium", 5.5, "libkrb5-3", "1.20.1-2+deb12u1", "1.20.1-2+deb12u2", "2024-02-29"),
    ("CVE-2023-38546", "Low", 3.7, "libcurl4", "7.88.1-10+deb12u3", "7.88.1-10+deb12u4", "2023-10-18"),
    ("CVE-2011-3374", "Low", 3.7, "apt", "2.6.1", "", "2019-11-26"),
    ("CVE-2022-0563", "Low", 5.5, "util-linux", "2.38.1-5+b1", "", "2022-02-21"),
    ("CVE-2023-39804", "Low", 6.2, "tar", "1.34+dfsg-1.2", "", "2024-03-27"),
]
DISTROLESS_PACKAGES = {"libc6", "libssl3", "zlib1g", "libgcc-s1", "libstdc++6"}
ALPINE = [
    ("CVE-2024-6119", "High", 7.5, "libcrypto3", "3.1.4-r1", "3.1.7-r0", "2024-09-03"),
    ("CVE-2025-26519", "High", 8.1, "musl", "1.2.4_git20230717-r4", "1.2.4_git20230717-r5", "2025-02-14"),
    ("CVE-2023-6237", "Medium", 5.9, "libcrypto3", "3.1.4-r1", "3.1.4-r4", "2024-04-25"),
    ("CVE-2024-4741", "Medium", 5.6, "libssl3", "3.1.4-r1", "3.1.6-r0", "2024-11-13"),
    ("CVE-2023-42363", "Medium", 5.5, "busybox", "1.36.1-r15", "1.36.1-r16", "2023-11-27"),
    ("CVE-2023-42364", "Medium", 5.5, "busybox", "1.36.1-r15", "1.36.1-r17", "2023-11-27"),
    ("CVE-2024-5535", "Low", 3.7, "libssl3", "3.1.4-r1", "3.1.6-r0", "2024-06-27"),
]
LANGUAGES = {
    "go": [
        ("CVE-2024-24790", "Critical", 9.8, "stdlib", "1.21.6", "1.21.11", "2024-06-05"),
        ("CVE-2024-45337", "Critical", 9.1, "golang.org/x/crypto", "0.21.0", "0.31.0", "2024-12-12"),
        ("CVE-2023-39325", "High", 7.5, "golang.org/x/net", "0.15.0", "0.17.0", "2023-10-11"),
        ("CVE-2024-34156", "High", 7.5, "stdlib", "1.21.6", "1.22.7", "2024-09-06"),
        ("CVE-2025-22869", "High", 7.5, "golang.org/x/crypto", "0.21.0", "0.35.0", "2025-02-26"),
        ("CVE-2023-45288", "Medium", 5.3, "golang.org/x/net", "0.17.0", "0.23.0", "2024-04-04"),
        ("CVE-2023-48795", "Medium", 5.9, "golang.org/x/crypto", "0.14.0", "0.17.0", "2023-12-18"),
        ("CVE-2024-24786", "Medium", 5.9, "google.golang.org/protobuf", "1.31.0", "1.33.0", "2024-03-05"),
        ("CVE-2024-28180", "Medium", 4.3, "github.com/go-jose/go-jose/v3", "3.0.1", "3.0.3", "2024-03-09"),
    ],
    "java": [
        ("CVE-2022-42889", "Critical", 9.8, "org.apache.commons:commons-text", "1.9", "1.10.0", "2022-10-13"),
        ("CVE-2022-1471", "High", 8.3, "org.yaml:snakeyaml", "1.33", "2.0", "2022-12-01"),
        ("CVE-2023-6378", "High", 7.5, "ch.qos.logback:logback-classic", "1.4.11", "1.4.12", "2023-11-29"),
        ("CVE-2024-22259", "High", 8.1, "org.springframework:spring-web", "6.0.13", "6.1.5", "2024-03-16"),
        ("CVE-2024-38816", "High", 7.5, "org.springframework:spring-webmvc", "6.0.13", "6.1.13", "2024-09-13"),
        ("CVE-2023-44487", "High", 7.5, "io.netty:netty-codec-http2", "4.1.97.Final", "4.1.100.Final", "2023-10-10"),
        ("CVE-2023-34062", "High", 7.5, "io.projectreactor.netty:reactor-netty-http", "1.1.10", "1.1.13", "2023-11-28"),
        ("CVE-2024-29857", "Medium", 5.9, "org.bouncycastle:bcprov-jdk18on", "1.76", "1.78", "2024-05-14"),
        ("CVE-2024-47554", "Medium", 4.3, "commons-io:commons-io", "2.11.0", "2.14.0", "2024-10-03"),
        ("CVE-2020-8908", "Low", 3.3, "com.google.guava:guava", "29.0-jre", "30.0", "2020-12-10"),
    ],
    "node": [
        ("CVE-2024-4068", "High", 7.5, "braces", "3.0.2", "3.0.3", "2024-05-14"),
        ("CVE-2024-45590", "High", 7.5, "body-parser", "1.20.2", "1.20.3", "2024-09-10"),
        ("CVE-2024-37890", "High", 7.5, "ws", "8.16.0", "8.17.1", "2024-06-17"),
        ("CVE-2024-21538", "High", 7.5, "cross-spawn", "7.0.3", "7.0.5", "2024-11-08"),
        ("CVE-2024-39338", "High", 7.5, "axios", "1.6.8", "1.7.4", "2024-08-09"),
        ("CVE-2024-29041", "Medium", 6.1, "express", "4.18.2", "4.19.2", "2024-03-25"),
        ("CVE-2022-25883", "Medium", 5.3, "semver", "7.5.1", "7.5.2", "2023-06-21"),
        ("CVE-2023-26136", "Medium", 6.5, "tough-cookie", "4.1.2", "4.1.3", "2023-07-01"),
        ("CVE-2024-28849", "Medium", 6.5, "follow-redirects", "1.15.5", "1.15.6", "2024-03-14"),
        ("CVE-2024-43796", "Low", 5.0, "express", "4.19.2", "4.20.0", "2024-09-10"),
    ],
    "python": [
        ("CVE-2023-37920", "Critical", 9.8, "certifi", "2022.12.7", "2023.7.22", "2023-07-25"),
        ("CVE-2024-6345", "High", 8.8, "setuptools", "65.5.0", "70.0.0", "2024-07-15"),
        ("CVE-2024-1135", "High", 7.5, "gunicorn", "21.2.0", "22.0.0", "2024-04-16"),
        ("CVE-2023-46136", "High", 7.5, "werkzeug", "2.3.7", "3.0.1", "2023-10-25"),
        ("CVE-2022-40897", "Medium", 5.9, "setuptools", "65.5.0", "65.5.1", "2022-12-23"),
        ("CVE-2024-35195", "Medium", 5.6, "requests", "2.31.0", "2.32.0", "2024-05-20"),
        ("CVE-2024-22195", "Medium", 5.4, "jinja2", "3.1.2", "3.1.3", "2024-01-11"),
        ("CVE-2024-3651", "Medium", 6.2, "idna", "3.6", "3.7", "2024-07-07"),
        ("CVE-2024-37891", "Medium", 4.4, "urllib3", "2.0.7", "2.2.2", "2024-06-17"),
    ],
    "dotnet": [
        ("CVE-2024-43485", "High", 7.5, "System.Text.Json", "8.0.0", "8.0.5", "2024-10-08"),
        ("CVE-2024-30105", "High", 7.5, "System.Text.Json", "8.0.0", "8.0.4", "2024-07-09"),
        ("CVE-2024-38095", "High", 7.5, "System.Formats.Asn1", "8.0.0", "8.0.1", "2024-07-09"),
        ("CVE-2023-36414", "High", 8.8, "Azure.Identity", "1.10.0", "1.10.2", "2023-10-10"),
        ("CVE-2024-21907", "High", 7.5, "Newtonsoft.Json", "12.0.3", "13.0.1", "2024-01-03"),
        ("CVE-2024-35255", "Medium", 5.5, "Azure.Identity", "1.10.2", "1.11.4", "2024-06-11"),
    ],
}
SEVERITY_WEIGHT = {"Critical": 0.35, "High": 1.0, "Medium": 1.6, "Low": 1.2}


def seeded(*parts):
    return random.Random(int(hashlib.sha256(":".join(map(str, parts)).encode()).hexdigest()[:16], 16))


def sha(*parts):
    return hashlib.sha256(":".join(map(str, parts)).encode()).hexdigest()


def iso(t):
    return t.astimezone(dt.timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def image_ref(service, release):
    return f"{REGISTRY}/nexus-demo/{service}:{release['tag']}"


def releases(service, now):
    rnd = seeded("releases", service)
    count, minor, patch = rnd.randint(3, 9), rnd.randint(1, 12), 0
    times = [now - dt.timedelta(days=rnd.randint(1, 5), hours=rnd.randint(0, 23))]
    for _ in range(count - 1):
        times.insert(0, times[0] - dt.timedelta(days=rnd.randint(2, 14), hours=rnd.randint(0, 23)))
    out = []
    for i, built in enumerate(times):
        if i:
            minor, patch = (minor + 1, 0) if rnd.random() < 0.2 else (minor, patch + 1)
        commit = sha("commit", service, i)[:40]
        semver = f"0.{minor}.{patch}"
        out.append({"version": f"{semver}+{commit}", "tag": f"{semver}-{commit[:7]}", "digest": "sha256:" + sha("image", service, commit), "builtAt": built})
    return out


def weighted_sample(rnd, pool, k):
    pool, picked = list(pool), []
    for _ in range(min(k, len(pool))):
        weights = [SEVERITY_WEIGHT[p[1]] for p in pool]
        picked.append(pool.pop(rnd.choices(range(len(pool)), weights=weights)[0]))
    return picked


def image_profile(service, n_releases):
    rnd = seeded("findings", service)
    base = rnd.choices(["debian 12", "alpine 3.19", "distroless (debian 12)"], weights=[50, 25, 25])[0]
    language = rnd.choices(list(LANGUAGES), weights=[30, 25, 20, 15, 10])[0]
    os_pool = ALPINE if base.startswith("alpine") else [p for p in DEBIAN if not base.startswith("distroless") or p[3] in DISTROLESS_PACKAGES]
    picks = [(p, "OS") for p in weighted_sample(rnd, os_pool, rnd.choices(range(12), weights=[8, 10, 12, 12, 11, 10, 9, 8, 7, 6, 4, 3])[0])]
    picks += [(p, "Language") for p in weighted_sample(rnd, LANGUAGES[language], rnd.choices(range(6), weights=[22, 26, 22, 15, 10, 5])[0])]
    candidates = []
    for p, category in picks:
        introduced = 0 if rnd.random() < 0.85 or n_releases == 1 else rnd.randint(1, n_releases - 1)
        fixed_in = n_releases if not p[5] or rnd.random() < 0.55 else rnd.randint(introduced + 1, n_releases)
        candidates.append((p, category, introduced, fixed_in))
    return base, language, candidates


def application(service, cluster, c, desired, live, scenario, history, now, rnd):
    health, health_message, phase, op_message = "Healthy", None, "Succeeded", "successfully synced (all tasks run)"
    if scenario == "degraded":
        health, health_message = "Degraded", rnd.choice(DEGRADED).format(s=service)
    elif scenario == "sync-failed":
        phase, op_message = "Failed", rnd.choice(SYNC_FAILED).format(s=service)
    elif scenario == "rolling-out":
        health, health_message = "Progressing", f'Waiting for rollout to finish: 1 old replicas are pending termination...'
        phase, op_message = "Running", f"waiting for healthy state of apps/Deployment/{service}"
    deployed = min(now - dt.timedelta(minutes=5), live["builtAt"] + dt.timedelta(hours=rnd.randint(1, 30)))
    started = now - dt.timedelta(minutes=rnd.randint(2, 50)) if phase != "Succeeded" else deployed
    operation = {"phase": phase, "message": op_message, "startedAt": iso(started)}
    if phase != "Running":
        operation["finishedAt"] = iso(started + dt.timedelta(seconds=rnd.randint(8, 90)))
    entries = [{"id": i + 1, "revisions": [r["version"]], "deployedAt": iso(min(deployed, r["builtAt"] + dt.timedelta(hours=2))),
                "sources": [{"chart": f"nexus-demo/{service}/chart", "repoURL": REGISTRY, "targetRevision": r["version"]}]}
               for i, r in enumerate(history)]
    entries[-1]["deployedAt"] = iso(deployed)
    return {
        "apiVersion": "argoproj.io/v1alpha1",
        "kind": "Application",
        "metadata": {"name": f"{service}-{cluster}", "namespace": "argocd",
                     "labels": {LABEL_COMPONENT: service, LABEL_CLUSTER: cluster, "nexus.demo/ring": c["ring"], "nexus.demo/stage": c["stage"]}},
        "spec": {"project": service, "destination": {"name": cluster, "namespace": service},
                 "sources": [{"chart": f"nexus-demo/{service}/chart", "repoURL": REGISTRY, "targetRevision": desired["version"]}],
                 "syncPolicy": {"automated": {"prune": True, "selfHeal": True}}},
        "status": {
            "sync": {"status": "Synced" if live is desired else "OutOfSync", "revisions": [desired["version"]]},
            "health": {"status": health, **({"message": health_message} if health_message else {})},
            "summary": {"images": [image_ref(service, live)]},
            "operationState": operation,
            "reconciledAt": iso(now - dt.timedelta(seconds=rnd.randint(20, 170))),
            "history": entries,
        },
    }


def write_json_lines(path, head, key, items, tail):
    """JSON with one array element per line, so diffs stay readable."""
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write(json.dumps(head)[:-1] + f', "{key}": [\n')
        f.write(",\n".join(json.dumps(i, ensure_ascii=False, separators=(",", ":")) for i in items))
        f.write("\n]" + (", " + json.dumps(tail)[1:] if tail else "}") + "\n")


def write(root, services, clusters, now, forced=None):
    """services: {name: [cluster names in scope, in promotion order]}. forced: {(service, cluster): scenario}."""
    forced = forced or {}
    for sub in ("gitops", "argocd", "acr"):
        shutil.rmtree(os.path.join(root, sub), ignore_errors=True)
        os.makedirs(os.path.join(root, sub))
    apps = {c: [] for c in clusters}
    findings = []
    for service in sorted(services):
        rel = releases(service, now)
        rnd = seeded("promotion", service)
        index, previous, referenced = {}, len(rel) - 1, set()
        for cluster in services[service]:
            previous = max(0, previous - rnd.choice(clusters[cluster]["lag"]))
            index[cluster] = previous
        for cluster, i in index.items():
            c = clusters[cluster]
            path = os.path.join(root, "gitops", *gitops_path(service, c["stage"], c["ring"]).split("/"))
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w", encoding="utf-8", newline="\n") as f:
                f.write(f"version: {rel[i]['version']}\n")
            scenario = forced.get((service, cluster)) or rnd.choices([s for s, _ in SCENARIOS], weights=[w for _, w in SCENARIOS])[0]
            if scenario in ("sync-failed", "rolling-out") and i == 0:
                scenario = "in-sync"
            referenced.add(i)
            if scenario == "not-deployed":
                continue
            live_i = i - 1 if scenario in ("sync-failed", "rolling-out") else i
            referenced.add(live_i)
            apps[cluster].append(application(service, cluster, c, rel[i], rel[live_i], scenario, rel[max(0, live_i - 2):live_i + 1], now, rnd))

        base, _, candidates = image_profile(service, len(rel))
        scan = seeded("scan", service)
        for i in sorted(referenced):
            scanned = iso(now - dt.timedelta(hours=scan.randint(1, 70)))
            for p, category, introduced, fixed_in in candidates:
                if introduced <= i < fixed_in:
                    cve, severity, cvss, package, installed, fixed, published = p
                    findings.append({
                        "registry": REGISTRY, "repository": f"nexus-demo/{service}", "digest": rel[i]["digest"], "tags": [rel[i]["tag"]],
                        "cveId": cve, "severity": severity, "cvss": cvss, "publishedDate": published,
                        "packageName": package, "installedVersion": installed, "fixedVersion": fixed,
                        "fixStatus": "FixAvailable" if fixed else "NoFixAvailable", "category": category, "osDetails": f"linux {base}",
                        "statusCode": "Unhealthy", "timeGenerated": scanned,
                    })
    for cluster, items in apps.items():
        write_json_lines(os.path.join(root, "argocd", f"{cluster}.json"),
                         {"apiVersion": "argoproj.io/v1alpha1", "kind": "ApplicationList", "metadata": {}}, "items", items, None)
    write_json_lines(os.path.join(root, "acr", "defender-findings.json"), {"count": len(findings)}, "data", findings,
                     {"skip_token": None, "total_records": len(findings)})
    with open(os.path.join(root, "acr", "query.kql"), "w", encoding="utf-8", newline="\n") as f:
        f.write(QUERY)
    return {"applications": sum(len(v) for v in apps.values()), "findings": len(findings)}


QUERY = f"""// Microsoft Defender for Containers: vulnerability findings for images in Azure Container Registry,
// as Azure Resource Graph sub-assessments of the MDVM assessment {ASSESSMENT_KEY}.
// The mock defender-findings.json has the shape of: az graph query -q "<this query>" --first 1000 -o json
securityresources
| where type =~ "microsoft.security/assessments/subassessments"
| where properties.additionalData.assessedResourceType == "AzureContainerRegistryVulnerability"
| extend assessmentKey = extract(@"(?i)providers/Microsoft.Security/assessments/([^/]*)", 1, id)
| where assessmentKey == "{ASSESSMENT_KEY}"
| extend a = properties.additionalData
| project
    registry = tostring(a.artifactDetails.registryHost),
    repository = tostring(a.artifactDetails.repositoryName),
    digest = tostring(a.artifactDetails.digest),
    tags = a.artifactDetails.tags,
    cveId = tostring(a.vulnerabilityDetails.cveId),
    severity = tostring(a.vulnerabilityDetails.severity),
    cvss = todouble(a.vulnerabilityDetails.cvss["3.0"].base),
    publishedDate = tostring(a.vulnerabilityDetails.publishedDate),
    packageName = tostring(a.softwareDetails.packageName),
    installedVersion = tostring(a.softwareDetails.version),
    fixedVersion = tostring(a.softwareDetails.fixedVersion),
    fixStatus = tostring(a.softwareDetails.fixStatus),
    category = tostring(a.softwareDetails.category),
    osDetails = strcat(tostring(a.softwareDetails.osDetails.osPlatform), " ", tostring(a.softwareDetails.osDetails.osVersion)),
    statusCode = tostring(properties.status.code),
    timeGenerated = tostring(properties.timeGenerated)
"""
