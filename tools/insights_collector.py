#!/usr/bin/env python3
"""Join GitOps desired versions, cluster deployment state and ACR vulnerability findings per service.

Three inputs, each in the shape of the real source:
  - GitOps: <stage>/rings/<ring>/chart-versions/<service>.yaml files containing `version: <chart version>`
  - Cluster state: an Argo CD ApplicationList export, or Deployments and Pods read from the Kubernetes API
  - ACR findings: Azure Resource Graph rows for Microsoft Defender for Containers sub-assessments

The catalog generator imports this module and reads mock exports. In the OpenChoreo sandbox the same file
runs as `collector.py serve`, reads the sandbox's own Kubernetes API and serves a Backstage catalog file.
Standard library only, so it runs in a plain python image.
"""

import argparse
import datetime as dt
import gzip
import http.server
import json
import os
import re
import ssl
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

SEVERITIES = ["critical", "high", "medium", "low"]
STATES = ["degraded", "drift", "not-deployed", "progressing", "not-in-gitops", "in-sync"]
STATE_LABELS = {"degraded": "Degraded", "drift": "Version drift", "not-deployed": "Not deployed", "progressing": "Progressing",
                "not-in-gitops": "Not in GitOps", "in-sync": "In sync"}

LABEL_COMPONENT = "nexus.demo/component"
LABEL_CLUSTER = "nexus.demo/cluster"
ANNOTATION_CHART_VERSION = "nexus.demo/chart-version"
ANNOTATION_IMAGE = "nexus.demo/image"
ANNOTATION_DEPLOYED_AT = "nexus.demo/deployed-at"

CHART_VERSION = re.compile(r"^version:\s*['\"]?([^'\"\s#]+)", re.M)
CHART_VERSION_PATH = re.compile(r"(?:^|/)(?P<stage>[^/]+)/rings/(?P<ring>[^/]+)/chart-versions/(?P<service>[^/]+)\.yaml$")
FAILING_WAIT_REASONS = {"ImagePullBackOff", "ErrImagePull", "InvalidImageName", "CrashLoopBackOff", "CreateContainerConfigError", "CreateContainerError"}


def gitops_path(service, stage, ring):
    return f"{stage}/rings/{ring}/chart-versions/{service}.yaml"


def parse_chart_version(text):
    match = CHART_VERSION.search(text or "")
    return match.group(1) if match else None


def short_version(version):
    """0.3.4+afb95bf7f6cf... -> 0.3.4+afb95bf"""
    if not version:
        return None
    base, _, build = version.partition("+")
    return f"{base}+{build[:7]}" if build else base


# ---- GitOps ----------------------------------------------------------------------------------

def read_gitops_dir(root):
    desired = {}
    for dirpath, _, files in os.walk(root):
        for filename in files:
            path = os.path.relpath(os.path.join(dirpath, filename), root).replace(os.sep, "/")
            match = CHART_VERSION_PATH.search(path)
            if not match:
                continue
            with open(os.path.join(dirpath, filename), encoding="utf-8") as f:
                version = parse_chart_version(f.read())
            if version:
                desired[(match["service"], match["stage"], match["ring"])] = {"version": version, "path": path}
    return desired


def read_gitops_urls(base_url, keys, fetch):
    desired = {}
    for service, stage, ring in keys:
        path = gitops_path(service, stage, ring)
        text = fetch(f"{base_url.rstrip('/')}/{path}", missing_ok=True)
        version = parse_chart_version(text) if text else None
        if version:
            desired[(service, stage, ring)] = {"version": version, "path": path}
    return desired


# ---- cluster state -------------------------------------------------------------------------------

def from_argocd(application_list):
    """Argo CD ApplicationList (for example `argocd app list -o json`) -> {(service, cluster): live state}."""
    live = {}
    for app in application_list.get("items") or []:
        labels = (app.get("metadata") or {}).get("labels") or {}
        service, cluster = labels.get(LABEL_COMPONENT), labels.get(LABEL_CLUSTER)
        if not service or not cluster:
            continue
        status = app.get("status") or {}
        history = status.get("history") or []
        last = history[-1] if history else {}
        operation = status.get("operationState") or {}
        health = status.get("health") or {}
        message = health.get("message") or ""
        if operation.get("phase") in ("Failed", "Error", "Running") and operation.get("message"):
            message = f"sync {operation['phase'].lower()}: {operation['message']}"
        live[(service, cluster)] = {
            "liveVersion": (last.get("revisions") or [last.get("revision")])[0],
            "deployedAt": last.get("deployedAt"),
            "health": health.get("status") or "Unknown",
            "reportedSync": (status.get("sync") or {}).get("status") or "Unknown",
            "message": message,
            "images": (status.get("summary") or {}).get("images") or [],
            "observedAt": status.get("reconciledAt"),
            "source": "Argo CD",
        }
    return live


def from_kubernetes(deployments, pods, cluster_by_namespace, observed_at):
    """Deployments and Pods labelled nexus.demo/component -> {(service, cluster): live state}."""
    waiting = {}
    for pod in pods:
        meta = pod.get("metadata") or {}
        key = (meta.get("namespace"), (meta.get("labels") or {}).get(LABEL_COMPONENT))
        for cs in (pod.get("status") or {}).get("containerStatuses") or []:
            reason = ((cs.get("state") or {}).get("waiting") or {}).get("reason")
            if reason in FAILING_WAIT_REASONS:
                waiting.setdefault(key, f"pod {meta.get('name')}: {reason}")
    live = {}
    for d in deployments:
        meta, spec, status = d.get("metadata") or {}, d.get("spec") or {}, d.get("status") or {}
        service, namespace = (meta.get("labels") or {}).get(LABEL_COMPONENT), meta.get("namespace")
        cluster = cluster_by_namespace.get(namespace)
        if not service or not cluster:
            continue
        annotations = meta.get("annotations") or {}
        replicas = spec.get("replicas", 1)
        available, updated = status.get("availableReplicas") or 0, status.get("updatedReplicas") or 0
        deadline = any(c.get("type") == "Progressing" and c.get("reason") == "ProgressDeadlineExceeded" for c in status.get("conditions") or [])
        if replicas == 0:
            health, message = "Suspended", "scaled to zero"
        elif (service and (namespace, service) in waiting) or deadline:
            health, message = "Degraded", waiting.get((namespace, service)) or "progress deadline exceeded"
        elif available >= replicas and updated >= replicas:
            health, message = "Healthy", ""
        else:
            health, message = "Progressing", f"{available}/{replicas} replicas available"
        containers = ((spec.get("template") or {}).get("spec") or {}).get("containers") or [{}]
        live[(service, cluster)] = {
            "liveVersion": annotations.get(ANNOTATION_CHART_VERSION),
            "deployedAt": annotations.get(ANNOTATION_DEPLOYED_AT) or meta.get("creationTimestamp"),
            "health": health,
            "reportedSync": None,
            "message": message,
            "images": [annotations.get(ANNOTATION_IMAGE) or containers[0].get("image")],
            "observedAt": observed_at,
            "source": "Kubernetes API",
        }
    return live


# ---- ACR vulnerability findings ------------------------------------------------------------------------

def index_findings(graph_result):
    """Azure Resource Graph rows -> {image reference: [rows]} keyed by registry/repository:tag and @digest."""
    index = {}
    for row in graph_result.get("data") or []:
        repo = f"{row['registry']}/{row['repository']}"
        for tag in row.get("tags") or []:
            index.setdefault(f"{repo}:{tag}", []).append(row)
        index.setdefault(f"{repo}@{row['digest']}", []).append(row)
    return index


def findings_for(index, image):
    if not image:
        return []
    if image in index:
        return index[image]
    if "@" in image:
        name, digest = image.split("@", 1)
        repo = name.rsplit(":", 1)[0] if ":" in name.rsplit("/", 1)[-1] else name
        return index.get(f"{repo}@{digest}") or index.get(name, [])
    return []


def count(rows):
    totals = {s: 0 for s in SEVERITIES}
    fixable = 0
    for row in rows:
        totals[row["severity"].lower()] += 1
        fixable += row.get("fixStatus") == "FixAvailable"
    totals["open"] = sum(totals[s] for s in SEVERITIES)
    totals["fixable"] = fixable
    return totals


def unique(rows):
    seen = {}
    for row in rows:
        seen.setdefault((row["cveId"], row["packageName"], row["installedVersion"]), row)
    return list(seen.values())


# ---- join ------------------------------------------------------------------------------------------

def state_of(want, have):
    if not have:
        return "not-deployed"
    if not want:
        return "not-in-gitops"
    if have["health"] == "Degraded":
        return "degraded"
    if have["health"] == "Progressing":
        return "progressing"
    if have["liveVersion"] != want["version"]:
        return "drift"
    if have["health"] != "Healthy":
        return "progressing"
    return "in-sync"


def join(services, clusters, desired, live, findings_index, missing="no Application for this cluster"):
    """services: {name: [cluster names in scope]}; clusters: {name: {"stage", "ring", ...}}."""
    result = {}
    for service, in_scope in services.items():
        environments, running, production = [], [], []
        per_finding_clusters = {}
        for cluster in in_scope:
            c = clusters[cluster]
            want, have = desired.get((service, c["stage"], c["ring"])), live.get((service, cluster))
            if not want and not have:
                continue
            state = state_of(want, have)
            image = ((have or {}).get("images") or [None])[0]
            rows = unique(findings_for(findings_index, image))
            for row in rows:
                per_finding_clusters.setdefault((row["cveId"], row["packageName"], row["installedVersion"]), []).append(cluster)
            running += rows
            if c["stage"] == "prd":
                production += rows
            environments.append({
                "cluster": cluster,
                "stage": c["stage"],
                "ring": c["ring"],
                "gitopsPath": (want or {}).get("path"),
                "desiredVersion": (want or {}).get("version"),
                "liveVersion": (have or {}).get("liveVersion"),
                "sync": None if not have or not want else ("Synced" if have["liveVersion"] == want["version"] else "OutOfSync"),
                "reportedSync": (have or {}).get("reportedSync"),
                "health": (have or {}).get("health", "Missing"),
                "message": have["message"] if have else missing,
                "image": image,
                "deployedAt": (have or {}).get("deployedAt"),
                "observedAt": (have or {}).get("observedAt"),
                "source": (have or {}).get("source"),
                "state": state,
                "vulnerabilities": count(rows),
            })
        running_unique = unique(running)
        findings = sorted(({
            "cve": row["cveId"], "severity": row["severity"].lower(), "cvss": row.get("cvss"), "package": row["packageName"],
            "installed": row["installedVersion"], "fixed": row.get("fixedVersion") or "", "fixStatus": row.get("fixStatus"),
            "category": row.get("category"), "published": row.get("publishedDate"),
            "clusters": [c for c in in_scope if c in per_finding_clusters[(row["cveId"], row["packageName"], row["installedVersion"])]],
        } for row in running_unique), key=lambda f: (SEVERITIES.index(f["severity"]), -(f["cvss"] or 0), f["cve"]))
        scanned = [row.get("timeGenerated") for row in running_unique if row.get("timeGenerated")]
        result[service] = {
            "environments": environments,
            "worstState": min((e["state"] for e in environments), key=STATES.index, default="not-deployed"),
            "vulnerabilities": {**count(running_unique), "production": count(unique(production)),
                                "lastScanned": max(scanned) if scanned else None,
                                "scanner": "Microsoft Defender for Containers findings from ACR"},
            "findings": findings,
        }
    return result


def deploy_text(environments):
    if not environments:
        return "Not deployed"
    states = [e["state"] for e in environments]
    text = f"Deploy {states.count('in-sync')}/{len(states)} in sync"
    others = [f"{states.count(s)} {STATE_LABELS[s].lower()}" for s in STATES if s != "in-sync" and s in states]
    return text + (", " + ", ".join(others) if others else "")


# ---- live collector (runs in the OpenChoreo sandbox) ---------------------------------------------------------

class KubernetesApi:
    SA = "/var/run/secrets/kubernetes.io/serviceaccount"

    def __init__(self):
        host, port = os.environ["KUBERNETES_SERVICE_HOST"], os.environ.get("KUBERNETES_SERVICE_PORT", "443")
        self.base = f"https://{host}:{port}"
        self.context = ssl.create_default_context(cafile=f"{self.SA}/ca.crt")

    def list(self, path):
        with open(f"{self.SA}/token", encoding="utf-8") as f:
            token = f.read().strip()
        request = urllib.request.Request(self.base + path, headers={"Authorization": f"Bearer {token}", "Accept": "application/json"})
        with urllib.request.urlopen(request, context=self.context, timeout=15) as response:
            return json.load(response).get("items") or []


def fetch_url(url, missing_ok=False):
    try:
        with urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": "nexus-live-collector"}), timeout=30) as response:
            return response.read().decode("utf-8")
    except urllib.error.HTTPError as e:
        if missing_ok and e.code == 404:
            return None
        raise


def md_table(header, rows):
    line = lambda cells: "| " + " | ".join(str(c).replace("|", "\\|") for c in cells) + " |"
    return [line(header), line(["---"] * len(header))] + [line(r) for r in rows]


def live_entities(config, joined, observed_at):
    clusters, entities = config["clusters"], []
    team_ns, insights_ns = config["teamNamespace"], config["insightsNamespace"]
    for svc in config["services"]:
        j = joined[svc["name"]]
        rows = [[clusters[e["cluster"]]["title"], short_version(e["desiredVersion"]) or "—", short_version(e["liveVersion"]) or "—",
                 e["health"], STATE_LABELS[e["state"]], e["message"] or ""] for e in j["environments"]]
        v = j["vulnerabilities"]
        lines = [f"**Live deployment status** read from the sandbox Kubernetes API at {observed_at}. GitOps desired versions come from the mock GitOps folder.", ""]
        lines += md_table(["Cluster (sandbox namespace)", "GitOps desired", "Running", "Health", "State", "Detail"], rows)
        lines += ["", f"**Vulnerabilities in running images** (mock ACR findings): Critical {v['critical']} · High {v['high']} · "
                      f"Medium {v['medium']} · Low {v['low']} · fixable {v['fixable']} of {v['open']}"]
        spec = {"type": "live-deployment-status", "owner": f"group:{team_ns}/{svc['team']}",
                "dependencyOf": [f"component:{svc['namespace']}/{svc['name']}"]}
        metadata = {"name": f"{svc['name']}-live-status", "namespace": svc["namespace"], "title": f"{svc['title']} · live cluster status",
                    "description": "\n".join(lines), "tags": ["live-cluster-data", f"deploy:{j['worstState']}"],
                    "annotations": {"nexus.demo/observed-at": observed_at}}
        if svc.get("parent"):
            spec["system"] = svc["parent"]
            metadata["annotations"]["openchoreo.io/project"] = svc["parent"]
        entities.append({"apiVersion": "backstage.io/v1alpha1", "kind": "Resource", "metadata": metadata, "spec": spec})

    summary_rows = []
    for name, c in clusters.items():
        envs = [e for svc in config["services"] for e in joined[svc["name"]]["environments"] if e["cluster"] == name]
        summary_rows.append([c["title"], len(envs)] + [sum(e["state"] == s for e in envs) for s in ("in-sync", "drift", "degraded", "progressing", "not-deployed")])
    problems = [f"- {svc['title']} on {clusters[e['cluster']]['title']}: {STATE_LABELS[e['state']]}" + (f" ({e['message']})" if e["message"] else "")
                for svc in config["services"] for e in joined[svc["name"]]["environments"] if e["state"] != "in-sync"]
    lines = [f"**Live deployment summary** for {len(config['services'])} services, read from the sandbox Kubernetes API at {observed_at}.", ""]
    lines += md_table(["Cluster (sandbox namespace)", "Workloads", "In sync", "Drift", "Degraded", "Progressing", "Not deployed"], summary_rows)
    lines += ["", "**Needs attention**"] + (problems or ["- Nothing. Every workload runs its GitOps version and is healthy."])
    entities.append({"apiVersion": "backstage.io/v1alpha1", "kind": "Resource",
                     "metadata": {"name": "nexus-live-deployment-summary", "namespace": insights_ns, "title": "Nexus · Live deployment summary (sandbox)",
                                  "description": "\n".join(lines), "tags": ["live-cluster-data", "global-summary"]},
                     "spec": {"type": "deployment-summary", "owner": f"group:{team_ns}/{config['catalogOwner']}"}})
    return entities


class LiveCollector:
    def __init__(self, config):
        self.config = config
        self.api = KubernetesApi()
        self.cluster_by_namespace = {c["namespace"]: name for name, c in config["clusters"].items()}
        self.sources_at, self.desired, self.findings, self.dataset = 0.0, {}, {}, None
        self.lock = threading.Lock()
        self.catalog, self.data, self.status = None, None, {"ready": False}

    def refresh_sources(self):
        keys = [(s["name"], self.config["clusters"][c]["stage"], self.config["clusters"][c]["ring"]) for s in self.config["services"] for c in s["clusters"]]
        self.desired = read_gitops_urls(self.config["gitopsBaseUrl"], keys, fetch_url)
        self.findings = index_findings(json.loads(fetch_url(self.config["acrFindingsUrl"])))
        if self.config.get("datasetUrl"):
            self.dataset = json.loads(fetch_url(self.config["datasetUrl"]))
        self.sources_at = time.time()

    def merged_dataset(self, joined, observed_at):
        """The portal's insights dataset, with the live sandbox state attached to the live services."""
        if not self.dataset:
            return None
        data = dict(self.dataset)
        data["services"] = [{**s, "live": {"observedAt": observed_at, **{k: joined[s["name"]][k] for k in ("environments", "worstState")}}}
                            if s["name"] in joined else s for s in self.dataset["services"]]
        data["live"] = {"observedAt": observed_at}
        body = json.dumps(data, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        return body, gzip.compress(body)

    def collect(self):
        if time.time() - self.sources_at > self.config.get("sourceRefreshSeconds", 300):
            self.refresh_sources()
        deployments, pods = [], []
        selector = urllib.parse.quote(LABEL_COMPONENT)
        for namespace in self.cluster_by_namespace:
            deployments += self.api.list(f"/apis/apps/v1/namespaces/{namespace}/deployments?labelSelector={selector}")
            pods += self.api.list(f"/api/v1/namespaces/{namespace}/pods?labelSelector={selector}")
        observed_at = dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")
        live = from_kubernetes(deployments, pods, self.cluster_by_namespace, observed_at)
        joined = join({s["name"]: s["clusters"] for s in self.config["services"]}, self.config["clusters"], self.desired, live, self.findings,
                      missing="no workload in this namespace")
        docs = "".join("---\n" + json.dumps(e, ensure_ascii=False, indent=1) + "\n" for e in live_entities(self.config, joined, observed_at))
        data = self.merged_dataset(joined, observed_at)
        with self.lock:
            self.catalog = docs.encode("utf-8")
            self.data = data
            self.status = {"ready": True, "observedAt": observed_at, "services": joined}

    def loop(self):
        while True:
            try:
                self.collect()
            except Exception as e:  # keep serving the last good result
                print(f"collect failed: {e!r}", file=sys.stderr, flush=True)
                with self.lock:
                    self.status = {**self.status, "lastError": repr(e)}
            time.sleep(self.config.get("intervalSeconds", 30))


def serve(config_path, port):
    with open(config_path, encoding="utf-8") as f:
        collector = LiveCollector(json.load(f))
    threading.Thread(target=collector.loop, daemon=True).start()

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            with collector.lock:
                catalog, data, status = collector.catalog, collector.data, collector.status
            encoding = None
            if self.path == "/catalog.yaml" and catalog:
                body, kind = catalog, "application/yaml"
            elif self.path == "/data.json" and data:
                kind = "application/json"
                if "gzip" in (self.headers.get("Accept-Encoding") or ""):
                    body, encoding = data[1], "gzip"
                else:
                    body = data[0]
            elif self.path == "/status.json":
                body, kind = json.dumps(status, indent=1).encode("utf-8"), "application/json"
            elif self.path == "/healthz" and catalog:
                body, kind = b"ok", "text/plain"
            else:
                self.send_error(404 if catalog else 503)
                return
            self.send_response(200)
            self.send_header("Content-Type", kind)
            if encoding:
                self.send_header("Content-Encoding", encoding)
            self.send_header("Vary", "Accept-Encoding")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, fmt, *args):
            pass

    print(f"serving on :{port}", flush=True)
    http.server.ThreadingHTTPServer(("", port), Handler).serve_forever()


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    s = sub.add_parser("serve", help="collect from the in-cluster Kubernetes API and serve /catalog.yaml")
    s.add_argument("--config", required=True)
    s.add_argument("--port", type=int, default=8080)
    args = parser.parse_args()
    serve(args.config, args.port)


if __name__ == "__main__":
    main()
