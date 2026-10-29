import { Entity } from '@backstage/catalog-model';
import {
  discoveryApiRef,
  fetchApiRef,
  useApi,
} from '@backstage/core-plugin-api';
import useAsync from 'react-use/esm/useAsync';

export type Severity = 'critical' | 'high' | 'medium' | 'low';
export const SEVERITIES: Severity[] = ['critical', 'high', 'medium', 'low'];
export type State =
  | 'degraded'
  | 'drift'
  | 'not-deployed'
  | 'progressing'
  | 'not-in-gitops'
  | 'in-sync';

export interface Counts {
  critical: number;
  high: number;
  medium: number;
  low: number;
  open: number;
  fixable: number;
}

export interface Environment {
  cluster: string;
  stage: string;
  ring: string;
  gitopsPath: string | null;
  desiredVersion: string | null;
  liveVersion: string | null;
  sync: string | null;
  health: string;
  message: string;
  image: string | null;
  deployedAt: string | null;
  observedAt: string | null;
  source: string | null;
  state: State;
  vulnerabilities: Counts;
}

export interface Finding {
  cve: string;
  severity: Severity;
  cvss: number | null;
  package: string;
  installed: string;
  fixed: string;
  fixStatus: string;
  category: string;
  clusters: string[];
}

export interface Criterion {
  id: string;
  name: string;
  status: 'satisfied' | 'excluded' | 'missing' | 'warning';
  reason: string;
  level: string;
}

export interface StageResult {
  applicable: number;
  met: number;
  percent: number;
  missing: number;
  warnings: number;
  passed: boolean;
  criteria: Criterion[];
}

export interface Service {
  name: string;
  title: string;
  description: string;
  type: string;
  lifecycle: string;
  team: string;
  namespace: string;
  parentKind: 'application' | 'platform-capability' | null;
  parent: string | null;
  availability: string | null;
  readiness: {
    inScope: boolean;
    currentStage: string | null;
    stages: Record<string, StageResult>;
  };
  environments: Environment[];
  deployState: State;
  vulnerabilities: Counts & { production: Counts; lastScanned: string | null };
  findings: Finding[];
  live?: { observedAt: string; environments: Environment[]; worstState: State };
}

export interface Cluster {
  title: string;
  stage: string;
  ring: string;
  region: string;
}

export interface NexusData {
  generatedAt: string;
  catalogCommit: string;
  notes: string;
  counts: Record<string, number>;
  stageLabels: Record<string, string>;
  stateLabels: Record<State, string>;
  clusters: Record<string, Cluster>;
  liveServices: string[];
  services: Service[];
  teams: Record<string, { title: string }>;
  applications: Record<string, { title: string }>;
  capabilities: Record<string, { title: string }>;
  live?: { observedAt: string | null; lastError?: string };
}

export const STATE_ORDER: State[] = [
  'degraded',
  'drift',
  'not-deployed',
  'progressing',
  'not-in-gitops',
  'in-sync',
];

let cached: Promise<NexusData> | undefined;
let cachedAt = 0;

/** Loads the insights dataset from the collector through the portal's proxy, shared by every view for a minute. */
export function useNexusData() {
  const discoveryApi = useApi(discoveryApiRef);
  const fetchApi = useApi(fetchApiRef);
  return useAsync(async () => {
    if (!cached || Date.now() - cachedAt > 60_000) {
      cachedAt = Date.now();
      cached = (async () => {
        const base = await discoveryApi.getBaseUrl('proxy');
        const response = await fetchApi.fetch(`${base}/nexus-insights/data.json`);
        if (!response.ok) {
          throw new Error(
            `The Nexus insights collector answered ${response.status} ${response.statusText}. Run sandbox/setup-nexus-portal.sh in the sandbox terminal.`,
          );
        }
        return (await response.json()) as NexusData;
      })();
      cached.catch(() => {
        cached = undefined;
      });
    }
    return cached;
  }, []);
}

export const isNexusEntity = (entity: Entity) =>
  Boolean(
    entity.metadata.annotations?.['nexus.demo/service-type'] ||
      entity.metadata.annotations?.['nexus.demo/entity-kind'],
  );

export const isNotNexusEntity = (entity: Entity) => !isNexusEntity(entity);

export const shortVersion = (version: string | null | undefined) => {
  if (!version) return '';
  const [base, build] = version.split('+');
  return build ? `${base}+${build.slice(0, 7)}` : base;
};

export const sumCounts = (list: Counts[]): Counts => {
  const total: Counts = { critical: 0, high: 0, medium: 0, low: 0, open: 0, fixable: 0 };
  for (const c of list) {
    total.critical += c.critical;
    total.high += c.high;
    total.medium += c.medium;
    total.low += c.low;
    total.open += c.open;
    total.fixable += c.fixable;
  }
  return total;
};

export const risk = (c: Counts) =>
  c.critical * 100 + c.high * 10 + c.medium + c.low * 0.1;

export interface CveSummary {
  id: string;
  severity: Severity;
  cvss: number | null;
  packages: string[];
  services: Service[];
  production: number;
  fixable: boolean;
}

interface CveAccumulator {
  first: Finding;
  packages: Set<string>;
  services: Map<string, Service>;
  production: Set<string>;
  fixable: boolean;
}

export function summarizeCves(services: Service[], clusters: Record<string, Cluster>): CveSummary[] {
  const byId = new Map<string, CveAccumulator>();
  for (const s of services) {
    for (const f of s.findings) {
      let acc = byId.get(f.cve);
      if (!acc) {
        acc = { first: f, packages: new Set(), services: new Map(), production: new Set(), fixable: false };
        byId.set(f.cve, acc);
      }
      acc.packages.add(f.package);
      acc.services.set(s.name, s);
      acc.fixable = acc.fixable || Boolean(f.fixed);
      if (f.clusters.some(x => clusters[x]?.stage === 'prd')) acc.production.add(s.name);
    }
  }
  return [...byId.values()]
    .map(acc => ({
      id: acc.first.cve,
      severity: acc.first.severity,
      cvss: acc.first.cvss,
      packages: [...acc.packages],
      services: [...acc.services.values()],
      production: acc.production.size,
      fixable: acc.fixable,
    }))
    .sort((a, b) =>
      SEVERITIES.indexOf(a.severity) - SEVERITIES.indexOf(b.severity) ||
      b.services.length - a.services.length ||
      (b.cvss ?? 0) - (a.cvss ?? 0));
}

export const currentStage = (s: Service) =>
  s.readiness.currentStage ? s.readiness.stages[s.readiness.currentStage] : undefined;
