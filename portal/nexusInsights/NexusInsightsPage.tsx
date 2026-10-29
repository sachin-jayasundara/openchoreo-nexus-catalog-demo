import { useMemo, useState } from 'react';
import { Box, Grid, MenuItem, TextField, Typography } from '@material-ui/core';
import {
  Header,
  InfoCard,
  Page,
  TabbedLayout,
  Table,
  TableColumn,
} from '@backstage/core-components';
import {
  CountChips,
  DataGate,
  DataNote,
  Kpi,
  ParentLink,
  PercentBar,
  ServiceLink,
  SeverityChip,
  StateChip,
  TeamLink,
} from './common';
import {
  CveSummary,
  NexusData,
  STATE_ORDER,
  Service,
  State,
  currentStage,
  risk,
  shortVersion,
  summarizeCves,
  sumCounts,
} from './data';

const clusterRows = (data: NexusData) =>
  Object.entries(data.clusters).map(([id, c]) => {
    const envs = data.services.flatMap(s => s.environments.filter(e => e.cluster === id));
    const states = Object.fromEntries(STATE_ORDER.map(st => [st, envs.filter(e => e.state === st).length])) as Record<State, number>;
    return { id, title: c.title, stage: c.stage, ring: c.ring, services: envs.length, states, vulns: sumCounts(envs.map(e => e.vulnerabilities)) };
  });

const ClusterTable = ({ data }: { data: NexusData }) => {
  type Row = ReturnType<typeof clusterRows>[number];
  const columns: TableColumn<Row>[] = [
    { title: 'Cluster', field: 'title' },
    { title: 'Stage · ring', render: r => `${r.stage} · ${r.ring}` },
    { title: 'Services', field: 'services', type: 'numeric' },
    ...STATE_ORDER.filter(st => st !== 'not-in-gitops').map(st => ({
      title: data.stateLabels[st],
      type: 'numeric' as const,
      render: (r: Row) => r.states[st],
    })),
    { title: 'Vulnerabilities in running images (C/H/M/L)', render: r => <CountChips counts={r.vulns} /> },
  ];
  return <Table<Row> title="Clusters (mock)" options={{ paging: false, search: false }} columns={columns} data={clusterRows(data)} />;
};

const CveTable = ({ data, cves, title, pageSize = 20 }: { data: NexusData; cves: CveSummary[]; title: string; pageSize?: number }) => {
  const columns: TableColumn<CveSummary>[] = [
    { title: 'CVE', field: 'id', render: c => <a href={`https://nvd.nist.gov/vuln/detail/${c.id}`} target="_blank" rel="noreferrer">{c.id}</a> },
    { title: 'Severity', field: 'severity', render: c => <SeverityChip severity={c.severity} /> },
    { title: 'CVSS', field: 'cvss', type: 'numeric' },
    { title: 'Package', render: c => c.packages.join(', ') },
    { title: 'Services', type: 'numeric', render: c => c.services.length, customSort: (a, b) => a.services.length - b.services.length },
    { title: 'In production', field: 'production', type: 'numeric' },
    { title: 'Fix available', render: c => (c.fixable ? 'yes' : 'no') },
  ];
  return (
    <Table<CveSummary>
      title={title}
      options={{ pageSize, search: true, padding: 'dense' }}
      columns={columns}
      data={cves}
      detailPanel={({ rowData }) => (
        <Box p={2}>
          <Typography variant="subtitle2">Affected services</Typography>
          {rowData.services.map(s => {
            const f = s.findings.find(x => x.cve === rowData.id)!;
            return (
              <Typography variant="body2" key={s.name}>
                <ServiceLink service={s} /> · {f.package} {f.installed} → {f.fixed || 'no fix yet'} · running on{' '}
                {f.clusters.map(c => data.clusters[c]?.title ?? c).join(', ')}
              </Typography>
            );
          })}
        </Box>
      )}
    />
  );
};

const serviceColumns = (data: NexusData): TableColumn<Service>[] => [
  { title: 'Service', field: 'title', render: s => <ServiceLink service={s} /> },
  { title: 'Belongs to', render: s => <ParentLink service={s} data={data} /> },
  { title: 'Owning team', field: 'team', render: s => <TeamLink team={s.team} data={data} /> },
  { title: 'Deployments', field: 'deployState', render: s => <StateChip state={s.deployState} labels={data.stateLabels} /> },
  { title: 'Vulnerabilities (C/H/M/L)', render: s => <CountChips counts={s.vulnerabilities} />, customSort: (a, b) => risk(a.vulnerabilities) - risk(b.vulnerabilities) },
  {
    title: 'Readiness (current stage)',
    render: s => {
      const st = currentStage(s);
      if (!s.readiness.inScope) return 'not applicable';
      if (!st) return 'no parent stage';
      return <PercentBar percent={st.percent} />;
    },
  },
];

const OverviewTab = ({ data }: { data: NexusData }) => {
  const envs = data.services.flatMap(s => s.environments);
  const total = sumCounts(data.services.map(s => s.vulnerabilities));
  const staged = data.services.filter(s => currentStage(s));
  const cves = summarizeCves(data.services, data.clusters);
  const count = (st: State) => envs.filter(e => e.state === st).length;
  return (
    <>
      <DataNote data={data} />
      <Grid container spacing={3}>
        <Grid item md={3} xs={6}>
          <InfoCard><Kpi label="Deployments in sync with GitOps" value={`${count('in-sync')} / ${envs.length}`} note={`${Object.keys(data.clusters).length} clusters`} /></InfoCard>
        </Grid>
        <Grid item md={3} xs={6}>
          <InfoCard><Kpi label="Version drift · degraded" value={`${count('drift')} · ${count('degraded')}`} note={`${count('not-deployed')} not deployed, ${count('progressing')} progressing`} /></InfoCard>
        </Grid>
        <Grid item md={3} xs={6}>
          <InfoCard><Kpi label="Open vulnerabilities in running images" value={total.open} note={<CountChips counts={total} />} /></InfoCard>
        </Grid>
        <Grid item md={3} xs={6}>
          <InfoCard>
            <Kpi label="Ready for their current stage" value={`${staged.filter(s => currentStage(s)!.passed).length} / ${staged.length}`}
                 note={`${data.services.filter(s => s.readiness.inScope).length} services subject to readiness criteria`} />
          </InfoCard>
        </Grid>
        <Grid item xs={12}><ClusterTable data={data} /></Grid>
        <Grid item md={6} xs={12}>
          <CveTable data={data} title="Most widespread critical and high CVEs" pageSize={10} cves={cves.filter(c => c.severity === 'critical' || c.severity === 'high')} />
        </Grid>
        <Grid item md={6} xs={12}>
          <Table<Service>
            title="Highest risk services"
            options={{ paging: false, search: false, padding: 'dense' }}
            columns={serviceColumns(data).filter(c => c.title !== 'Belongs to' && c.title !== 'Readiness (current stage)')}
            data={[...data.services].sort((a, b) => risk(b.vulnerabilities) - risk(a.vulnerabilities)).slice(0, 10).map(s => ({ ...s }))}
          />
        </Grid>
      </Grid>
    </>
  );
};

const DeploymentsTab = ({ data }: { data: NexusData }) => {
  const [state, setState] = useState('');
  const [cluster, setCluster] = useState('');
  const rows = useMemo(
    () => data.services.filter(s => s.environments.some(e => (!state || e.state === state) && (!cluster || e.cluster === cluster))),
    [data, state, cluster],
  );
  const columns: TableColumn<Service>[] = [
    { title: 'Service', field: 'title', render: s => <><ServiceLink service={s} />{data.liveServices.includes(s.name) ? ' · live' : ''}</> },
    { title: 'Belongs to', render: s => <ParentLink service={s} data={data} /> },
    ...Object.entries(data.clusters).map(([id, c]) => ({
      title: c.title,
      render: (s: Service) => {
        const e = s.environments.find(x => x.cluster === id);
        if (!e) return '—';
        return (
          <span title={`GitOps ${shortVersion(e.desiredVersion) || 'none'}${e.message ? ` · ${e.message}` : ''}`}>
            <StateChip state={e.state} labels={data.stateLabels} />
            <Typography variant="caption" display="block" color="textSecondary">
              {shortVersion(e.liveVersion) || 'not deployed'}
              {e.state === 'drift' ? ` → ${shortVersion(e.desiredVersion)}` : ''}
            </Typography>
          </span>
        );
      },
    })),
  ];
  return (
    <>
      <DataNote data={data} />
      <Typography variant="body2" paragraph>
        The desired version comes from GitOps (<code>&lt;stage&gt;/rings/&lt;ring&gt;/chart-versions/&lt;service&gt;.yaml</code>). Running version,
        sync and health come from Argo CD. Hover a cell for the GitOps version and Argo CD's message.
      </Typography>
      <Box display="flex" mb={2} style={{ gap: 16 }}>
        <TextField select label="State" value={state} onChange={e => setState(e.target.value)} variant="outlined" size="small" style={{ minWidth: 200 }}>
          <MenuItem value="">All states</MenuItem>
          {STATE_ORDER.map(st => <MenuItem key={st} value={st}>{data.stateLabels[st]}</MenuItem>)}
        </TextField>
        <TextField select label="Cluster" value={cluster} onChange={e => setCluster(e.target.value)} variant="outlined" size="small" style={{ minWidth: 240 }}>
          <MenuItem value="">All clusters</MenuItem>
          {Object.entries(data.clusters).map(([id, c]) => <MenuItem key={id} value={id}>{c.title}</MenuItem>)}
        </TextField>
      </Box>
      <Table<Service> title={`Services (${rows.length})`} options={{ pageSize: 25, padding: 'dense' }} columns={columns} data={rows.map(s => ({ ...s }))} />
    </>
  );
};

const VulnerabilitiesTab = ({ data }: { data: NexusData }) => {
  const cves = summarizeCves(data.services, data.clusters);
  const total = sumCounts(data.services.map(s => s.vulnerabilities));
  const production = sumCounts(data.services.map(s => s.vulnerabilities.production));
  const teams = Object.keys(data.teams)
    .map(team => ({ team, services: data.services.filter(s => s.team === team) }))
    .filter(t => t.services.length)
    .map(t => ({ ...t, counts: sumCounts(t.services.map(s => s.vulnerabilities)) }))
    .sort((a, b) => risk(b.counts) - risk(a.counts));
  type TeamRow = (typeof teams)[number];
  return (
    <>
      <DataNote data={data} />
      <Typography variant="body2" paragraph>
        Microsoft Defender for Containers findings from ACR for the image each cluster runs, matched through Argo CD's image list. A service counts a
        CVE once even when several clusters run affected images. Expand a row for the affected services.
      </Typography>
      <Grid container spacing={3}>
        <Grid item md={4} xs={12}><InfoCard><Kpi label="Open findings" value={total.open} note={<CountChips counts={total} />} /></InfoCard></Grid>
        <Grid item md={4} xs={12}><InfoCard><Kpi label="Running in production" value={production.open} note={<CountChips counts={production} />} /></InfoCard></Grid>
        <Grid item md={4} xs={12}><InfoCard><Kpi label="Fix available" value={`${total.fixable} / ${total.open}`} note={`${cves.length} distinct CVEs`} /></InfoCard></Grid>
        <Grid item xs={12}><CveTable data={data} title="CVEs across the fleet" cves={cves} /></Grid>
        <Grid item xs={12}>
          <Table<TeamRow>
            title="By owning team"
            options={{ pageSize: 10, padding: 'dense' }}
            columns={[
              { title: 'Team', render: t => <TeamLink team={t.team} data={data} /> },
              { title: 'Services', type: 'numeric', render: t => t.services.length },
              { title: 'Vulnerabilities (C/H/M/L)', render: t => <CountChips counts={t.counts} /> },
              { title: 'Fix available', type: 'numeric', render: t => t.counts.fixable },
            ]}
            data={teams}
          />
        </Grid>
      </Grid>
    </>
  );
};

const ReadinessTab = ({ data }: { data: NexusData }) => {
  const inScope = data.services.filter(s => s.readiness.inScope);
  const missed = new Map<string, number>();
  inScope.forEach(s => currentStage(s)?.criteria.filter(c => c.status === 'missing').forEach(c => missed.set(c.name, (missed.get(c.name) ?? 0) + 1)));
  const columns: TableColumn<Service>[] = [
    { title: 'Service', field: 'title', render: s => <ServiceLink service={s} /> },
    { title: 'Belongs to', render: s => <ParentLink service={s} data={data} /> },
    { title: 'Current stage', render: s => (s.readiness.currentStage ? data.stageLabels[s.readiness.currentStage] : 'no parent stage') },
    { title: 'Met', render: s => { const st = currentStage(s); return st ? <PercentBar percent={st.percent} /> : '—'; }, customSort: (a, b) => (currentStage(a)?.percent ?? -1) - (currentStage(b)?.percent ?? -1) },
    { title: 'Missing', render: s => currentStage(s)?.criteria.filter(c => c.status === 'missing').map(c => c.name).join(', ') || '—' },
  ];
  type MissedRow = { name: string; count: number };
  return (
    <>
      <DataNote data={data} />
      <Grid container spacing={3}>
        {Object.entries(data.stageLabels).map(([stage, label]) => {
          const list = inScope.filter(s => s.readiness.currentStage === stage);
          return (
            <Grid item md={4} xs={12} key={stage}>
              <InfoCard><Kpi label={label} value={`${list.filter(s => currentStage(s)!.passed).length} / ${list.length}`} note="services ready for this stage" /></InfoCard>
            </Grid>
          );
        })}
        <Grid item md={8} xs={12}>
          <Table<Service> title="Services subject to readiness criteria" options={{ pageSize: 20, padding: 'dense' }} columns={columns} data={inScope.map(s => ({ ...s }))} />
        </Grid>
        <Grid item md={4} xs={12}>
          <Table<MissedRow>
            title="Most often missing"
            options={{ paging: false, search: false, padding: 'dense' }}
            columns={[{ title: 'Criterion', field: 'name' }, { title: 'Services', field: 'count', type: 'numeric' }]}
            data={[...missed.entries()].map(([name, count]) => ({ name, count })).sort((a, b) => b.count - a.count)}
          />
        </Grid>
      </Grid>
    </>
  );
};

const LiveTab = ({ data }: { data: NexusData }) => {
  const live = data.services.filter(s => s.live);
  type Row = { service: Service; cluster: string };
  const rows: Row[] = live.flatMap(s => s.live!.environments.map(e => ({ service: s, cluster: e.cluster })));
  const env = (r: Row) => r.service.live!.environments.find(e => e.cluster === r.cluster)!;
  return (
    <>
      <Typography variant="body2" paragraph>
        These services also run as workloads in this sandbox, one namespace per mock cluster. The collector reads them from the Kubernetes API every 30
        seconds and compares them with GitOps and the ACR findings. {data.live?.observedAt ? `Last read ${data.live.observedAt}.` : 'Not read yet.'}
        {data.live?.lastError ? ` Last error: ${data.live.lastError}` : ''}
      </Typography>
      <Table<Row>
        title="Live workloads in the sandbox cluster"
        options={{ paging: false, padding: 'dense' }}
        columns={[
          { title: 'Service', render: r => <ServiceLink service={r.service} /> },
          { title: 'Cluster (namespace)', render: r => `${data.clusters[r.cluster]?.title} (${r.cluster})` },
          { title: 'GitOps desired', render: r => shortVersion(env(r).desiredVersion) || 'not in GitOps' },
          { title: 'Running', render: r => shortVersion(env(r).liveVersion) || 'not deployed' },
          { title: 'Health', render: r => env(r).health },
          { title: 'State', render: r => <StateChip state={env(r).state} labels={data.stateLabels} /> },
          { title: 'Detail', render: r => env(r).message },
          { title: 'Vulnerabilities (C/H/M/L)', render: r => <CountChips counts={env(r).vulnerabilities} /> },
        ]}
        data={rows}
      />
    </>
  );
};

export const NexusInsightsPage = () => (
  <Page themeId="tool">
    <Header title="Nexus insights" subtitle="Deployment status, versions, vulnerabilities and Service Readiness for the Nexus Catalog" />
    <DataGate>
      {data => (
        <TabbedLayout>
          <TabbedLayout.Route path="/" title="Overview"><OverviewTab data={data} /></TabbedLayout.Route>
          <TabbedLayout.Route path="/deployments" title="Deployments"><DeploymentsTab data={data} /></TabbedLayout.Route>
          <TabbedLayout.Route path="/vulnerabilities" title="Vulnerabilities"><VulnerabilitiesTab data={data} /></TabbedLayout.Route>
          <TabbedLayout.Route path="/readiness" title="Service Readiness"><ReadinessTab data={data} /></TabbedLayout.Route>
          <TabbedLayout.Route path="/live" title="Live sandbox cluster"><LiveTab data={data} /></TabbedLayout.Route>
        </TabbedLayout>
      )}
    </DataGate>
  </Page>
);
