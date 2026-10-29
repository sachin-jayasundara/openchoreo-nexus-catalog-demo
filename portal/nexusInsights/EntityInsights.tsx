import { Box, Grid, Typography } from '@material-ui/core';
import { InfoCard, Table, TableColumn, WarningPanel } from '@backstage/core-components';
import { useEntity } from '@backstage/plugin-catalog-react';
import {
  CountChips,
  DataGate,
  DataNote,
  Kpi,
  PercentBar,
  ServiceLink,
  SeverityChip,
  StateChip,
} from './common';
import {
  Environment,
  Finding,
  NexusData,
  STATE_ORDER,
  Service,
  currentStage,
  isNexusEntity,
  risk,
  shortVersion,
  sumCounts,
} from './data';

const envColumns = (data: NexusData): TableColumn<Environment>[] => [
  { title: 'Cluster', render: e => data.clusters[e.cluster]?.title ?? e.cluster },
  { title: 'GitOps desired', render: e => <span title={e.gitopsPath ?? ''}>{shortVersion(e.desiredVersion) || 'not in GitOps'}</span> },
  { title: 'Running', render: e => <span title={e.image ?? ''}>{shortVersion(e.liveVersion) || 'not deployed'}</span> },
  { title: 'Sync', render: e => e.sync ?? '—' },
  { title: 'Health', field: 'health' },
  { title: 'State', render: e => <StateChip state={e.state} labels={data.stateLabels} /> },
  { title: 'Detail', field: 'message' },
  { title: 'Vulnerabilities (C/H/M/L)', render: e => <CountChips counts={e.vulnerabilities} /> },
];

const findingColumns = (data: NexusData): TableColumn<Finding>[] => [
  { title: 'CVE', field: 'cve', render: f => <a href={`https://nvd.nist.gov/vuln/detail/${f.cve}`} target="_blank" rel="noreferrer">{f.cve}</a> },
  { title: 'Severity', field: 'severity', render: f => <SeverityChip severity={f.severity} /> },
  { title: 'CVSS', field: 'cvss', type: 'numeric' },
  { title: 'Package', field: 'package' },
  { title: 'Type', field: 'category' },
  { title: 'Installed', field: 'installed' },
  { title: 'Fixed in', render: f => f.fixed || 'no fix yet' },
  { title: 'Running on', render: f => f.clusters.map(c => data.clusters[c]?.title ?? c).join(', ') },
];

const ServiceInsights = ({ service, data }: { service: Service; data: NexusData }) => {
  const v = service.vulnerabilities;
  const r = service.readiness;
  return (
    <Grid container spacing={3}>
      <Grid item xs={12}><DataNote data={data} /></Grid>
      <Grid item xs={12}>
        <Table<Environment>
          title="Deployments: GitOps desired version against what Argo CD reports running"
          options={{ paging: false, search: false, padding: 'dense' }}
          columns={envColumns(data)}
          data={service.environments.map(e => ({ ...e }))}
        />
      </Grid>
      {service.live && (
        <Grid item xs={12}>
          <Table<Environment>
            title={`Live from the sandbox cluster (read ${service.live.observedAt})`}
            options={{ paging: false, search: false, padding: 'dense' }}
            columns={envColumns(data).filter(c => c.title !== 'Sync')}
            data={service.live.environments.map(e => ({ ...e }))}
          />
        </Grid>
      )}
      <Grid item md={4} xs={12}>
        <InfoCard title="Vulnerabilities in running images">
          <Kpi label="Open findings" value={v.open} note={<CountChips counts={v} />} />
          <Box mt={2}><Kpi label="In production images" value={v.production.open} note={<CountChips counts={v.production} />} /></Box>
          <Box mt={2}>
            <Typography variant="body2" color="textSecondary">
              Fix available for {v.fixable} of {v.open}. Microsoft Defender for Containers findings from ACR, last scan {v.lastScanned ?? 'n/a'}.
            </Typography>
          </Box>
        </InfoCard>
      </Grid>
      <Grid item md={8} xs={12}>
        <Table<Finding>
          title="Findings"
          options={{ pageSize: 10, padding: 'dense', search: true }}
          columns={findingColumns(data)}
          data={service.findings.map(f => ({ ...f }))}
        />
      </Grid>
      <Grid item xs={12}>
        <InfoCard title="Service Readiness">
          {!r.inScope && <Typography>No readiness criteria apply to service type {service.type}.</Typography>}
          {r.inScope && !r.currentStage && (
            <Typography color="textSecondary" paragraph>The service has no parent application or platform capability, so its current stage is unknown.</Typography>
          )}
          <Grid container spacing={2}>
            {Object.entries(r.stages).map(([stage, st]) => (
              <Grid item md={4} xs={12} key={stage}>
                <Typography variant="subtitle1">
                  {data.stageLabels[stage]}{stage === r.currentStage ? ' · current stage' : ''}
                </Typography>
                <PercentBar percent={st.percent} /> {st.met}/{st.applicable} met, {st.passed ? 'ready' : `${st.missing} missing`}
                {st.criteria.filter(c => c.status !== 'satisfied').map(c => (
                  <Typography variant="body2" key={c.id} color={c.status === 'missing' ? 'error' : 'textSecondary'}>
                    {c.status} · {c.name}{c.reason ? ` (${c.reason})` : ''}
                  </Typography>
                ))}
              </Grid>
            ))}
          </Grid>
        </InfoCard>
      </Grid>
    </Grid>
  );
};

const parentServices = (data: NexusData, name: string) => data.services.filter(s => s.parent === name);

const ParentInsights = ({ name, data }: { name: string; data: NexusData }) => {
  const services = parentServices(data, name);
  const columns: TableColumn<Service>[] = [
    { title: 'Service', field: 'title', render: s => <ServiceLink service={s} /> },
    { title: 'Lifecycle', field: 'lifecycle' },
    ...Object.entries(data.clusters).map(([id, c]) => ({
      title: c.title,
      render: (s: Service) => {
        const e = s.environments.find(x => x.cluster === id);
        return e ? (
          <span title={e.message}>
            <StateChip state={e.state} labels={data.stateLabels} />
            <Typography variant="caption" display="block" color="textSecondary">{shortVersion(e.liveVersion) || 'not deployed'}</Typography>
          </span>
        ) : '—';
      },
    })),
    { title: 'Vulnerabilities (C/H/M/L)', render: s => <CountChips counts={s.vulnerabilities} />, customSort: (a, b) => risk(a.vulnerabilities) - risk(b.vulnerabilities) },
    { title: 'Readiness', render: s => { const st = currentStage(s); return s.readiness.inScope ? (st ? <PercentBar percent={st.percent} /> : 'no stage') : 'n/a'; } },
  ];
  return (
    <Grid container spacing={3}>
      <Grid item xs={12}><DataNote data={data} /></Grid>
      <Grid item xs={12}>
        <Table<Service> title={`Services (${services.length})`} options={{ paging: false, padding: 'dense' }} columns={columns} data={services.map(s => ({ ...s }))} />
      </Grid>
    </Grid>
  );
};

/** The "Nexus insights" tab on Nexus services and on platform capability and application projects. */
export const NexusEntityInsightsContent = () => {
  const { entity } = useEntity();
  return (
    <DataGate inline>
      {data => {
        if (entity.kind === 'System') return <ParentInsights name={entity.metadata.name} data={data} />;
        const service = data.services.find(s => s.name === entity.metadata.name);
        return service ? (
          <ServiceInsights service={service} data={data} />
        ) : (
          <WarningPanel title="Not in the Nexus insights dataset" message={`No insights for ${entity.metadata.name}.`} />
        );
      }}
    </DataGate>
  );
};

const Summary = ({ services, data }: { services: Service[]; data: NexusData }) => {
  const envs = services.flatMap(s => s.environments);
  const counts = sumCounts(services.map(s => s.vulnerabilities));
  const single = services.length === 1 ? services[0] : undefined;
  const stage = single ? currentStage(single) : undefined;
  return (
    <Grid container spacing={2}>
      <Grid item md={5} xs={12}>
        <Typography variant="overline" color="textSecondary">Deployments</Typography>
        {single ? (
          single.environments.map(e => (
            <Box key={e.cluster} display="flex" alignItems="center" style={{ gap: 8 }}>
              <StateChip state={e.state} labels={data.stateLabels} />
              <Typography variant="body2">
                {data.clusters[e.cluster]?.title}: {shortVersion(e.liveVersion) || 'not deployed'}
                {e.state === 'drift' ? `, GitOps ${shortVersion(e.desiredVersion)}` : ''}
              </Typography>
            </Box>
          ))
        ) : (
          <Box display="flex" flexWrap="wrap" style={{ gap: 8 }}>
            {STATE_ORDER.filter(st => envs.some(e => e.state === st)).map(st => (
              <Typography variant="body2" key={st}>
                <StateChip state={st} labels={data.stateLabels} /> {envs.filter(e => e.state === st).length}
              </Typography>
            ))}
          </Box>
        )}
      </Grid>
      <Grid item md={4} xs={12}>
        <Kpi label="Vulnerabilities in running images" value={counts.open} note={<CountChips counts={counts} />} />
      </Grid>
      <Grid item md={3} xs={12}>
        {single ? (
          <Kpi label="Service Readiness" value={stage ? `${stage.percent}%` : 'n/a'}
               note={stage ? `${data.stageLabels[single.readiness.currentStage!]}, ${stage.missing} missing` : 'no criteria or stage'} />
        ) : (
          <Kpi label="Services" value={services.length} note={`${services.filter(s => currentStage(s)?.passed).length} ready for their stage`} />
        )}
      </Grid>
    </Grid>
  );
};

/** Summary card for the Overview tab; renders nothing for entities that are not from the Nexus Catalog. */
export const NexusInsightsOverviewCard = () => {
  const { entity } = useEntity();
  if (!isNexusEntity(entity)) return null;
  return (
    <Grid item xs={12}>
      <InfoCard title="Nexus insights" deepLink={{ title: 'Deployments, vulnerabilities and readiness', link: 'nexus-insights' }}>
        <DataGate inline>
          {data => {
            const services = entity.kind === 'System'
              ? parentServices(data, entity.metadata.name)
              : data.services.filter(s => s.name === entity.metadata.name);
            return services.length ? <Summary services={services} data={data} /> : <Typography>No insights for this entity.</Typography>;
          }}
        </DataGate>
      </InfoCard>
    </Grid>
  );
};
