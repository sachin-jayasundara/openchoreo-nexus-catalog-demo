import { ReactNode } from 'react';
import { Box, Chip, LinearProgress, Typography, makeStyles } from '@material-ui/core';
import { Content, Progress, WarningPanel } from '@backstage/core-components';
import { EntityRefLink } from '@backstage/plugin-catalog-react';
import {
  Counts,
  NexusData,
  SEVERITIES,
  Service,
  Severity,
  State,
  useNexusData,
} from './data';

const useStyles = makeStyles(theme => ({
  chip: { height: 22, fontWeight: 600, marginRight: 4, marginBottom: 2 },
  critical: { backgroundColor: '#e5484d', color: '#fff' },
  high: { backgroundColor: '#f76b15', color: '#111' },
  medium: { backgroundColor: '#ffc53d', color: '#111' },
  low: { backgroundColor: '#3e9bff', color: '#fff' },
  zero: { backgroundColor: theme.palette.action.disabledBackground, color: theme.palette.text.secondary },
  'in-sync': { backgroundColor: '#30a46c', color: '#fff' },
  drift: { backgroundColor: '#ffc53d', color: '#111' },
  degraded: { backgroundColor: '#e5484d', color: '#fff' },
  progressing: { backgroundColor: '#3e9bff', color: '#fff' },
  'not-deployed': { backgroundColor: theme.palette.action.disabledBackground, color: theme.palette.text.primary },
  'not-in-gitops': { backgroundColor: '#8e4ec6', color: '#fff' },
  kpi: { fontSize: 28, fontWeight: 600, lineHeight: 1.2 },
  progress: { width: 120, display: 'inline-block', marginRight: 8, verticalAlign: 'middle' },
}));

export const SeverityChip = ({ severity, value }: { severity: Severity; value?: ReactNode }) => {
  const classes = useStyles();
  const zero = value === 0;
  return (
    <Chip
      size="small"
      className={`${classes.chip} ${zero ? classes.zero : classes[severity]}`}
      label={value ?? severity.charAt(0).toUpperCase() + severity.slice(1)}
    />
  );
};

export const CountChips = ({ counts }: { counts: Counts }) => (
  <Box display="flex" flexWrap="nowrap">
    {SEVERITIES.map(s => (
      <SeverityChip key={s} severity={s} value={counts[s]} />
    ))}
  </Box>
);

export const StateChip = ({ state, labels }: { state: State; labels: Record<State, string> }) => {
  const classes = useStyles();
  return <Chip size="small" className={`${classes.chip} ${classes[state]}`} label={labels[state] ?? state} />;
};

export const Kpi = ({ label, value, note }: { label: string; value: ReactNode; note?: ReactNode }) => {
  const classes = useStyles();
  return (
    <Box>
      <Typography variant="overline" color="textSecondary">
        {label}
      </Typography>
      <div className={classes.kpi}>{value}</div>
      {note && (
        <Typography variant="body2" color="textSecondary">
          {note}
        </Typography>
      )}
    </Box>
  );
};

export const PercentBar = ({ percent }: { percent: number }) => {
  const classes = useStyles();
  return (
    <span>
      <LinearProgress className={classes.progress} variant="determinate" value={percent} />
      {percent}%
    </span>
  );
};

export const ServiceLink = ({ service }: { service: Service }) => (
  <EntityRefLink entityRef={{ kind: 'component', namespace: service.namespace, name: service.name }}>
    {service.title}
  </EntityRefLink>
);

export const TeamLink = ({ team, data }: { team: string; data: NexusData }) => (
  <EntityRefLink entityRef={{ kind: 'group', namespace: 'nexus-teams', name: team }}>
    {data.teams[team]?.title ?? team}
  </EntityRefLink>
);

export const ParentLink = ({ service, data }: { service: Service; data: NexusData }) => {
  if (!service.parent || !service.parentKind) {
    return (
      <Typography variant="body2" color="textSecondary">
        none
      </Typography>
    );
  }
  const application = service.parentKind === 'application';
  const title = (application ? data.applications : data.capabilities)[service.parent]?.title ?? service.parent;
  return (
    <EntityRefLink
      entityRef={{
        kind: 'system',
        namespace: application ? 'nexus-applications' : 'nexus-platform-capabilities',
        name: service.parent,
      }}
    >
      {title}
    </EntityRefLink>
  );
};

/** Renders children once the dataset has loaded, or a progress bar or an explanation. */
export const DataGate = ({ children, inline }: { children: (data: NexusData) => ReactNode; inline?: boolean }) => {
  const { value, loading, error } = useNexusData();
  const wrap = (node: ReactNode) => (inline ? <>{node}</> : <Content>{node}</Content>);
  if (loading) return wrap(<Progress />);
  if (error || !value) {
    return wrap(
      <WarningPanel severity="warning" title="Nexus insights are not available" message={error?.message ?? 'No data'} />,
    );
  }
  return <>{children(value)}</>;
};

export const DataNote = ({ data }: { data: NexusData }) => (
  <Typography variant="body2" color="textSecondary" paragraph>
    Catalog snapshot {data.catalogCommit}, generated {data.generatedAt}. {data.notes}
    {data.live?.observedAt ? ` Live sandbox workloads read at ${data.live.observedAt}.` : ''}
  </Typography>
);
