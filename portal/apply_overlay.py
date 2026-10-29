#!/usr/bin/env python3
"""Add the Nexus insights views to a checkout of openchoreo/backstage-plugins (tested against v1.2.2).

Copies portal/nexusInsights into packages/app/src/components/nexusInsights and edits three app files:
  App.tsx          route /nexus-insights
  Root.tsx         sidebar item "Nexus insights"
  EntityPage.tsx   "Nexus insights" tab and overview card on Nexus services and projects, and hides the
                   OpenChoreo build, deploy and runtime tabs for entities imported from the Nexus Catalog
Every edit asserts how often its anchor occurs, so an upstream change fails the build instead of the page.
"""

import os
import re
import shutil
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
OPENCHOREO_TABS = ["definition", "workflows", "environments", "runtime-logs", "runtime-events", "metrics", "alerts",
                   "deploy", "cell-diagram", "logs", "traces", "incidents", "rca-reports", "cost-analysis"]


def edit(path, edits):
    with open(path, encoding="utf-8") as f:
        text = f.read()
    for anchor, replacement, expected in edits:
        found = text.count(anchor)
        if found != expected:
            sys.exit(f"{path}: expected {expected} occurrence(s) of {anchor!r}, found {found}")
        text = text.replace(anchor, replacement)
    return text


def write(path, text):
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write(text)


def main(root):
    app = os.path.join(root, "packages", "app", "src")
    target = os.path.join(app, "components", "nexusInsights")
    shutil.rmtree(target, ignore_errors=True)
    os.makedirs(target)
    for name in sorted(os.listdir(os.path.join(HERE, "nexusInsights"))):
        with open(os.path.join(HERE, "nexusInsights", name), encoding="utf-8") as f:
            write(os.path.join(target, name), f.read())

    path = os.path.join(app, "App.tsx")
    write(path, edit(path, [
        ("import { PlatformOverviewPage } from './components/platformOverview';\n",
         "import { PlatformOverviewPage } from './components/platformOverview';\n"
         "import { NexusInsightsPage } from './components/nexusInsights';\n", 1),
        ('    <Route path="/platform-overview" element={<PlatformOverviewPage />} />\n',
         '    <Route path="/platform-overview" element={<PlatformOverviewPage />} />\n'
         '    <Route path="/nexus-insights" element={<NexusInsightsPage />} />\n', 1),
    ]))

    path = os.path.join(app, "components", "Root", "Root.tsx")
    write(path, edit(path, [
        ("import BubbleChartIcon from '@material-ui/icons/BubbleChart';\n",
         "import BubbleChartIcon from '@material-ui/icons/BubbleChart';\n"
         "import AssessmentIcon from '@material-ui/icons/Assessment';\n", 1),
        ('                  text="Platform"\n                />\n',
         '                  text="Platform"\n                />\n'
         '                <SidebarItem\n'
         '                  icon={AssessmentIcon}\n'
         '                  to="nexus-insights"\n'
         '                  text="Nexus insights"\n'
         '                />\n', 1),
    ]))

    path = os.path.join(app, "components", "catalog", "EntityPage.tsx")
    insights_tab = ('      <EntityLayout.Route path="/nexus-insights" title="Nexus insights" if={isNexusEntity}>\n'
                    '        <NexusEntityInsightsContent />\n'
                    '      </EntityLayout.Route>\n')
    text = edit(path, [
        ("import { Grid } from '@material-ui/core';\n",
         "import { Grid } from '@material-ui/core';\n"
         "import {\n  NexusEntityInsightsContent,\n  NexusInsightsOverviewCard,\n  isNexusEntity,\n  isNotNexusEntity,\n} from '../nexusInsights';\n", 1),
        # Overview of components: our card first, OpenChoreo's CI and deployment cards only for OpenChoreo components.
        ("      {entityWarningContent}\n      <EntitySwitch>\n        <EntitySwitch.Case if={isKind('component')}>\n          {/* Failed-build",
         "      {entityWarningContent}\n      <NexusInsightsOverviewCard />\n      <EntitySwitch>\n"
         "        <EntitySwitch.Case if={e => isKind('component')(e) && isNotNexusEntity(e)}>\n          {/* Failed-build", 1),
        # Service and generic component pages: tab right after Overview.
        ("        <OverviewContent />\n      </EntityLayout.Route>\n",
         "        <OverviewContent />\n      </EntityLayout.Route>\n\n" + insights_tab, 2),
        # Project (System) page: card under Project Contents, pipeline card only for OpenChoreo projects, tab after Overview.
        ("          <ProjectContentsCard />\n        </Grid>\n",
         "          <ProjectContentsCard />\n        </Grid>\n        <NexusInsightsOverviewCard />\n", 1),
        ("        <Grid item md={6} xs={12}>\n          <DeploymentPipelineCard />\n        </Grid>\n",
         "        <EntitySwitch>\n          <EntitySwitch.Case if={isNotNexusEntity}>\n"
         "            <Grid item md={6} xs={12}>\n              <DeploymentPipelineCard />\n            </Grid>\n"
         "          </EntitySwitch.Case>\n        </EntitySwitch>\n", 1),
        ('        {/* Row 3: Catalog Relations, full width */}\n        <Grid item xs={12}>\n'
         '          <EntityCatalogGraphCard height={400} renderNode={CustomGraphNode} />\n        </Grid>\n      </Grid>\n'
         '    </EntityLayout.Route>\n    <EntityLayout.Route path="/definition" title="Definition">\n',
         '        {/* Row 3: Catalog Relations, full width */}\n        <Grid item xs={12}>\n'
         '          <EntityCatalogGraphCard height={400} renderNode={CustomGraphNode} />\n        </Grid>\n      </Grid>\n'
         '    </EntityLayout.Route>\n'
         '    <EntityLayout.Route path="/nexus-insights" title="Nexus insights" if={isNexusEntity}>\n'
         '      <NexusEntityInsightsContent />\n'
         '    </EntityLayout.Route>\n'
         '    <EntityLayout.Route path="/definition" title="Definition">\n', 1),
    ])
    pattern = re.compile(r'<EntityLayout\.Route path="/(' + "|".join(map(re.escape, OPENCHOREO_TABS)) + r')" title="([^"]+)">')
    text, hidden = pattern.subn(r'<EntityLayout.Route path="/\1" title="\2" if={isNotNexusEntity}>', text)
    if hidden < 20:
        sys.exit(f"{path}: expected at least 20 OpenChoreo tabs to gate, found {hidden}")
    write(path, text)
    print(f"Nexus insights overlay applied to {root}: {hidden} OpenChoreo tabs hidden for Nexus entities")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else ".")
