# Bursa Grafana Dashboards

| Dashboard | File | Description |
|-----------|------|-------------|
| **Bursa — KES Agent** | `bursa-kes-agent.json` | KES agent replicas, signing and guard-write latency against the producers' sign timeout, signs by profile and result, slot-guard refusals and store errors, key evolutions, and KES periods left per profile |

## Prerequisites

- **Grafana 12+** with the
  **[Business Text plugin](https://grafana.com/grafana/plugins/marcusolsson-dynamictext-panel/)**
  (`marcusolsson-dynamictext-panel`) for the header panel.
- **Prometheus** scraping the KES agent's `/metrics` endpoint (see
  [Health and metrics](../signer/kes-agent.md#health-and-metrics)), with
  `namespace` and `pod` labels on its series.
- The KES agent deployed on Kubernetes by the `bursa` Helm chart in
  `kes-agent` mode. The replica panels find agents through the chart's
  `<release>-kes-agent` ConfigMap and read **kube-state-metrics** and
  **cAdvisor** for deployment replicas, pod readiness, restarts and memory.
  Agent pods are found through their ReplicaSet and Deployment owners
  (`kube_pod_owner`, `kube_replicaset_owner`).
- Producers running Dingo with the KES agent in sign mode, with their Dingo
  metrics scraped into the same Prometheus datasource, for the producer
  round-trip series (`dingo_kes_agent_sign_latency_seconds`). That metric
  carries no label linking a producer to an agent, so the round-trip series
  cover every producer in the datasource and ignore the `$namespace`,
  `$profile` and `$pod` variables.

## Datasource

Every panel queries the Prometheus datasource selected by the `$datasource`
variable, which starts on the datasource marked default.

## Template variables

| Variable | Purpose |
|----------|---------|
| `$datasource` | Prometheus datasource every panel and variable queries. |
| `$namespace` | Namespaces running a KES agent. |
| `$profile` | KES agent profiles (`profile` label). |
| `$pod` | KES agent replicas. |

## Sign budget

Latency panels are drawn against Dingo's default KES agent sign timeout of
500 ms (`CARDANO_SHELLEY_KES_AGENT_SIGN_TIMEOUT`): amber from 250 ms, red from
400 ms. A producer configured with a different timeout needs the thresholds
on the signing panels adjusted to match.

## Navigation

The dashboard is tagged `dingo` and has a **Dingo** menu in the top bar that
lists every loaded dashboard with that tag, such as the Dingo operator
dashboards (`dingonodes`, `dingo-forging`, `dingo-operator`) from the
`dingo-operator` repository, which show the producers this agent signs for.
The menu keeps the time range and the `$datasource` selection.
