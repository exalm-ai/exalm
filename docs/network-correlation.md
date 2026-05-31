# Network-layer correlation (Hubble)

Exalm can correlate Kubernetes findings with L4/L7 network flow data captured by [Hubble](https://github.com/cilium/hubble) — Cilium's eBPF-backed observability layer. This lets you tell *application regression* apart from *network policy drops* and *DNS failures*, a class of incident neither OpenObserve nor Komodor can diagnose today.

## Phase 5 status

This release ships the **adapter and correlation logic** with mocked unit tests. The production gRPC client to Hubble Relay is **deferred** — the Cilium API package (`github.com/cilium/cilium/api/v1/observer`) is intentionally not yet added to keep the binary lean (per the project's stdlib-first rule).

The shape is final, the wire path is stubbed. When Hubble Relay support lands, callers swap `network.Dial(addr)` for the real gRPC dial and everything downstream — `CorrelateDrops`, `SummarizeReason`, evidence-chain integration — works unchanged.

## How it will work in production

1. **Deploy** Cilium with Hubble Relay enabled in your cluster.
2. **Configure** the Hubble endpoint:
   ```sh
   exalm k8s analyze --hubble-endpoint hubble-relay.kube-system:4245
   ```
3. **Use the data**:
   - Each pod-related finding queries Hubble for flows in the 5-minute window before the finding's first observation.
   - `DROPPED` and `ERROR` verdicts become `EvidenceItem` entries on the finding with kind `"network"`.
   - The dashboard's expanded card shows the dropped-flow line: e.g. *`DROPPED TCP exalm-prod/api → kube-system/coredns:53 (policy-deny)`*.

## Why ship the adapter now

- **Tests pass against a mock** (`internal/network/hubble_test.go`), so the correlation logic is verified.
- **Other modules don't have to know** whether Hubble is connected — they call `client.RecentFlows(...)` and either get flows or a graceful "not connected" error.
- **Competitive positioning** is settled: anyone reading the codebase sees the gap is filled at the type-and-test level even before the gRPC client lands.

## What's deferred

| Item | Why deferred | Where it lives next |
|------|--------------|--------------------|
| Real Hubble gRPC dial | Adds ~2 MB to the binary; needs a Cilium-running cluster to test | Phase 6 or later, behind a build tag |
| Webhook ingest from Hubble | Same; eBPF/network-layer is a maturity-curve away | Phase 3 roadmap item |
| L7 HTTP/gRPC parse | Hubble already does this; we just need to expose it | After gRPC client |
