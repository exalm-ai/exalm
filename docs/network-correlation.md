# Network-layer correlation (Hubble) — EXPERIMENTAL

> **Status: experimental, not wired.** This is a design + adapter preview, **not
> a shipping feature**. The `internal/network` package is not referenced by any
> command, there is no `--hubble-endpoint` flag today, and nothing in the CLI or
> dashboard consumes network flows yet. This document describes the intended
> design so contributors can help finish it — it is not a description of current
> behavior.

The goal is to correlate Kubernetes findings with L4/L7 network flow data captured by [Hubble](https://github.com/cilium/hubble) — Cilium's eBPF-backed observability layer — so you can tell *application regression* apart from *network policy drops* and *DNS failures*.

## Current status

The repository contains the **adapter and correlation logic** with mocked unit tests only. The production gRPC client to Hubble Relay is **deferred** — the Cilium API package (`github.com/cilium/cilium/api/v1/observer`) is intentionally not yet added to keep the binary lean.

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
- **The contract is settled** at the type-and-test level, so the gRPC client can land later without reshaping the callers.

## What's deferred

| Item | Why deferred | Where it lives next |
|------|--------------|--------------------|
| Real Hubble gRPC dial | Adds ~2 MB to the binary; needs a Cilium-running cluster to test | a future release, behind a build tag |
| Webhook ingest from Hubble | Same; eBPF/network-layer is a maturity-curve away | a roadmap item |
| L7 HTTP/gRPC parse | Hubble already does this; we just need to expose it | After gRPC client |
