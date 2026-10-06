# Container benchmark

This project owns isolated protocol interoperability, VCore native-TUN pressure, and matched VCore/Mihomo comparisons. Read `README.md` before changing workloads, cases, metrics or cleanup.

- Supply VCore explicitly through `--source vcore=PATH`; never infer a parent/sibling checkout. `interop --list` is offline and source-free. Production compilation and Rust memory/configuration regressions remain in VCore.
- Keep `interop`, `stress` and `compare` outcomes separate. Interop prefers official Mihomo listeners and retains official Xray-core, Hysteria2, V2Ray and Caddy supplements; comparisons include only VCore/Mihomo and share one workload/observer. Adapters prepare normal binaries, configuration and startup.
- Run every owned container on the same latest official Ubuntu LTS image, NAT, 5 CPUs and 8 GiB. Retain core defaults for threads, TUN rings, queues and socket buffers; disclose representation and routing differences.
- Keep every performance and memory-pressure run fixed to complete enhanced `geosite:cn` and `geoip:cn`. Download original DAT files and load only these two categories; change this selection only on an explicit user request.
- Check stable public dependencies once per local day in the ignored cache; freeze identities per session. Stop builders before load and record actual binary/source/rule identities.
- Keep actual throughput, CPU, RSS, directional UDP delivery and DNS completion separate. Mark unavailable data explicitly; measurements are not release or device acceptance.
- Keep shared dependencies in ignored `.cache/`, per-run inputs/builds/logs in `.work/`, and sanitized text in `conclusions/`. Join owned resources before deleting scratch; preserve shared downloads, unrelated resources and source checkouts.
- Run focused offline tests for code changes. Execute only the requested container smoke/matrix; offline/list results, interop, performance and physical-device/release acceptance are distinct evidence.
