# Container benchmark

This project compares only VCore and Mihomo using native TUN. Read `README.md` for the workload, Mermaid XYChart results and metric definitions.

- Share one workload, Linux process observer and runner. Adapters only prepare normal binaries, configuration and startup. Supply the VCore checkout through `--source vcore=PATH`; download the official latest stable Mihomo binary.
- Run every owned container on the same latest official Ubuntu LTS image, NAT, 5 CPUs and 8 GiB. Retain core defaults for threads, TUN rings, queues and socket buffers; disclose representation and routing differences.
- Check stable public dependencies once per local day in the ignored cache; freeze identities per session. Stop builders before load and record actual binary/source/rule identities.
- Keep actual throughput, CPU, RSS, directional UDP delivery and DNS completion separate. Mark unavailable data explicitly; measurements are not release or device acceptance.
- Write aggregate text results, join owned processes/containers and remove per-run scratch. Preserve shared downloads, unrelated resources and source checkouts; scope cleanup to recorded ownership.
- Validate changes with focused offline tests and a short native-TUN smoke before the explicitly requested comparison matrix.
