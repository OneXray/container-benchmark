# VCore tests and TUN benchmark

本工程托管 VCore 的隔离协议互通、GeoData 内存压力与 **VCore / Mihomo** 原生 TUN 横向比较。
VCore 仓库的脚本只负责编译；这里通过显式源码路径使用其生产 ABI。
横向比较观察实际带宽、CPU、Linux RSS 观测峰值、UDP 丢包率。
两者复用同一 Go 流量客户端、网络设施、外部 PID 采样器与统计代码；适配层只负责正常构建、配置和启动。

## 横向比较的固定环境与负载

- Apple Silicon macOS + Apple 官方 `container`；每个自有容器 **5 CPU / 8 GiB**。
- 构建、被测内核、两个隔离原站使用同一官方最新 **Ubuntu LTS digest**，通过 NAT 连接。
  先完成构建并销毁 builder，再启动负载；负载期间仅保留两个原站容器与一个被测容器。
- **1 / 1.5 / 2 Gbps** 三档；每档新进程，60 秒混合 TCP + UDP，上下行有效载荷总量。
- 总计 64 条业务流；每条 UDP 源 socket 轮流访问 64 个目的端口，速率不乘倍。
- 同步叠加 1000 QPS 唯一名称 DNS 查询，CN GeoSite 命中与未命中两支各承担一半业务。
- 仅引用增强 GeoData 的 `geosite:cn` / `geoip:cn`，使用同一原始 DAT 与拒绝见证。
- TUN ring、eth0 队列、qdisc、socket 缓冲和线程策略保持默认，不为单个内核调参。
- 每日检查一次公共依赖，每轮冻结实际版本、镜像 digest、源码与二进制 SHA256。

所有业务出口为 DIRECT；这是原生 TUN、GeoData 与 DNS 的混合负载比较，不是加密代理协议比较。
内核输出统一持续排空、仅保留前 1 MiB，不因日志超限终止内核；日志生成开销仍计入 CPU。

## 运行

```sh
# 隔离协议互通；--list 可离线使用，不需要源码或容器
uv run --locked container-benchmark interop --list
uv run --locked container-benchmark interop --source vcore=/absolute/path/to/VCore

# VCore 单核内存压力；默认 128 万原始 GeoData 记录、2 Gbps、60 秒、1000 QPS DNS
uv run --locked container-benchmark stress \
  --source vcore=/absolute/path/to/VCore --geodata-records 1280000

# 完整 CN 双核横向比较，与大容量压力场景分开
uv run --locked container-benchmark compare \
  --source vcore=/absolute/path/to/VCore

# 单核启动短测，不作为正式性能数据
uv run --locked container-benchmark compare --core mihomo --rates 1000 --seconds 3

uv run --locked container-benchmark self-test
uv run --locked python maintenance/verify_go_fixtures.py
```

默认比较两款内核，`--core` 仅接受 `vcore` / `mihomo`。
VCore 通过 `--source vcore=PATH` 提供正常 Release checkout；Mihomo 始终下载官方最新稳定二进制，不本地编译。
可用 `--rates` 选择档位、`--seconds` 缩短测试；公共设施不假设项目目录关系。

### 协议互通

保留 64 个代表用例，优先 Mihomo listener；其不支持的字段由官方 Xray-core、
Hysteria2、V2Ray 与 Caddy 补验，`--backend` / `--protocol` 可筛选。
所有服务端和消费者都在隔离容器中，使用 5 CPU / 8 GiB、最新 Ubuntu LTS 与 NAT；
失败不回退宿主。2026-10-06 迁移后已通过一次 Mihomo SOCKS5 TCP/UDP 短测：
TCP 双向各 1,024 bytes、UDP 双向各两包（64 / 1,200 bytes），核对原站所见来源与
正常 Stop，容器和临时产物已清理。完整 64 用例矩阵本次未重跑，离线验证不能代替它。
互通模块、fixture 和离线回归原属 VCore，保留其 [MIT 许可](src/container_benchmark/interop/LICENSE)。

### 128 万 GeoData 内存压力

使用同一官方增强 DAT 的真实记录，不复制或伪造记录凑数。先选取 GeoIP，再从
GeoSite 大分类中保留前缀，使实际引用的原始 CIDR + Domain 总量恰为指定值。
按归一 code 排序截取分类内原始前缀；输入原件不改动，派生 fixture 的 hash、
分类与数量写入文字结论。DNS 与 TUN 分流见证来自保留的 CN 前缀。

该场景与完整 CN 的横向比较分开，默认仅运行 VCore，仍使用 64 流、2 Gbps、
1000 QPS DNS、60 秒，观察整个启动/负载/排空期间的内核进程 RSS 峰值，
单独记录是否低于 50,000,000 bytes。Linux 不启用 iOS/tvOS 的数量截断，
因此由明确派生的规则 fixture 提供相同总量；结果不是 Apple physical footprint
或移动平台截断路径的真机验收。

2026-10-06（Asia/Shanghai）已执行一次正式 60 秒压力测试。VCore 为
`71445c28` 加本轮未提交修改，源码 diff SHA256 为
`9044ee6a8c31fce4d78e5f2b7da8f8b6007a8467511373e07d35a94a6b128077`。
使用增强 DAT `202610042206`：260 类 GeoIP 共 **1,054,987** 条，GeoSite
`category-ads-all` **187,402** 条 + `cn` **37,611** 条，共 **225,013** 条，
原始记录总计 **1,280,000**。GeoIP 优先后 CN 仅保留前缀，本轮 Site 包含 Domain/Full，
不覆盖 Plain/Regex 或复杂正则的最坏内存。

| 指标 | 2 Gbps / 60 秒 / 1,000 QPS DNS |
| --- | --- |
| 实际带宽 | 1,989.45 Mbps |
| CPU | 146.93%（100% = 一个逻辑核） |
| Linux RSS 峰值 | **42,557,440 bytes / 40.59 MiB**，低于 50,000,000 bytes |
| UDP 丢包 | 2,513 / 6,249,984 包，**0.0402%**；上行 2,069，下行 444 |
| DNS | 计划 60,000，发送 59,998，成功 59,912；timeout 86、skipped 2 |

该轮满足既有 99% 吞吐/DNS 负载判定与 RSS 目标，但仍有 UDP 未完整交付和 DNS 超时，
**不是零丢包或全部成功验收**。观测器无采样错误，正常退出，本轮容器和 scratch
已清理；原始脱敏文字结论仅在本机忽略目录中保留。结果不保证其他分类组合、
正则复杂度、资产更新叠加或 Apple 真机内存。

### 横向比较的适配差异

| 内核 | 原生入口 / GeoData |
| --- | --- |
| VCore | 原始 FD、原生 DAT；无自带 Linux CLI，最小 C 适配仅调用生产生命周期 ABI |
| Mihomo | 原始 FD、原生 DAT；本轮稳定版默认 MIPS、memconservative 与 redir-host |

VCore 所需的未使用具体节点及 REJECT 组只为满足配置模型，不增加业务路径。
默认 TUN 栈与 DNS 域名提示实现的差异保留，不宣称内部执行方式完全等价。

## 指标口径

- **实际带宽**：60 秒活动窗口内收到的有效载荷，不将固定 3 秒收尾计入 goodput。
- **CPU**：进程 CPU 秒 / 采样墙钟秒 × 100%；**100% 表示一个逻辑核，5 CPU 上限为 500%**。
  包含公共负载准备和收尾，排除编译、下载与内核启动。
- **内存**：验证 PID / 可执行文件身份后，20 ms 采样中观测到的最大 Linux VmHWM / VmRSS，
  覆盖启动、连通检查、负载和收尾；采样在退出信号前停止，不宣称包含退出阶段的完整峰值。
  `wait4` 可能计入 exec 前启动器占用，仅作独立诊断值，不用于内存排名。
  不包含客户端与原站，也不作为 Apple Provider 内存验收。
- **UDP 丢包率**：`(实际发送包 - 实际收到包) / 实际发送包`，包含固定收尾内的接收；
  合计按包数加权，保留上下行独立计数，不把发送不足当作丢包。
- DNS 发送不足、skipped / timeout 单独记录；TCP 内容校验不等于零网络丢包。
  不可用数据写 N/A，不补零；runner 的 `PASS` 仅表示带宽与 DNS 各自达到 99% 阈值。

内存口径参见 [Linux exec RSS 记账](https://raw.githubusercontent.com/gregkh/linux/v6.18.35/fs/exec.c)。

## 实测结果：Bar Chart

以下复用 **2026-10-05–06（Asia/Shanghai）**正式测试中的两核六行有效数据；本次范围和图表调整未重跑 60 秒矩阵。
宿主 Apple M5、10 核、32 GiB，`container` 1.5.0；容器 Ubuntu 26.04.1 LTS。
每容器 5 vCPU 不代表独占五个物理核，所有容器共享宿主资源。
镜像 digest：`sha256:f144425ff09be612d6d9ad965196e9cdc23dae1f42110a8a11a3e9a8198759f7`。
版本：VCore `a0e1fb1`、Mihomo `1.19.32`；CN 分类 121,009 条（GeoSite 111,361、GeoIP 9,648）。
RSS 取清理前独立核对并保全的 `/proc` 峰值，不使用旧记录中混入启动器峰值的字段。

五张图使用 Mermaid XYChart 的柱状图，统一使用 **VCore 蓝色 / Mihomo 橙色**、命名图例；渲染需 Mermaid ≥ 11.17。
每档负载的两款内核并排展示；序列中的 `0` 仅用于另一款内核的横轴占位，不代表实测值。
参见 [官方 XYChart 命名序列语法](https://mermaid.js.org/syntax/xyChart.html#legend-v11-17-0)。

### 实际带宽

```mermaid
---
config:
  themeVariables:
    xyChart:
      plotColorPalette: "#2563eb,#ea580c"
---
xychart
    title "实际带宽"
    x-axis "目标负载（Gbps） / 内核" ["1 VCore", "1 Mihomo", "1.5 VCore", "1.5 Mihomo", "2 VCore", "2 Mihomo"]
    y-axis "有效载荷（Mbps）" 0 --> 2100
    bar "VCore" [997.7, 0, 1496.2, 0, 1991.5, 0]
    bar "Mihomo" [0, 996.3, 0, 1492.1, 0, 1987.3]
```

### CPU

```mermaid
---
config:
  themeVariables:
    xyChart:
      plotColorPalette: "#2563eb,#ea580c"
---
xychart
    title "CPU 占用（100% = 一个逻辑核）"
    x-axis "目标负载（Gbps） / 内核" ["1 VCore", "1 Mihomo", "1.5 VCore", "1.5 Mihomo", "2 VCore", "2 Mihomo"]
    y-axis "CPU（%）" 0 --> 200
    bar "VCore" [91.8, 0, 117.7, 0, 148.3, 0]
    bar "Mihomo" [0, 115.2, 0, 147.0, 0, 172.1]
```

### 内存

```mermaid
---
config:
  themeVariables:
    xyChart:
      plotColorPalette: "#2563eb,#ea580c"
---
xychart
    title "Linux RSS 观测峰值"
    x-axis "目标负载（Gbps） / 内核" ["1 VCore", "1 Mihomo", "1.5 VCore", "1.5 Mihomo", "2 VCore", "2 Mihomo"]
    y-axis "RSS（MiB）" 0 --> 120
    bar "VCore" [23.6, 0, 25.3, 0, 26.9, 0]
    bar "Mihomo" [0, 98.6, 0, 102.4, 0, 105.1]
```

### UDP 丢包率

```mermaid
---
config:
  themeVariables:
    xyChart:
      plotColorPalette: "#2563eb,#ea580c"
---
xychart
    title "UDP 合计丢包率"
    x-axis "目标负载（Gbps） / 内核" ["1 VCore", "1 Mihomo", "1.5 VCore", "1.5 Mihomo", "2 VCore", "2 Mihomo"]
    y-axis "丢包率（%）" 0 --> 1
    bar "VCore" [0.0206, 0, 0.0457, 0, 0.0464, 0]
    bar "Mihomo" [0, 0.4237, 0, 0.6726, 0, 0.9001]
```

### DNS 成功次数

每档计划 60,000 次；纵轴从零开始，不放大各档差异。

```mermaid
---
config:
  themeVariables:
    xyChart:
      plotColorPalette: "#2563eb,#ea580c"
---
xychart
    title "DNS 成功次数（每档计划 60,000 次）"
    x-axis "目标负载（Gbps） / 内核" ["1 VCore", "1 Mihomo", "1.5 VCore", "1.5 Mihomo", "2 VCore", "2 Mihomo"]
    y-axis "成功查询（次）" 0 --> 60000
    bar "VCore" [59921, 0, 59890, 0, 59972, 0]
    bar "Mihomo" [0, 59510, 0, 59321, 0, 59371]
```

| 内核 | 1 Gbps | 1.5 Gbps | 2 Gbps |
| --- | ---: | ---: | ---: |
| VCore | 59,921 | 59,890 | 59,972 |
| Mihomo | 59,510 | 59,321 | 59,371 |

本轮两者实际带宽均接近目标，VCore 的 CPU、观测 RSS、UDP 丢包率低于 Mihomo；
但六行均有 UDP 丢包，DNS 也未全部成功。单轮顺序测试与默认配置差异不证明稳定上限或跨平台性能。

## 存储与清理

`.cache/` 保存被忽略的共享下载；`.work/run-*/` 为本轮临时输入和编译产物。
先 join 自有进程 / 容器，保存本机 `conclusions/*.md` 文字证据，再删除本轮临时产物。
README 保存可提交的汇总；共享缓存、历史文字证据和源码 checkout 保留，不提交 `conclusions/`。
上述六行的原始证据为 `conclusions/20261005T162024343755Z-run-z8vwu9ra.md`，包含固定版本、SHA256 与独立 RSS 核对。
