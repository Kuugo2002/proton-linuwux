<p align="center">
  <img src="assets/banner.svg" alt="Proton-LinUwUx" width="900">
</p>

<p align="center">
  集成 <strong>LinUwUx Rework</strong> 兼容层的 Proton-GE 与 Proton-CachyOS 构建。
</p>

<p align="center">
  <a href="#downloads"><strong>发布版本</strong></a>
  ·
  <a href="https://sourceforge.net/projects/proton-linuwux/files/"><strong>二进制下载</strong></a>
  ·
  <a href="https://t.me/+EdH8jcUUzcA2MmFk"><strong>支持</strong></a>
</p>

<p align="center">
  <a href="#downloads">下载</a>
  ·
  <a href="#features">特性</a>
  ·
  <a href="#installation">安装</a>
  ·
  <a href="#faq">常见问题</a>
</p>

---

<a id="about"></a>

## 关于

**Proton-LinUwUx** 提供集成 **LinUwUx Rework** 兼容层的 x86_64 版 Proton-GE 与 Proton-CachyOS 构建。

本项目基于最初的 LinUwUx 补丁以及其开发者 **LinUwUx** 的工作成果构建，正是该实现为本项目所保留的兼容行为奠定了基础。

当前的 **LinUwUx Rework** 并未取代那项工作，而是将其重构并扩展为一个更模块化、更健壮、更易维护的兼容层：既保留原有 LinUwUx 行为，又让集成过程更容易适应未来的 Proton/Wine 变更、运行时协议变体以及上游结构变动。

原始补丁及相关讨论可参见 [cs.rin.ru](https://cs.rin.ru/forum/viewtopic.php?f=10&t=159989)。

> [!TIP]
> [**LinUwUx Runtime**](https://github.com/brcly/proton-LinUwUx-patch)：由 **LinUwUx、brcly、xXJSONDeruloXx 及其他贡献者**开发的 Runtime 是使用 LinUwUx 的主要且推荐方案。它把底层的兼容概念带出被修改的 Proton 构建，提供了一种更独立、也更 inherently robust 的解决途径。Proton-LinUwUx Rework 与其并行维护，作为替代与回退实现，在需要兼容、测试或适合 Proton 集成实现的场景中保留「打补丁的 Proton」这一思路。

> [!NOTE]
> Proton 与 Wine 仍在持续演进，因此与未来上游版本的兼容性可能需要后续维护更新。本项目目前处于稳定里程碑阶段，后续工作主要集中在与新版 Proton/Wine 的兼容性、回归问题以及用户反馈的问题修复上。

> [!IMPORTANT]
> 这些构建不会加入与本项目无关的性能优化调整。项目特有的改动仅限于 LinUwUx 兼容层、它的集成方式，以及维护和排障该兼容层所必需的诊断功能。

<a id="features"></a>

## 特性

- 以独立发布版本的形式同时支持 Proton-GE 与 Proton-CachyOS。
- 提供开箱即用的 x86_64 兼容工具压缩包。
- 包含用于应用 LinUwUx Rework 以及构建受支持的 Proton/Wine 代码树的自动化流程。
- 包含结构性诊断功能，帮助识别可能破坏自动化流程的上游改动。
- 包含可选的 `LINUWUX_DEBUG=1` 运行时诊断，用于排查兼容性问题与回归问题。

<a id="available-builds"></a>

## 可用构建

| 构建 | 上游项目 | 架构 | 说明 |
|---|---|---:|---|
| **Proton-GE LinUwUx** | [GloriousEggroll/proton-ge-custom](https://github.com/GloriousEggroll/proton-ge-custom) | x86_64 | 集成 LinUwUx Rework 的受支持 Proton-GE 发行版。 |
| **Proton-CachyOS LinUwUx** | [CachyOS/proton-cachyos](https://github.com/CachyOS/proton-cachyos) | x86_64 | 集成 LinUwUx Rework 的受支持 Proton-CachyOS 发行版。 |

<a id="downloads"></a>

## 下载

发布信息发布于：

<p align="center">
  <strong>
    <a href="https://codeberg.org/xshaduwulfx/proton-linuwux/releases">Codeberg Releases（上游）</a>
    ·
    <a href="https://github.com/Kuugo2002/proton-linuwux/releases">GitHub Releases</a>
  </strong>
</p>

二进制压缩包托管于：

<p align="center">
  <strong>
    <a href="https://sourceforge.net/projects/proton-linuwux/files/">SourceForge</a>
  </strong>
</p>

每个二进制压缩包都附带一个 `.sha256` 校验和文件，并包含一个完整的兼容工具目录，可直接解压到受支持的兼容工具位置。

<a id="installation"></a>

## 安装

### Steam

1. 通过 [Releases](/Kuugo2002/proton-linuwux/releases) 下载所需的压缩包。
2. 将其解压到以下目录之一：

   ```text
   ~/.steam/root/compatibilitytools.d/
   ~/.local/share/Steam/compatibilitytools.d/
   ~/.var/app/com.valvesoftware.Steam/.local/share/Steam/compatibilitytools.d/
   ```

3. 如果所选目录尚不存在，请先创建。
4. 重启 Steam。
5. 右键点击游戏，打开 **属性 → 兼容性**。
6. 启用 **强制使用特定的 Steam Play 兼容工具**。
7. 选择已安装的 Proton-LinUwUx 构建。

### Heroic Games Launcher

1. 通过 [Releases](/Kuugo2002/proton-linuwux/releases) 下载所需的压缩包。

2. 将 Proton-LinUwUx 目录解压到相应的 Heroic Proton 目录：

   **原生安装：**

   ```text
   ~/.config/heroic/tools/proton/
   ```

   **Flatpak 安装：**

   ```text
   ~/.var/app/com.heroicgameslauncher.hgl/config/heroic/tools/proton/
   ```

3. 如果所选目录尚不存在，请先创建。

4. 重启 Heroic Games Launcher。

5. 在 **Library（游戏库）** 中选择所需的游戏。

6. 打开该游戏的 **设置**。

7. 打开 **Wine** 部分。

8. 在 **Wine 版本** 中选择已安装的 Proton-LinUwUx 构建。

9. 启动游戏。

### Lutris

1. 通过 [Releases](/Kuugo2002/proton-linuwux/releases) 下载所需的压缩包。

2. 将 Proton-LinUwUx 目录解压到 Lutris 的自定义 Wine 运行器目录：

   **原生安装：**

   ```text
   ~/.local/share/lutris/runners/wine/
   ```

   **Flatpak 安装：**

   ```text
   ~/.var/app/net.lutris.Lutris/data/lutris/runners/wine/
   ```

3. 如果所选目录尚不存在，请先创建。

4. 重启 Lutris。

5. 在 **Library（游戏库）** 中选择所需的游戏。

6. 打开该游戏的 **配置（Configure）** 菜单。

7. 打开 **运行器选项** 选项卡。

8. 在 **Wine 版本** 中选择已安装的 Proton-LinUwUx 构建。

9. 保存配置并启动游戏。

### Faugus Launcher

1. 将构建解压到上文列出的某个 Steam 兼容工具目录中。
2. 使用 Flatpak 版 Faugus Launcher 时，请打开 **Flatseal**。
3. 选择 Faugus Launcher，并在 **Filesystems → Other files** 下添加解压路径。
4. 打开：

   ```text
   ~/.var/app/io.github.Faugus.faugus-launcher/data/faugus-launcher/games.json
   ```

5. 找到对应的游戏条目，将其 `"runner"` 值设置为解压后 Proton 目录的绝对路径。

> [!NOTE]
> 在添加游戏或修改启动选项之后，可能需要重新设置一次运行器路径。

<a id="variables"></a>

## 变量

### AVX 兼容性

某些游戏可能需要由 LinUwUx 兼容层暴露出 AVX 支持。

如果游戏提示需要 AVX 或 AVX2 支持，可以尝试使用以下方式启动：

```text
PROTON_AVX=1
```

请仅对确实需要该选项的游戏启用此选项。那些在未启用 AVX 支持的情况下生成的令牌，在开启 `PROTON_AVX=1` 后可能无法启动。

因此，该选项应当按单个游戏进行配置，而不是全局启用。

### 系统调用兼容模式

某些游戏可能需要启用可选的 LinUwUx 系统调用兼容模式：

```text
LINUWUX_SYSCALL_HACK=1
```

该模式默认关闭，不应全局启用。

如果某个游戏无法启动，可以尝试为该游戏启用 `LINUWUX_SYSCALL_HACK=1`，并检查问题是否因此得到解决。

Rework 中集成的系统调用兼容行为基于 [brcly](https://github.com/brcly/proton-LinUwUx-patch) 较新的 LinUwUx Runtime 工作，并已适配 Proton-LinUwUx Rework 的架构。

<a id="faq"></a>

## 常见问题

### 虚拟机监控器（HV）绕过是如何实现的？

关于 HV 绕过的说明、所需条件、设置方式以及兼容性，请参阅专门的 **[cs.rin.ru 讨论帖](https://cs.rin.ru/forum/viewtopic.php?f=10&t=159989)**。

### Proton-LinUwUx Rework 与 LinUwUx Runtime 有什么区别？

这两个项目提供了使用 LinUwUx 的不同方式。

**LinUwUx Runtime** 是主要且推荐的方案。它由 LinUwUx、brcly、xXJSONDeruloXx 及其他贡献者积极开发，旨在提供一种更通用的解决途径，无需依赖专用的 Proton 构建。

**Proton-LinUwUx Rework** 则采用了不同的思路：它把所需的 LinUwUx 行为直接集成进 Proton/Wine，并提供预构建的 Proton-GE 与 Proton-CachyOS 变体。

因此，Rework 应当被视为一种**替代与回退方案**，而不是 LinUwUx Runtime 的替代品。

在适用的情况下，Rework 还会吸收并改编作为 Runtime 工作一部分开发出的较新兼容行为，同时保留其自身的 Proton 集成架构。

如果 LinUwUx Runtime 能在你的环境中正常工作，通常应当优先使用它。Proton-LinUwUx Rework 仍然适用于需要 Proton 集成实现，或希望获得另一种实现方式用于兼容性测试与验证的场景。

### Proton-CachyOS 与 Proton-GE 有什么区别？

两个变体都应用相同的项目专用补丁，但它们基于不同的上游 Proton 项目。

Proton-GE 与 Proton-CachyOS 可能包含不同的 Wine 补丁、组件、默认配置与兼容性改动，因此不同游戏之间的表现可能存在差异。

### 这些构建能在不可变发行版上使用吗？

可以。包括 Steam Deck、Fedora Silverblue、Bazzite 等系统。

请将兼容工具安装在主目录内，例如：

```text
~/.steam/root/compatibilitytools.d/
~/.local/share/Steam/compatibilitytools.d/
~/.var/app/com.valvesoftware.Steam/.local/share/Steam/compatibilitytools.d/
~/.var/app/com.heroicgameslauncher.hgl/config/heroic/tools/proton/
~/.var/app/net.lutris.Lutris/data/lutris/runners/wine/
```

请勿尝试将其安装到 `/usr/share/steam` 这类只读的系统目录中。

### 虚拟机监控器绕过在 ARM 设备上可用吗？

不可用。FEX-Emu 等翻译器目前并未提供全部所需行为（包括 `cpuid_fault` 支持），而用户态模拟也无法复现某些保护系统所检查的全部属性。

这些构建**仅面向 x86_64 Linux 系统**。

### 存在被封禁的风险吗？

请自行承担使用风险。

修改过的兼容工具或试图绕过反篡改系统的行为，可能违反某个游戏、平台或在线服务的服务条款。请避免在竞技类或带反作弊保护的多人环境中使用修改版构建。

### 新版 Proton/Wine 是如何处理的？

本项目目前处于稳定里程碑阶段。

新的 Proton-GE、Proton-CachyOS 与 Wine 发行版都会针对 LinUwUx Rework 的兼容性进行评估。仓库中包含自动化诊断机制，用于快速识别结构性的上游改动，以便在必要时更新集成方案。

<a id="support"></a>

## 支持与公告

如遇兼容性问题、回归问题、构建故障或需要排障：

- **支持与故障排查：** https://t.me/+EdH8jcUUzcA2MmFk
- **公告：** https://t.me/protonlinuwux

报告问题时，请附上所用的 Proton-LinUwUx 构建、受影响的游戏或应用程序，以及相关日志。可通过 `LINUWUX_DEBUG=1` 启用运行时诊断。也可以使用 `LINUWUX_LOG=/path/to/linuwux.log` 将诊断信息写入文件。两个变量可以同时使用。报告问题时，请提供生成的 LinUwUx 日志。

<a id="disclaimer"></a>

## 免责声明

本仓库是一个独立的社区项目，与 Valve、CodeWeavers、GloriousEggroll、CachyOS 或任何游戏发行商均无隶属关系。

所有商标与项目名称均归各自所有者所有。

<a id="credits"></a>

## 致谢

- **LinUwUx**（原始补丁作者）
- **DenuvOwO Team**
- **GloriousEggroll**
- **CachyOS Team**
- **Valve** 与 **CodeWeavers**（Proton 与 Wine 的开发方）
