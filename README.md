<p align="center">
  <img src="assets/banner.svg" alt="Proton-LinUwUx" width="900">
</p>

<p align="center">
  Proton-GE and Proton-CachyOS builds integrating the <strong>LinUwUx Rework</strong> compatibility layer.
</p>

<p align="center">
  <a href="#downloads"><strong>Releases</strong></a>
  ·
  <a href="https://sourceforge.net/projects/proton-linuwux/files/"><strong>Binary Downloads</strong></a>
  ·
  <a href="https://t.me/+EdH8jcUUzcA2MmFk"><strong>Support</strong></a>
</p>

<p align="center">
  <a href="#downloads">Downloads</a>
  ·
  <a href="#features">Features</a>
  ·
  <a href="#installation">Installation</a>
  ·
  <a href="#faq">FAQ</a>
</p>

---

## About

**Proton-LinUwUx** provides x86_64 builds of Proton-GE and Proton-CachyOS integrating the **LinUwUx Rework** compatibility layer.

The project is built on the original LinUwUx patch and the work of its developer, **LinUwUx**, whose implementation provides the foundation for the compatibility behavior preserved by this project.

The current **LinUwUx Rework** does not replace that work; it restructures and extends it into a more modular, robust and maintainable compatibility layer, with the goal of preserving the original LinUwUx behavior while making the integration easier to adapt to future Proton/Wine changes, runtime protocol variants and upstream structural changes.

The original patch and the related discussion can be found on [cs.rin.ru](https://cs.rin.ru/forum/viewtopic.php?f=10&t=159989).

> [!TIP]
> **LinUwUx Runtime:** Also consider the work by **LinUwUx, brcly, xXJSONDeruloXx and the other contributors to the LinUwUx Runtime**. It brings the same underlying compatibility concept outside of modified Proton builds, providing a more independent and inherently robust approach. Proton-LinUwUx is maintained alongside it as both an alternative implementation and a fallback, preserving the patched-Proton approach and giving users the freedom to choose whichever solution better suits their setup and preferences.

> [!NOTE]
> Proton and Wine continue to evolve, so compatibility with future upstream releases may require maintenance updates. The project is currently at a stable milestone, with future work focused primarily on compatibility with new Proton/Wine versions, regressions and reported issues.

> [!IMPORTANT]
> These builds do not add unrelated performance tweaks. Project-specific changes are limited to the LinUwUx compatibility layer, its integration and the diagnostics required to maintain and troubleshoot it.

## Features

- Supports Proton-GE and Proton-CachyOS as separate release variants.
- Provides ready-to-use x86_64 compatibility-tool archives.
- Includes automation for applying the LinUwUx Rework and building supported Proton/Wine trees.
- Includes structural diagnostics to help identify upstream changes that may break the automation.
- Includes optional `LINUWUX_DEBUG=1` runtime diagnostics for compatibility and regression troubleshooting.

## Available builds

| Build | Upstream project | Architecture | Description |
|---|---|---:|---|
| **Proton-GE LinUwUx** | [GloriousEggroll/proton-ge-custom](https://github.com/GloriousEggroll/proton-ge-custom) | x86_64 | Supported Proton-GE release integrating the LinUwUx Rework. |
| **Proton-CachyOS LinUwUx** | [CachyOS/proton-cachyos](https://github.com/CachyOS/proton-cachyos) | x86_64 | Supported Proton-CachyOS release integrating the LinUwUx Rework. |

## Downloads

Release information is published on:

<p align="center">
  <strong>
    <a href="https://codeberg.org/xshaduwulfx/proton-linuwux/releases">Codeberg Releases</a>
    ·
    <a href="https://github.com/xshaduwulfx/proton-linuwux/releases">GitHub Releases</a>
  </strong>
</p>

Binary archives are hosted on:

<p align="center">
  <strong>
    <a href="https://sourceforge.net/projects/proton-linuwux/files/">SourceForge</a>
  </strong>
</p>

Each binary archive is accompanied by a `.sha256` checksum file and contains a complete compatibility-tool directory that can be extracted into a supported compatibility-tools location.

## Installation

### Steam

1. Download the desired archive through [Codeberg Releases](https://codeberg.org/xshaduwulfx/proton-linuwux/releases).
2. Extract it into one of the following directories:

   ```text
   ~/.steam/root/compatibilitytools.d/
   ~/.local/share/Steam/compatibilitytools.d/
   ~/.var/app/com.valvesoftware.Steam/.local/share/Steam/compatibilitytools.d/
   ```

3. Create the selected directory if it does not already exist.
4. Restart Steam.
5. Right-click the game and open **Properties → Compatibility**.
6. Enable **Force the use of a specific Steam Play compatibility tool**.
7. Select the installed Proton-LinUwUx build.

### Heroic Games Launcher

1. Download the desired archive through **Codeberg Releases**.

2. Extract the Proton-LinUwUx directory into the appropriate Heroic Proton directory:

   **Native installation:**

   ```text
   ~/.config/heroic/tools/proton/
   ```

   **Flatpak installation:**

   ```text
   ~/.var/app/com.heroicgameslauncher.hgl/config/heroic/tools/proton/
   ```

3. Create the selected directory if it does not already exist.

4. Restart Heroic Games Launcher.

5. Select the desired game from the **Library**.

6. Open the game's **Settings**.

7. Open the **Wine** section.

8. Under **Wine Version**, select the installed Proton-LinUwUx build.

9. Launch the game.

### Lutris

1. Download the desired archive through [Codeberg Releases](https://codeberg.org/xshaduwulfx/proton-linuwux/releases).

2. Extract the Proton-LinUwUx directory into the Lutris custom Wine runners directory:

   **Native installation:**

   ```text
   ~/.local/share/lutris/runners/wine/
   ```

   **Flatpak installation:**

   ```text
   ~/.var/app/net.lutris.Lutris/data/lutris/runners/wine/
   ```

3. Create the selected directory if it does not already exist.

4. Restart Lutris.

5. Select the desired game from the **Library**.

6. Open the game's **Configure** menu.

7. Open the **Runner options** tab.

8. Under **Wine version**, select the installed Proton-LinUwUx build.

9. Save the configuration and launch the game.

### Faugus Launcher

1. Extract the build into one of the Steam compatibility-tools directories listed above.
2. When using the Flatpak version of Faugus Launcher, open **Flatseal**.
3. Select Faugus Launcher and add the extraction path under **Filesystems → Other files**.
4. Open:

   ```text
   ~/.var/app/io.github.Faugus.faugus-launcher/data/faugus-launcher/games.json
   ```

5. Find the relevant game entry and set its `"runner"` value to the absolute path of the extracted Proton directory.

> [!NOTE]
> The runner path may need to be set again after adding a game or changing its launch options.

## FAQ

### How does the Hypervisor (HV) bypass work?

For information about the HV bypass, its requirements, setup and compatibility, please refer to the dedicated **[cs.rin.ru discussion thread](https://cs.rin.ru/forum/viewtopic.php?f=10&t=159989)**.

### What is the difference between Proton-CachyOS and Proton-GE?

Both variants receive the same project-specific patch, but they are based on different upstream Proton projects.

Proton-GE and Proton-CachyOS may contain different Wine patches, components, defaults and compatibility changes. Results can therefore vary between games.

### Do these builds work on immutable distributions?

Yes. This includes systems such as Steam Deck, Fedora Silverblue and Bazzite.

Install the compatibility tool inside your home directory, for example:

```text
~/.steam/root/compatibilitytools.d/
~/.local/share/Steam/compatibilitytools.d/
~/.var/app/com.valvesoftware.Steam/.local/share/Steam/compatibilitytools.d/
~/.var/app/com.heroicgameslauncher.hgl/config/heroic/tools/proton/
~/.var/app/net.lutris.Lutris/data/lutris/runners/wine/
```

Do not attempt to install it into a read-only system directory such as `/usr/share/steam`.

### Does the hypervisor bypass work on ARM devices?

No. Translators such as FEX-Emu do not currently provide all the required behavior, including `cpuid_fault` support, and user-mode emulation cannot reproduce every property checked by some protection systems.

These builds target **x86_64 Linux systems only**.

### Is there a risk of being banned?

Use these builds at your own risk.

Modified compatibility tools or attempts to bypass anti-tamper systems may violate the terms of service of a game, platform or online service. Avoid using modified builds in competitive or anti-cheat-protected multiplayer environments.

### How are new Proton/Wine releases handled?

The project is currently at a stable milestone.

New Proton-GE, Proton-CachyOS and Wine releases are evaluated for compatibility with the LinUwUx Rework. The repository includes automation diagnostics intended to identify structural upstream changes quickly so the integration can be updated when required.

## Support & Announcements

For compatibility issues, regressions, build problems or troubleshooting:

- **Support & Troubleshooting:** https://t.me/+EdH8jcUUzcA2MmFk
- **Announcements:** https://t.me/protonlinuwux

When reporting an issue, please include the Proton-LinUwUx build used, the affected game or application and any relevant logs. Runtime diagnostics can be enabled with `LINUWUX_DEBUG=1`. Optionally, diagnostics can also be written to a file with `LINUWUX_LOG=/path/to/linuwux.log`. Both variables can be used together. Please provide the resulting LinUwUx log when reporting an issue.

## Disclaimer

This repository is an independent community project and is not affiliated with Valve, CodeWeavers, GloriousEggroll, CachyOS or any game publisher.

All trademarks and project names belong to their respective owners.

## Credits

- **LinUwUx** (original patch author)
- **DenuvOwO Team**
- **GloriousEggroll**
- **CachyOS Team**
- **Valve** and **CodeWeavers** for Proton and Wine development
