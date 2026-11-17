# Private Server, Invite Codes & Performance Port (`PokeZ-ARecomp` v0.1.25 + Lumiose)

This repository merges the core runtime performance improvements from [`Hexveil404/PokeZ-ARecomp`](https://github.com/Hexveil404/PokeZ-ARecomp) (`v0.1.25`) into [`TheMagnumChad/PokeZ-ARecomp-Online`](https://github.com/TheMagnumChad/PokeZ-ARecomp-Online) while keeping Lumiose Online multiplayer compatibility intact, and adds a self-hosted **Private Room Server** with short invite codes (`ZA1-...` / `ZA2-...`) and multi-profile saves.

## Performance Improvements Included (`v0.1.25`)
- Multithreaded Vulkan shader translation and pipeline preparation (`runtime/nvn/vulkan/build_threads.h`, `shader_variants_za.txt`)
- Lower memory usage shader cleanup (< 12 GB RAM setups) and GPU slow-frame profiler
- Constant game-speed frame pacing below 30 FPS (`runtime/hle/framepace.c`)
- AMD FSR 4 provider scaffolding (`runtime/nvn/vulkan/fsr4.cpp`, `third_party/ffx_api/`)

## Private Room Multiplayer
- **`tools/lumiose/private_server.py`**: Pure-Python stdlib UDP server implementing the Lumiose `0x01`/`0x81`, `0x10`/`0x90`, chat (`0x12`/`0x13`), trades (`0x30`/`0x31`), raids (`0x50`), duel (`0x70`/`0xF0`), and room secret handshake (`ZAKNOCK!<secret>`).
- **`tools/lumiose/invite_code.py`**: Compact Crockford Base32 + CRC16-CCITT invite code encoder/decoder (`ZA1-` for IPv4, `ZA2-` for hostnames such as Playit.gg).
- **`tools/lumiose/redirect_winmm.c` & `build_redirect_winmm.py`**: Generates `winmm.dll` (181 exports forwarded + WS2_32 IAT hook on `sendto`/`recvfrom`) so the stock game binary redirects UDP traffic to `LUMIOSE_SERVER_OVERRIDE` without patching game binaries.
- **`tools/lumiose/profiles.py` & `entry.py`**: Interactive launcher wizard supporting profile switching (`LARECOMP_SAVE_DIR` + `save/sdcard` junction), Host Room setup (Playit.gg / UPnP / LAN-VPN), Join by Invite Code, and `winmm.dll` / firewall configuration.
- **`Start Private Server Only.bat`**: Runs the standalone dedicated host server from `lumiose/private-server.json`.

## Automated Windows Build
GitHub Actions workflow [`.github/workflows/windows-private-build.yml`](.github/workflows/windows-private-build.yml) builds `lasrecomp.exe`, `lasrecomp.dll.a`, `winmm.dll`, bundles runtime DLLs + `tools/lumiose/`, runs the unit tests, and uploads `Lumiose-Private-Patch-windows` as a workflow artifact.

> **Note:** No game ROMs, extracted assets, keys, or save files are stored or distributed in this repository. Provide your own legally dumped game files locally.
