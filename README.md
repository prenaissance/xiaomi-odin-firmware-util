# xiaomi-odin-firmware-util

Zero-dependency Rust firmware extractor, NV MAC / Bluetooth `BD_ADDR` provisioner, and hardware status CLI for the **Xiaomi MIX 4 (`xiaomi-odin`, Snapdragon 888+ / SM8350)** running mainline Linux.

## Why This Exists

The Xiaomi MIX 4 requires proprietary firmware blobs (Qualcomm WCN6855 Wi-Fi/BT, Adreno 660, Iris VPU, Hexagon ADSP/SLPI/CDSP, Cirrus Logic CS35L41, Awinic AW8697) and per-device factory NV data that cannot legally be redistributed in open-source repositories or Linux distribution packages. This tool extracts those files directly on-device (read-only) from the phone's existing Android partitions so distributions and users can bring up hardware cleanly without distributing proprietary firmware.

## What It Does

- **Multi-subsystem firmware extraction** (read-only from Android `modem_a`, `bluetooth_a`, `dsp_a`, `persist`, and `super/vendor_a` partitions):
  - Qualcomm WCN6855 (`ath11k` `hw1.1` / `hw2.0` `amss.bin`, `m3.bin`, compact `board-2.bin` TLV bundle, `regdb.bin`, and Bluetooth `hpbtfw10.tlv` / `hpnv10.bin` + symlinks)
  - Adreno 660 GPU (`a660_zap.mbn`), Iris VPU (`vpu20_4v.mbn`), Hexagon ADSP (`adsp.mbn`), SLPI + sensor registry (`slpi.mbn`), CDSP (`cdsp.mbn`)
  - Cirrus Logic CS35L41 speaker DSPs & Awinic AW8697 haptics firmware
- **Factory NV MAC & Bluetooth `BD_ADDR` provisioning**:
  - Reads the factory Wi-Fi MAC from Android `persist/wlan_mac.bin` (with deterministic serial fallback) and writes `/etc/systemd/network/10-odin-wifi.link` + `/etc/NetworkManager/conf.d/10-odin-wifi.conf`
  - Configures WCN6855 `hci0` `BD_ADDR` via `btmgmt` on boot (`xiaomi-odin-firmware-util bluetooth`)
- **Hardware & firmware diagnostics**:
  - `xiaomi-odin-firmware-util status` reports PCIe/MHI, firmware files, GPU/DRM, V4L2, battery, SLPI/CDSP, Bluetooth, flash, ALSA, and Wi-Fi state.

## Building

Requires only a standard Rust toolchain (no external crates):

```bash
cargo test
cargo build --release
```

Cross-compiling for `aarch64` (e.g. `aarch64-unknown-linux-musl` or `aarch64-unknown-linux-gnu`):

```bash
cargo build --release --target aarch64-unknown-linux-musl
```

## Usage

```bash
# One-time / first-boot firmware + MAC provisioning (requires root)
sudo xiaomi-odin-firmware-util provision --if-needed

# Subsystem-only provisioning
sudo xiaomi-odin-firmware-util provision-gpu --if-needed
sudo xiaomi-odin-firmware-util provision-adsp --if-needed

# Configure WCN6855 Bluetooth BD_ADDR and power on hci0
sudo xiaomi-odin-firmware-util bluetooth

# Print hardware & firmware diagnostics
sudo xiaomi-odin-firmware-util status
```

## License

Licensed under the **GNU General Public License v3.0 or later** (`GPL-3.0-or-later`). See [LICENSE](LICENSE).
