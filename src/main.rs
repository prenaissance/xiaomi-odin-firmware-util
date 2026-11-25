//! `xiaomi-odin-firmware-util`: Firmware extractor, NV MAC / Bluetooth BD_ADDR
//! provisioner, and hardware status CLI for Xiaomi MIX 4 (`xiaomi-odin`, SM8350).

use std::env;
use std::fs;
use std::io::Write;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};
use std::thread;
use std::time::Duration;
use xiaomi_odin_firmware_util::bd2::{
    Board2Bundle, BoardEntry, ATH11K_BD_IE_BOARD, ATH11K_BD_IE_REGDB,
};
use xiaomi_odin_firmware_util::lp::{self, DynamicPartition};
use xiaomi_odin_firmware_util::mac::MacAddr;
use xiaomi_odin_firmware_util::mdt;

const DEFAULT_MODEM_DEV: &str = "/dev/disk/by-partlabel/modem_a";
const FALLBACK_MODEM_DEV: &str = "/dev/sde5";
const DEFAULT_BT_DEV: &str = "/dev/disk/by-partlabel/bluetooth_a";
const FALLBACK_BT_DEV: &str = "/dev/sde6";
const DEFAULT_DSP_DEV: &str = "/dev/disk/by-partlabel/dsp_a";
const FALLBACK_DSP_DEV: &str = "/dev/sde10";
const DEFAULT_PERSIST_DEV: &str = "/dev/disk/by-partlabel/persist";
const FALLBACK_PERSIST_DEV: &str = "/dev/sda21";
const DEFAULT_SUPER_DEV: &str = "/dev/disk/by-partlabel/super";
const FALLBACK_SUPER_DEV: &str = "/dev/sda28";
const DEFAULT_FW_ROOT: &str = "/lib/firmware/ath11k/WCN6855";
const DEFAULT_QCOM_FW_ROOT: &str = "/lib/firmware/qcom";
const DEFAULT_QCA_BT_FW_ROOT: &str = "/lib/firmware/qca";
const DEFAULT_CIRRUS_FW_ROOT: &str = "/lib/firmware/cirrus";
const DEFAULT_HEXAGON_SHARE_ROOT: &str = "/usr/share/qcom/sm8350/Xiaomi/odin";
const ODIN_SUBDIR: &str = "sm8350/xiaomi/odin";
const ODIN_ZAP_REL_PATH: &str = "sm8350/xiaomi/odin/a660_zap.mbn";
const ODIN_IRIS_REL_PATH: &str = "sm8350/xiaomi/odin/vpu20_4v.mbn";
const ODIN_ADSP_REL_PATH: &str = "sm8350/xiaomi/odin/adsp.mbn";
const ODIN_SLPI_REL_PATH: &str = "sm8350/xiaomi/odin/slpi.mbn";
const ODIN_CDSP_REL_PATH: &str = "sm8350/xiaomi/odin/cdsp.mbn";
const NM_CONF_PATH: &str = "/etc/NetworkManager/conf.d/10-odin-wifi.conf";
const SYSTEMD_LINK_PATH: &str = "/etc/systemd/network/10-odin-wifi.link";
const MAC_STATE_PATH: &str = "/etc/xiaomi-odin-firmware-util/mac_address";
const LEGACY_MAC_STATE_PATH: &str = "/etc/odin-wifi/mac_address";
const VARIANT_NAME: &str = "Xiaomi_MIX4";
const COMPACT_BD2_MAX_BYTES: u64 = 2 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AmssSource {
    Auto,
    Upstream,
    Vendor,
}

/// RAII temporary read-only mount guard — guarantees `umount` on scope exit.
struct RoMountGuard {
    mountpoint: PathBuf,
    mounted: bool,
}

impl RoMountGuard {
    fn mount_ro(dev: &Path, fstype: &str, tag: &str) -> Result<Self, String> {
        let mp = PathBuf::from(format!("/run/odin-wifi-mnt-{tag}-{}", std::process::id()));
        fs::create_dir_all(&mp).map_err(|e| format!("mkdir {}: {e}", mp.display()))?;

        // Only ext4 understands `noload` (skip journal replay on ro mount); vfat uses plain `ro`.
        let mount_opts = if fstype == "ext4" { "ro,noload" } else { "ro" };

        let status = Command::new("mount")
            .args(["-o", mount_opts, "-t", fstype])
            .arg(dev)
            .arg(&mp)
            .status()
            .map_err(|e| format!("exec mount {}: {e}", dev.display()))?;

        if !status.success() {
            if mount_opts != "ro" {
                let retry = Command::new("mount")
                    .args(["-o", "ro", "-t", fstype])
                    .arg(dev)
                    .arg(&mp)
                    .status()
                    .map_err(|e| format!("exec mount retry {}: {e}", dev.display()))?;
                if retry.success() {
                    return Ok(Self {
                        mountpoint: mp,
                        mounted: true,
                    });
                }
            }
            let _ = fs::remove_dir(&mp);
            return Err(format!("mount -o ro -t {fstype} {} failed", dev.display()));
        }

        Ok(Self {
            mountpoint: mp,
            mounted: true,
        })
    }

    fn path(&self) -> &Path {
        &self.mountpoint
    }
}

impl Drop for RoMountGuard {
    fn drop(&mut self) {
        if self.mounted {
            let _ = Command::new("umount").arg(&self.mountpoint).status();
            let _ = fs::remove_dir(&self.mountpoint);
        }
    }
}

enum SuperMapBackend {
    DmLinear(String),
    LoopDev(PathBuf),
}

/// RAII zero-copy read-only block mapping for an Android `super` dynamic partition.
struct SuperMapperGuard {
    dev_path: PathBuf,
    backend: SuperMapBackend,
}

impl SuperMapperGuard {
    fn map_ro(super_dev: &Path, part: &DynamicPartition) -> Result<Self, String> {
        let dm_name = format!("odin_{}_ro_{}", part.name, std::process::id());
        let table = part.dm_table(&super_dev.to_string_lossy());

        if let Ok(mut child) = Command::new("dmsetup")
            .args(["create", "--readonly", &dm_name])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
        {
            if let Some(mut stdin) = child.stdin.take() {
                let _ = writeln!(stdin, "{table}");
            }
            if let Ok(st) = child.wait() {
                let mapper_path = PathBuf::from(format!("/dev/mapper/{dm_name}"));
                if st.success() && mapper_path.exists() {
                    return Ok(Self {
                        dev_path: mapper_path,
                        backend: SuperMapBackend::DmLinear(dm_name),
                    });
                }
            }
        }

        if part.extents.len() == 1 {
            let ext = &part.extents[0];
            let out = Command::new("losetup")
                .args([
                    "-r",
                    "-f",
                    "--show",
                    "-o",
                    &ext.byte_offset().to_string(),
                    "--sizelimit",
                    &ext.byte_len().to_string(),
                ])
                .arg(super_dev)
                .output()
                .map_err(|e| format!("exec losetup {}: {e}", super_dev.display()))?;
            if out.status.success() {
                let loop_str = String::from_utf8_lossy(&out.stdout).trim().to_owned();
                let loop_path = PathBuf::from(&loop_str);
                if !loop_str.is_empty() && loop_path.exists() {
                    return Ok(Self {
                        dev_path: loop_path.clone(),
                        backend: SuperMapBackend::LoopDev(loop_path),
                    });
                }
            }
        }

        Err(format!(
            "failed to map dynamic partition '{}' from {}",
            part.name,
            super_dev.display()
        ))
    }

    fn path(&self) -> &Path {
        &self.dev_path
    }
}

impl Drop for SuperMapperGuard {
    fn drop(&mut self) {
        match &self.backend {
            SuperMapBackend::DmLinear(name) => {
                let _ = Command::new("dmsetup").args(["remove", name]).status();
            }
            SuperMapBackend::LoopDev(dev) => {
                let _ = Command::new("losetup").arg("-d").arg(dev).status();
            }
        }
    }
}

fn resolve_block_dev(primary: &str, fallback: &str) -> Option<PathBuf> {
    for candidate in [primary, fallback] {
        let p = Path::new(candidate);
        if p.exists() {
            return Some(p.to_path_buf());
        }
    }
    None
}

fn atomic_write(dest: &Path, bytes: &[u8]) -> Result<(), String> {
    if let Some(parent) = dest.parent() {
        fs::create_dir_all(parent).map_err(|e| format!("mkdir {}: {e}", parent.display()))?;
    }
    let tmp = dest.with_extension("tmp.odin");
    {
        let mut f = fs::File::create(&tmp).map_err(|e| format!("create {}: {e}", tmp.display()))?;
        f.write_all(bytes)
            .map_err(|e| format!("write {}: {e}", tmp.display()))?;
        f.sync_all()
            .map_err(|e| format!("fsync {}: {e}", tmp.display()))?;
    }
    fs::rename(&tmp, dest).map_err(|e| format!("rename {} -> {}: {e}", tmp.display(), dest.display()))
}

fn read_trimmed(p: &Path) -> Option<String> {
    fs::read_to_string(p).ok().map(|s| s.trim().to_owned())
}

/// Detect live PCI subsystem IDs if `17cb:1103` is already enumerated on PCIe0.
fn detect_live_wcn6855_subsys() -> Vec<(u16, u16)> {
    let mut pairs = vec![
        (0x17cb, 0x0108),
        (0x17cb, 0x3374),
        (0x0000, 0x0000),
    ];
    let Ok(entries) = fs::read_dir("/sys/bus/pci/devices") else {
        return pairs;
    };
    for ent in entries.flatten() {
        let p = ent.path();
        let vendor = read_trimmed(&p.join("vendor")).unwrap_or_default();
        let device = read_trimmed(&p.join("device")).unwrap_or_default();
        if vendor.eq_ignore_ascii_case("0x17cb") && device.eq_ignore_ascii_case("0x1103")
            && let (Some(sv_s), Some(sd_s)) = (
                read_trimmed(&p.join("subsystem_vendor")),
                read_trimmed(&p.join("subsystem_device")),
            ) {
                let sv = u16::from_str_radix(sv_s.trim_start_matches("0x"), 16).unwrap_or(0);
                let sd = u16::from_str_radix(sd_s.trim_start_matches("0x"), 16).unwrap_or(0);
                if !pairs.contains(&(sv, sd)) {
                    pairs.insert(0, (sv, sd));
                }
            }
    }
    pairs
}

fn build_k8_board_aliases(subsys_pairs: &[(u16, u16)]) -> Vec<String> {
    let chip_ids = [2u32, 18, 0, 1];
    let board_ids = [255u32, 0];
    let mut names = Vec::new();

    // 1. Exact full PCIe + variant=Xiaomi_MIX4 matches (ath11k lookup #1)
    for &(sv, sd) in subsys_pairs {
        for &cid in &chip_ids {
            for &bid in &board_ids {
                names.push(format!(
                    "bus=pci,vendor=17cb,device=1103,subsystem-vendor={sv:04x},subsystem-device={sd:04x},qmi-chip-id={cid},qmi-board-id={bid},variant={VARIANT_NAME}"
                ));
            }
        }
    }

    // 2. Full PCIe without variant when qmi-board-id=255 or 0 (ath11k lookup #2)
    for &(sv, sd) in subsys_pairs {
        for &cid in &chip_ids {
            for &bid in &board_ids {
                names.push(format!(
                    "bus=pci,vendor=17cb,device=1103,subsystem-vendor={sv:04x},subsystem-device={sd:04x},qmi-chip-id={cid},qmi-board-id={bid}"
                ));
            }
        }
    }

    // 3. Chip-ID fallback matches (ath11k lookup #3: `bus=pci,qmi-chip-id=%d`)
    for &cid in &chip_ids {
        names.push(format!("bus=pci,qmi-chip-id={cid}"));
    }

    names
}

fn collect_bdwlan_entries(image_dir: &Path, subsys_pairs: &[(u16, u16)]) -> Vec<BoardEntry> {
    let mut entries = Vec::new();
    let Ok(rd) = fs::read_dir(image_dir) else {
        return entries;
    };
    let mut files: Vec<PathBuf> = rd.flatten().map(|e| e.path()).collect();
    files.sort();

    for path in files {
        let Some(fname) = path.file_name().and_then(|s| s.to_str()) else {
            continue;
        };
        let Some(hex_ext) = fname.strip_prefix("bdwlan.e") else {
            continue;
        };
        let Ok(board_id) = u32::from_str_radix(hex_ext, 16) else {
            continue;
        };
        if board_id == 0xff {
            continue;
        }
        let Ok(data) = fs::read(&path) else {
            continue;
        };
        if data.is_empty() {
            continue;
        }
        let mut names = Vec::new();
        for &(sv, sd) in subsys_pairs {
            for cid in [2u32, 18, 0, 1] {
                names.push(format!(
                    "bus=pci,vendor=17cb,device=1103,subsystem-vendor={sv:04x},subsystem-device={sd:04x},qmi-chip-id={cid},qmi-board-id={board_id},variant={VARIANT_NAME}"
                ));
                names.push(format!(
                    "bus=pci,vendor=17cb,device=1103,subsystem-vendor={sv:04x},subsystem-device={sd:04x},qmi-chip-id={cid},qmi-board-id={board_id}"
                ));
            }
        }
        entries.push(BoardEntry { names, data });
    }
    entries
}

fn provision_firmware(
    fw_root: &Path,
    amss_source: AmssSource,
    include_ref_bdfs: bool,
) -> Result<(), String> {
    let hw11 = fw_root.join("hw1.1");
    let hw20 = fw_root.join("hw2.0");
    let hw21 = fw_root.join("hw2.1");
    fs::create_dir_all(&hw11).map_err(|e| format!("mkdir {}: {e}", hw11.display()))?;
    fs::create_dir_all(&hw20).map_err(|e| format!("mkdir {}: {e}", hw20.display()))?;

    let modem_dev = resolve_block_dev(DEFAULT_MODEM_DEV, FALLBACK_MODEM_DEV)
        .ok_or_else(|| format!("modem partition not found ({DEFAULT_MODEM_DEV} / {FALLBACK_MODEM_DEV})"))?;

    println!(
        "[xiaomi-odin-firmware-util] Mounting {} read-only to extract Xiaomi K8 RF calibration & WCN6855 firmware...",
        modem_dev.display()
    );
    let modem_mnt = RoMountGuard::mount_ro(&modem_dev, "vfat", "modem")?;
    let image_dir = if modem_mnt.path().join("image").is_dir() {
        modem_mnt.path().join("image")
    } else {
        modem_mnt.path().to_path_buf()
    };

    let bd_k8_path = image_dir.join("bd_k8.elf");
    let bd_k8 = fs::read(&bd_k8_path)
        .or_else(|_| fs::read(image_dir.join("bdwlan.elf")))
        .map_err(|e| format!("failed to read {}: {e}", bd_k8_path.display()))?;
    println!("[xiaomi-odin-firmware-util] Loaded factory K8 BDF ({} bytes)", bd_k8.len());

    let regdb_xiaomi = fs::read(image_dir.join("regdb_xiaomi.bin"))
        .or_else(|_| fs::read(image_dir.join("regdb.bin")))
        .or_else(|_| fs::read(hw20.join("regdb.upstream.bin")))
        .map_err(|e| format!("failed to read regdb_xiaomi.bin/regdb.bin: {e}"))?;

    let vendor_m3 = fs::read(image_dir.join("m3.bin"))
        .map_err(|e| format!("failed to read vendor m3.bin: {e}"))?;

    // 1. Provision WCN6855/hw1.1 (QCA6490 v1 silicon: PCI rev 0x01, soc_hw_version 1 16).
    // Per vendor cnss2/pci.c:5381, major_version == 1 uses `amss.bin` (DEFAULT_FW_FILE_NAME),
    // whereas upstream linux-firmware's `amss.bin` is built for `eval_v2_TOQ` (hw2.0).
    let upstream_amss = hw20.join("amss.upstream.bin");
    let upstream_m3 = hw20.join("m3.upstream.bin");
    let use_upstream_for_hw11 = amss_source == AmssSource::Upstream
        && upstream_amss.is_file()
        && upstream_m3.is_file();

    if use_upstream_for_hw11 {
        let amss = fs::read(&upstream_amss).map_err(|e| format!("read {}: {e}", upstream_amss.display()))?;
        let m3 = fs::read(&upstream_m3).map_err(|e| format!("read {}: {e}", upstream_m3.display()))?;
        atomic_write(&hw11.join("amss.bin"), &amss)?;
        atomic_write(&hw11.join("m3.bin"), &m3)?;
        println!(
            "[xiaomi-odin-firmware-util] Installed upstream firmware into hw1.1 (amss.bin={} B, m3.bin={} B)",
            amss.len(),
            m3.len()
        );
    } else {
        let vendor_amss_v1 = fs::read(image_dir.join("amss.bin"))
            .or_else(|_| fs::read(image_dir.join("amss20.bin")))
            .map_err(|e| format!("failed to read vendor amss.bin for hw1.1: {e}"))?;
        atomic_write(&hw11.join("amss.bin"), &vendor_amss_v1)?;
        atomic_write(&hw11.join("m3.bin"), &vendor_m3)?;
        println!(
            "[xiaomi-odin-firmware-util] Installed vendor modem_a HW_V1 firmware into hw1.1 (amss.bin={} B, m3.bin={} B)",
            vendor_amss_v1.len(),
            vendor_m3.len()
        );
    }

    // 2. Provision WCN6855/hw2.0 (+ hw2.1 -> hw2.0 symlink) for v2 silicon compatibility.
    let use_vendor_for_hw20 = match amss_source {
        AmssSource::Vendor => true,
        AmssSource::Upstream | AmssSource::Auto => !upstream_amss.is_file() || !upstream_m3.is_file(),
    };

    if use_vendor_for_hw20 {
        let vendor_amss_v2 = fs::read(image_dir.join("amss20.bin"))
            .or_else(|_| fs::read(image_dir.join("amss.bin")))
            .map_err(|e| format!("failed to read vendor amss20.bin for hw2.0: {e}"))?;
        atomic_write(&hw20.join("amss.bin"), &vendor_amss_v2)?;
        atomic_write(&hw20.join("m3.bin"), &vendor_m3)?;
        println!(
            "[xiaomi-odin-firmware-util] Installed vendor modem_a HW_V2 firmware into hw2.0 (amss20.bin={} B, m3.bin={} B)",
            vendor_amss_v2.len(),
            vendor_m3.len()
        );
    } else {
        let amss = fs::read(&upstream_amss).map_err(|e| format!("read {}: {e}", upstream_amss.display()))?;
        let m3 = fs::read(&upstream_m3).map_err(|e| format!("read {}: {e}", upstream_m3.display()))?;
        atomic_write(&hw20.join("amss.bin"), &amss)?;
        atomic_write(&hw20.join("m3.bin"), &m3)?;
        println!(
            "[xiaomi-odin-firmware-util] Installed upstream linux-firmware WLAN.HSP.1.1 into hw2.0 (amss.bin={} B, m3.bin={} B)",
            amss.len(),
            m3.len()
        );
    }

    // 3. Build compact verified board-2.bin for Xiaomi MIX 4 (HARDWARE_PROJECT_K8 -> bd_k8.elf)
    let subsys_pairs = detect_live_wcn6855_subsys();
    let k8_aliases = build_k8_board_aliases(&subsys_pairs);
    let first_alias = k8_aliases[0].clone();

    let mut boards = Vec::new();
    let bdwlan_count = if include_ref_bdfs {
        let refs = collect_bdwlan_entries(&image_dir, &subsys_pairs);
        let n = refs.len();
        boards.extend(refs);
        n
    } else {
        0
    };

    boards.push(BoardEntry {
        names: k8_aliases,
        data: bd_k8.clone(),
    });

    if include_ref_bdfs {
        let upstream_bd2_path = hw20.join("board-2.upstream.bin");
        if let Ok(raw_up) = fs::read(&upstream_bd2_path)
            && let Ok(parsed_up) = Board2Bundle::parse(&raw_up) {
                boards.extend(parsed_up.boards);
            }
    }

    let bundle = Board2Bundle {
        boards,
        regdbs: vec![BoardEntry {
            names: vec!["bus=pci".to_owned()],
            data: regdb_xiaomi.clone(),
        }],
    };

    let encoded_bd2 = bundle
        .encode()
        .map_err(|e| format!("failed to encode board-2.bin: {e}"))?;

    // Self-verify using exact kernel parser logic before writing to disk!
    let verify_board = Board2Bundle::kernel_lookup(&encoded_bd2, ATH11K_BD_IE_BOARD, &first_alias)
        .map_err(|e| format!("self-verify board lookup error: {e}"))?;
    if verify_board != Some(bd_k8.as_slice()) {
        return Err("self-verification failed: K8 BDF mismatch in encoded board-2.bin".into());
    }
    for fallback_key in ["bus=pci,qmi-chip-id=0", "bus=pci,qmi-chip-id=2"] {
        let verify_fallback =
            Board2Bundle::kernel_lookup(&encoded_bd2, ATH11K_BD_IE_BOARD, fallback_key)
                .map_err(|e| format!("self-verify chip-id fallback lookup error: {e}"))?;
        if verify_fallback != Some(bd_k8.as_slice()) {
            return Err(format!(
                "self-verification failed: {fallback_key} mismatch in encoded board-2.bin"
            ));
        }
    }
    let verify_regdb = Board2Bundle::kernel_lookup(&encoded_bd2, ATH11K_BD_IE_REGDB, "bus=pci")
        .map_err(|e| format!("self-verify regdb lookup error: {e}"))?;
    if verify_regdb != Some(regdb_xiaomi.as_slice()) {
        return Err("self-verification failed: regdb mismatch in encoded board-2.bin".into());
    }

    for dir in [&hw11, &hw20] {
        atomic_write(&dir.join("board-2.bin"), &encoded_bd2)?;
        atomic_write(&dir.join("board.bin"), &bd_k8)?;
        atomic_write(&dir.join("regdb.bin"), &regdb_xiaomi)?;
    }

    // Ensure hw2.1 -> hw2.0 symlink
    if let Ok(meta) = hw21.symlink_metadata() {
        if meta.is_dir() && !meta.file_type().is_symlink() {
            let _ = fs::remove_dir_all(&hw21);
        } else {
            let _ = fs::remove_file(&hw21);
        }
    }
    symlink("hw2.0", &hw21).map_err(|e| format!("symlink hw2.1 -> hw2.0: {e}"))?;

    println!(
        "[xiaomi-odin-firmware-util] Wrote verified board-2.bin ({} B, K8 + {} ref bdwlan entries) to hw1.1 & hw2.0 (+ hw2.1 symlink)",
        encoded_bd2.len(),
        bdwlan_count
    );
    Ok(())
}

fn sync_mac_address() -> Result<MacAddr, String> {
    let mut resolved_mac: Option<MacAddr> = None;

    if let Some(persist_dev) = resolve_block_dev(DEFAULT_PERSIST_DEV, FALLBACK_PERSIST_DEV)
        && let Ok(persist_mnt) = RoMountGuard::mount_ro(&persist_dev, "ext4", "persist") {
            for rel in ["wlan_mac.bin", "wifi/wlan_mac.bin"] {
                let p = persist_mnt.path().join(rel);
                if let Ok(txt) = fs::read_to_string(&p)
                    && let Some(mac) = MacAddr::parse_wlan_mac_bin(&txt) {
                        println!("[xiaomi-odin-firmware-util] Read factory NV Wi-Fi MAC {mac} from persist/{rel}");
                        resolved_mac = Some(mac);
                        break;
                    }
            }
        }

    let mac = resolved_mac.unwrap_or_else(|| {
        let cmdline = fs::read_to_string("/proc/cmdline").unwrap_or_default();
        let serial = MacAddr::extract_serial_from_cmdline(&cmdline).unwrap_or("xiaomi-odin");
        let fallback = MacAddr::from_serial_fallback(serial);
        println!("[xiaomi-odin-firmware-util] Using deterministic locally-administered Wi-Fi MAC {fallback} (serial={serial})");
        fallback
    });

    atomic_write(Path::new(MAC_STATE_PATH), format!("{mac}\n").as_bytes())?;
    atomic_write(Path::new(NM_CONF_PATH), mac.networkmanager_conf().as_bytes())?;
    atomic_write(Path::new(SYSTEMD_LINK_PATH), mac.systemd_link_conf().as_bytes())?;
    Ok(mac)
}

fn ensure_modules_and_interface(mac: MacAddr) {
    let _ = Command::new("rfkill").args(["unblock", "wifi", "wlan"]).status();

    for module in ["ath11k", "ath11k_pci"] {
        let _ = Command::new("modprobe").arg(module).status();
    }

    // Wait up to 4s for wlan0 to appear; if ath11k_pci probed before firmware existed, reload it once.
    let wlan0 = Path::new("/sys/class/net/wlan0");
    for _ in 0..16 {
        if wlan0.exists() {
            break;
        }
        thread::sleep(Duration::from_millis(250));
    }

    if !wlan0.exists() && Path::new("/sys/module/ath11k_pci").exists() {
        println!("[xiaomi-odin-firmware-util] wlan0 not yet registered; reloading ath11k_pci after firmware provisioning...");
        let _ = Command::new("modprobe").args(["-r", "ath11k_pci"]).status();
        thread::sleep(Duration::from_millis(300));
        let _ = Command::new("modprobe").arg("ath11k_pci").status();
        for _ in 0..32 {
            if wlan0.exists() {
                break;
            }
            thread::sleep(Duration::from_millis(250));
        }
    }

    if wlan0.exists() {
        let cur_mac = read_trimmed(&wlan0.join("address")).unwrap_or_default();
        if !cur_mac.eq_ignore_ascii_case(&mac.to_string()) {
            let _ = Command::new("ip").args(["link", "set", "dev", "wlan0", "down"]).status();
            let _ = Command::new("ip")
                .args(["link", "set", "dev", "wlan0", "address", &mac.to_string()])
                .status();
        }
        let _ = Command::new("ip").args(["link", "set", "dev", "wlan0", "up"]).status();
        println!("[xiaomi-odin-firmware-util] wlan0 is registered and UP (MAC {mac})");
    } else {
        eprintln!("[xiaomi-odin-firmware-util] NOTE: wlan0 has not appeared yet; check `xiaomi-odin-firmware-util status` and `dmesg`");
    }
}

fn ensure_udev_rules() {
    let rules: &[(&str, &[u8])] = &[
        (
            "/usr/lib/udev/rules.d/73-xiaomi-odin-haptics.rules",
            b"# Awinic AW8697 LRA haptic controller on Xiaomi MIX 4 (odin)\nSUBSYSTEM==\"input\", KERNEL==\"event*\", ENV{ID_INPUT}==\"1\", SUBSYSTEMS==\"input\", ATTRS{name}==\"aw8697-haptics\", TAG+=\"uaccess\", ENV{FEEDBACKD_TYPE}=\"vibra\"\n",
        ),
        (
            "/usr/lib/udev/rules.d/81-libssc-xiaomi-odin.rules",
            b"# iio-sensor-proxy with libssc: accelerometer mount matrix on Xiaomi MIX 4 (odin)\nSUBSYSTEM==\"misc\", KERNEL==\"fastrpc-*\", ENV{ACCEL_MOUNT_MATRIX}+=\"-1, 0, 0; 0, -1, 0; 0, 0, -1\"\n",
        ),
        (
            "/usr/lib/udev/rules.d/83-xiaomi-odin-flashlight.rules",
            b"# Rear dual-LED torch/flash permissions for video group & Plasma Mobile on Xiaomi MIX 4 (odin)\nSUBSYSTEM==\"leds\", DEVPATH==\"*/*:flash\", RUN+=\"/bin/chmod g+w /sys%p/brightness /sys%p/flash_strobe\", RUN+=\"/bin/chown :video /sys%p/brightness /sys%p/flash_strobe\"\n",
        ),
    ];
    for &(path_str, content) in rules {
        let p = Path::new(path_str);
        let unchanged = fs::read(p).map(|b| b == content).unwrap_or(false);
        if !unchanged {
            let _ = atomic_write(p, content);
        }
    }
}

fn ensure_bluetooth_ready() {
    let _ = Command::new("rfkill").args(["unblock", "bluetooth"]).status();
    let _ = Command::new("modprobe").arg("hci_uart").status();

    let hci0 = Path::new("/sys/class/bluetooth/hci0");
    for _ in 0..12 {
        if hci0.exists() {
            break;
        }
        thread::sleep(Duration::from_millis(250));
    }
    if !hci0.exists() {
        return;
    }

    if Path::new("/usr/bin/btmgmt").is_file() {
        let btmgmt_has_addr = || -> bool {
            Command::new("/usr/bin/btmgmt")
                .args(["--index", "0", "info"])
                .output()
                .map(|out| {
                    let s = format!(
                        "{}{}",
                        String::from_utf8_lossy(&out.stdout),
                        String::from_utf8_lossy(&out.stderr)
                    );
                    s.contains("addr ")
                        && !s.contains("missing options: public-address")
                        && !s.contains("failed")
                })
                .unwrap_or(false)
        };

        if !btmgmt_has_addr() {
            let cmdline = fs::read_to_string("/proc/cmdline").unwrap_or_default();
            let serial = MacAddr::extract_serial_from_cmdline(&cmdline).unwrap_or("xiaomi-odin");
            let bt_mac = MacAddr::bt_from_serial_fallback(serial);
            println!("[xiaomi-odin-firmware-util] Setting deterministic Bluetooth BD_ADDR {bt_mac} on hci0...");
            // Retry briefly in case WCN6855 is still downloading UART firmware
            // or the kernel is asynchronously re-registering hci0.
            for attempt in 0..30 {
                if attempt % 4 == 0 {
                    let _ = Command::new("/usr/bin/btmgmt")
                        .args(["--index", "0", "public-addr", &bt_mac.to_string()])
                        .status();
                }
                thread::sleep(Duration::from_millis(500));
                if btmgmt_has_addr() {
                    break;
                }
            }
        }
        let _ = Command::new("/usr/bin/btmgmt")
            .args(["--index", "0", "power", "on"])
            .status();
    }
}

fn print_status() {
    println!("=== Xiaomi MIX 4 (xiaomi-odin) Hardware & Firmware Status ===");

    // 1. PCIe devices
    print!("PCIe0 devices: ");
    if let Ok(entries) = fs::read_dir("/sys/bus/pci/devices") {
        let mut devs = Vec::new();
        for ent in entries.flatten() {
            let p = ent.path();
            let bdf = ent.file_name().to_string_lossy().into_owned();
            let v = read_trimmed(&p.join("vendor")).unwrap_or_default();
            let d = read_trimmed(&p.join("device")).unwrap_or_default();
            let sv = read_trimmed(&p.join("subsystem_vendor")).unwrap_or_default();
            let sd = read_trimmed(&p.join("subsystem_device")).unwrap_or_default();
            let rev = read_trimmed(&p.join("revision")).unwrap_or_default();
            let speed = read_trimmed(&p.join("current_link_speed")).unwrap_or_default();
            devs.push(format!("{bdf} ({v}:{d} subsys {sv}:{sd} rev {rev} @ {speed})"));
        }
        devs.sort();
        if devs.is_empty() {
            println!("none enumerated");
        } else {
            println!("{}", devs.join(", "));
        }
    } else {
        println!("sysfs /sys/bus/pci unavailable");
    }

    // 2. MHI state
    if let Ok(entries) = fs::read_dir("/sys/bus/mhi/devices") {
        let mut names: Vec<String> = entries
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        println!(
            "MHI bus devices: {}",
            if names.is_empty() {
                "none".into()
            } else {
                names.join(", ")
            }
        );
    }

    // 4. Firmware files (hw1.1 + hw2.0)
    for rev_dir in ["hw1.1", "hw2.0"] {
        let dir = Path::new(DEFAULT_FW_ROOT).join(rev_dir);
        let mut summary = Vec::new();
        for f in ["amss.bin", "m3.bin", "board-2.bin", "regdb.bin"] {
            let p = dir.join(f);
            match fs::metadata(&p) {
                Ok(m) => summary.push(format!("{f}={}B", m.len())),
                Err(_) => summary.push(format!("{f}=MISSING")),
            }
        }
        println!("Firmware {}: {}", dir.display(), summary.join(", "));
    }

    // 5. Adreno 660 GPU, Hexagon ADSP/SLPI firmware + DRM/battery status
    let qcom_dir = Path::new(DEFAULT_QCOM_FW_ROOT);
    let mut gpu_summary = Vec::new();
    for f in [
        "a660_sqe.fw",
        "a660_gmu.bin",
        ODIN_ZAP_REL_PATH,
        ODIN_IRIS_REL_PATH,
        ODIN_ADSP_REL_PATH,
        ODIN_SLPI_REL_PATH,
        ODIN_CDSP_REL_PATH,
    ] {
        let p = qcom_dir.join(f);
        match fs::metadata(&p) {
            Ok(m) => gpu_summary.push(format!("{f}={}B", m.len())),
            Err(_) => gpu_summary.push(format!("{f}=MISSING")),
        }
    }
    println!("Qualcomm FW ({}): {}", qcom_dir.display(), gpu_summary.join(", "));
    let render_node = Path::new("/dev/dri/renderD128");
    println!(
        "DRM render node /dev/dri/renderD128: {}",
        if render_node.exists() { "PRESENT" } else { "NOT PRESENT" }
    );
    let mut video_nodes: Vec<String> = fs::read_dir("/dev")
        .ok()
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| {
            let n = e.file_name().to_string_lossy().into_owned();
            if n.starts_with("video") {
                Some(format!("/dev/{n}"))
            } else {
                None
            }
        })
        .collect();
    video_nodes.sort();
    println!(
        "V4L2 video nodes: {}",
        if video_nodes.is_empty() {
            "none".into()
        } else {
            video_nodes.join(", ")
        }
    );
    let bat_dir = Path::new("/sys/class/power_supply/qcom-battmgr-bat");
    if bat_dir.exists() {
        let cap = read_trimmed(&bat_dir.join("capacity")).unwrap_or_default();
        let st = read_trimmed(&bat_dir.join("status")).unwrap_or_default();
        let pwr = read_trimmed(&bat_dir.join("power_now")).unwrap_or_default();
        println!("Battery (qcom-battmgr-bat): {cap}% ({st}, power_now={pwr} uW)");
    }

    // 6. Peripherals (Bluetooth, Sensors, Haptics, Flashlight)
    println!(
        "Sensors /dev/fastrpc-sdsp: {}",
        if Path::new("/dev/fastrpc-sdsp").exists() { "PRESENT" } else { "NOT PRESENT" }
    );
    println!(
        "CDSP /dev/fastrpc-cdsp: {}",
        if Path::new("/dev/fastrpc-cdsp").exists() { "PRESENT" } else { "NOT PRESENT" }
    );
    println!(
        "Bluetooth /sys/class/bluetooth/hci0: {}",
        if Path::new("/sys/class/bluetooth/hci0").exists() { "PRESENT" } else { "NOT PRESENT" }
    );
    println!(
        "Flashlight /sys/class/leds/white:flash: {}",
        if Path::new("/sys/class/leds/white:flash").exists() { "PRESENT" } else { "NOT PRESENT" }
    );
    let cirrus_dir = Path::new(DEFAULT_CIRRUS_FW_ROOT);
    let mut cirrus_summary = Vec::new();
    for f in [
        "cs35l41-dsp1-spk-prot-xiaomi-odin.wmfw",
        "cs35l41-dsp1-spk-prot-xiaomi-odin-rcv.bin",
        "cs35l41-dsp1-spk-prot-xiaomi-odin-spk.bin",
    ] {
        match fs::metadata(cirrus_dir.join(f)) {
            Ok(m) => cirrus_summary.push(format!("{f}={}B", m.len())),
            Err(_) => cirrus_summary.push(format!("{f}=MISSING")),
        }
    }
    println!("Cirrus FW ({}): {}", cirrus_dir.display(), cirrus_summary.join(", "));
    if let Some(cards) = read_trimmed(Path::new("/proc/asound/cards")) {
        println!("ALSA cards (/proc/asound/cards): {}", if cards.is_empty() { "none" } else { &cards });
    }

    // 7. wlan0 netdev
    let wlan0 = Path::new("/sys/class/net/wlan0");
    if wlan0.exists() {
        let addr = read_trimmed(&wlan0.join("address")).unwrap_or_default();
        let oper = read_trimmed(&wlan0.join("operstate")).unwrap_or_default();
        println!("Interface wlan0: PRESENT (MAC={addr}, operstate={oper})");
        let _ = Command::new("ip").args(["-brief", "addr", "show", "dev", "wlan0"]).status();
        let _ = Command::new("iw").args(["dev", "wlan0", "info"]).status();
    } else {
        println!("Interface wlan0: NOT PRESENT");
    }
}

fn is_gpu_provisioned(qcom_fw_root: &Path) -> bool {
    for rel in [
        "a660_sqe.fw",
        "a660_gmu.bin",
        ODIN_ZAP_REL_PATH,
        ODIN_IRIS_REL_PATH,
    ] {
        let Ok(meta) = fs::metadata(qcom_fw_root.join(rel)) else {
            return false;
        };
        if !meta.is_file() || meta.len() == 0 {
            return false;
        }
    }
    true
}

fn provision_gpu_firmware(qcom_fw_root: &Path) -> Result<(), String> {
    let super_dev = resolve_block_dev(DEFAULT_SUPER_DEV, FALLBACK_SUPER_DEV)
        .ok_or_else(|| format!("super partition not found ({DEFAULT_SUPER_DEV} / {FALLBACK_SUPER_DEV})"))?;

    let vendor_part = lp::find_super_partition(&super_dev, &["vendor_a", "vendor"])?;
    println!(
        "[xiaomi-odin-firmware-util] Mapping dynamic partition '{}' ({} sectors, {} MiB) read-only from {}...",
        vendor_part.name,
        vendor_part.total_sectors(),
        vendor_part.total_bytes() / (1024 * 1024),
        super_dev.display()
    );

    let mapper = SuperMapperGuard::map_ro(&super_dev, &vendor_part)?;
    let vendor_mnt = RoMountGuard::mount_ro(mapper.path(), "ext4", "vendor")?;
    let fw_src = if vendor_mnt.path().join("firmware").is_dir() {
        vendor_mnt.path().join("firmware")
    } else {
        vendor_mnt.path().to_path_buf()
    };

    let sqe = fs::read(fw_src.join("a660_sqe.fw"))
        .map_err(|e| format!("read vendor a660_sqe.fw: {e}"))?;
    let gmu = fs::read(fw_src.join("a660_gmu.bin"))
        .map_err(|e| format!("read vendor a660_gmu.bin: {e}"))?;
    let zap_elf = fs::read(fw_src.join("a660_zap.elf"))
        .map_err(|e| format!("read vendor a660_zap.elf: {e}"))?;
    let vpu_mbn = fs::read(fw_src.join("vpu20_4v.mbn"))
        .map_err(|e| format!("read vendor vpu20_4v.mbn: {e}"))?;

    atomic_write(&qcom_fw_root.join("a660_sqe.fw"), &sqe)?;
    atomic_write(&qcom_fw_root.join("a660_gmu.bin"), &gmu)?;
    atomic_write(&qcom_fw_root.join(ODIN_ZAP_REL_PATH), &zap_elf)?;
    atomic_write(&qcom_fw_root.join(ODIN_IRIS_REL_PATH), &vpu_mbn)?;

    for split_file in ["a660_zap.mdt", "a660_zap.b00", "a660_zap.b01", "a660_zap.b02"] {
        if let Ok(bytes) = fs::read(fw_src.join(split_file)) {
            atomic_write(&qcom_fw_root.join(split_file), &bytes)?;
        }
    }

    if let Ok(hap_bytes) = fs::read(fw_src.join("aw8697_haptic.bin"))
        && let Some(fw_base) = qcom_fw_root.parent() {
            let _ = atomic_write(&fw_base.join("aw8697_haptic.bin"), &hap_bytes);
        }
    if let Some(fw_base) = qcom_fw_root.parent() {
        let cirrus_dir = fw_base.join("cirrus");
        let _ = copy_cirrus_files_from_dir(&fw_src, &cirrus_dir);
    }

    println!(
        "[xiaomi-odin-firmware-util] Installed Xiaomi Adreno 660 & Iris VPU firmware into {} (sqe={} B, gmu={} B, {}={} B, {}={} B)",
        qcom_fw_root.display(),
        sqe.len(),
        gmu.len(),
        ODIN_ZAP_REL_PATH,
        zap_elf.len(),
        ODIN_IRIS_REL_PATH,
        vpu_mbn.len()
    );
    Ok(())
}

fn is_adsp_provisioned(qcom_fw_root: &Path) -> bool {
    let Ok(meta) = fs::metadata(qcom_fw_root.join(ODIN_ADSP_REL_PATH)) else {
        return false;
    };
    meta.is_file() && meta.len() > 1024 * 1024
}

fn provision_adsp_firmware(qcom_fw_root: &Path) -> Result<(), String> {
    let modem_dev = resolve_block_dev(DEFAULT_MODEM_DEV, FALLBACK_MODEM_DEV)
        .ok_or_else(|| format!("modem partition not found ({DEFAULT_MODEM_DEV} / {FALLBACK_MODEM_DEV})"))?;

    println!(
        "[xiaomi-odin-firmware-util] Mounting {} read-only to squash Xiaomi signed ADSP firmware -> {ODIN_ADSP_REL_PATH}...",
        modem_dev.display()
    );
    let modem_mnt = RoMountGuard::mount_ro(&modem_dev, "vfat", "modem-adsp")?;
    let image_dir = if modem_mnt.path().join("image").is_dir() {
        modem_mnt.path().join("image")
    } else {
        modem_mnt.path().to_path_buf()
    };

    let adsp_mbn = mdt::squash_mdt_from_dir(&image_dir, "adsp")?;
    let odin_dir = qcom_fw_root.join(ODIN_SUBDIR);
    atomic_write(&qcom_fw_root.join(ODIN_ADSP_REL_PATH), &adsp_mbn)?;

    let mut jsn_count = 0usize;
    for jsn in ["adspr.jsn", "adspua.jsn", "battmgr.jsn"] {
        if let Ok(bytes) = fs::read(image_dir.join(jsn)) {
            atomic_write(&odin_dir.join(jsn), &bytes)?;
            jsn_count += 1;
        }
    }

    println!(
        "[xiaomi-odin-firmware-util] Installed squashed Xiaomi ADSP firmware into {} ({} B + {} PD .jsn maps)",
        qcom_fw_root.join(ODIN_ADSP_REL_PATH).display(),
        adsp_mbn.len(),
        jsn_count
    );
    Ok(())
}

fn copy_dir_files(src: &Path, dst: &Path, lowercase_names: bool, overwrite: bool) -> Result<usize, String> {
    fs::create_dir_all(dst).map_err(|e| format!("mkdir {}: {e}", dst.display()))?;
    let rd = fs::read_dir(src).map_err(|e| format!("readdir {}: {e}", src.display()))?;
    let mut count = 0usize;
    for ent in rd.flatten() {
        let p = ent.path();
        if !p.is_file() {
            continue;
        }
        let Some(raw_name) = p.file_name().and_then(|s| s.to_str()) else {
            continue;
        };
        let target_name = if lowercase_names {
            raw_name.to_ascii_lowercase()
        } else {
            raw_name.to_owned()
        };
        let dest_path = dst.join(target_name);
        if !overwrite && dest_path.is_file() {
            continue;
        }
        let bytes = fs::read(&p).map_err(|e| format!("read {}: {e}", p.display()))?;
        atomic_write(&dest_path, &bytes)?;
        count += 1;
    }
    Ok(count)
}

fn is_slpi_provisioned(qcom_fw_root: &Path, hexagon_root: &Path) -> bool {
    let Ok(meta) = fs::metadata(qcom_fw_root.join(ODIN_SLPI_REL_PATH)) else {
        return false;
    };
    if !meta.is_file() || meta.len() <= 1024 * 1024 {
        return false;
    }
    fs::read_to_string(hexagon_root.join("sensors/sns_reg.conf"))
        .map(|s| s.contains("/sensors/registry/registry/reg"))
        .unwrap_or(false)
        && hexagon_root.join("sensors/config").is_dir()
        && hexagon_root.join("sensors/registry/sns_reg_version").is_file()
        && hexagon_root.join("sensors/registry/sns_reg_config").is_file()
        && hexagon_root.join("sensors/registry/reg/default_sensors.accel").is_file()
        && hexagon_root.join("socinfo/hw_platform").is_file()
}

fn provision_slpi_and_sensors(qcom_fw_root: &Path, hexagon_root: &Path) -> Result<(), String> {
    let modem_dev = resolve_block_dev(DEFAULT_MODEM_DEV, FALLBACK_MODEM_DEV)
        .ok_or_else(|| format!("modem partition not found ({DEFAULT_MODEM_DEV} / {FALLBACK_MODEM_DEV})"))?;

    println!(
        "[xiaomi-odin-firmware-util] Mounting {} read-only to squash Xiaomi signed SLPI firmware -> {ODIN_SLPI_REL_PATH}...",
        modem_dev.display()
    );
    let modem_mnt = RoMountGuard::mount_ro(&modem_dev, "vfat", "modem-slpi")?;
    let image_dir = if modem_mnt.path().join("image").is_dir() {
        modem_mnt.path().join("image")
    } else {
        modem_mnt.path().to_path_buf()
    };

    let slpi_mbn = mdt::squash_mdt_from_dir(&image_dir, "slpi")?;
    let odin_dir = qcom_fw_root.join(ODIN_SUBDIR);
    atomic_write(&qcom_fw_root.join(ODIN_SLPI_REL_PATH), &slpi_mbn)?;

    let mut jsn_count = 0usize;
    for jsn in ["slpir.jsn", "slpius.jsn"] {
        if let Ok(bytes) = fs::read(image_dir.join(jsn)) {
            atomic_write(&odin_dir.join(jsn), &bytes)?;
            jsn_count += 1;
        }
    }
    drop(modem_mnt);

    // Populate HexagonRPCD SDSP filesystem under /usr/share/qcom/sm8350/Xiaomi/odin
    let super_dev = resolve_block_dev(DEFAULT_SUPER_DEV, FALLBACK_SUPER_DEV)
        .ok_or_else(|| format!("super partition not found ({DEFAULT_SUPER_DEV} / {FALLBACK_SUPER_DEV})"))?;
    let vendor_part = lp::find_super_partition(&super_dev, &["vendor_a", "vendor"])?;
    let mapper = SuperMapperGuard::map_ro(&super_dev, &vendor_part)?;
    let vendor_mnt = RoMountGuard::mount_ro(mapper.path(), "ext4", "vendor-slpi")?;

    let sns_src = vendor_mnt.path().join("etc/sensors");
    let raw_sns_reg_cfg = fs::read_to_string(sns_src.join("sns_reg_config"))
        .map_err(|e| format!("read vendor sns_reg_config: {e}"))?;
    // Shift SLPI's registry output one level down into .../registry/reg so that
    // SLPI's relative lookups (<output>/../sns_reg_version and ../sns_reg_config)
    // land inside hexagonrpcd's mapped /sensors/registry/ root instead of escaping
    // outside it and causing ENOENT + 56s of read-only temp.json retry loops.
    let sns_reg_cfg = raw_sns_reg_cfg.replace(
        "file=output=/mnt/vendor/persist/sensors/registry/registry\n",
        "file=output=/mnt/vendor/persist/sensors/registry/registry/reg\n",
    );
    atomic_write(&hexagon_root.join("sensors/sns_reg.conf"), sns_reg_cfg.as_bytes())?;
    let cfg_backup_dir = hexagon_root.join("sensors/config.orig");
    let cfg_count = copy_dir_files(&sns_src.join("config"), &cfg_backup_dir, false, true)?;

    if let Ok(hap_bytes) = fs::read(vendor_mnt.path().join("firmware/aw8697_haptic.bin"))
        && let Some(fw_base) = qcom_fw_root.parent() {
            let _ = atomic_write(&fw_base.join("aw8697_haptic.bin"), &hap_bytes);
        }
    drop(vendor_mnt);
    drop(mapper);

    if let Some(dsp_dev) = resolve_block_dev(DEFAULT_DSP_DEV, FALLBACK_DSP_DEV)
        && let Ok(dsp_mnt) = RoMountGuard::mount_ro(&dsp_dev, "ext4", "dsp-slpi") {
            let sdsp_src = dsp_mnt.path().join("sdsp");
            if sdsp_src.is_dir() {
                let _ = copy_dir_files(&sdsp_src, &hexagon_root.join("dsp/sdsp"), false, true);
            }
        }

    let reg_root = hexagon_root.join("sensors/registry");
    let reg_sub = reg_root.join("reg");
    let mut reg_count = 0usize;
    let mut have_reg_version = false;
    if let Some(persist_dev) = resolve_block_dev(DEFAULT_PERSIST_DEV, FALLBACK_PERSIST_DEV)
        && let Ok(persist_mnt) = RoMountGuard::mount_ro(&persist_dev, "ext4", "persist-slpi") {
            let reg_src = persist_mnt.path().join("sensors/registry/registry");
            if reg_src.is_dir() {
                reg_count = copy_dir_files(&reg_src, &reg_sub, false, false)?;
            }
            if let Ok(ver_bytes) = fs::read(persist_mnt.path().join("sensors/registry/sns_reg_version")) {
                atomic_write(&reg_root.join("sns_reg_version"), &ver_bytes)?;
                have_reg_version = true;
            }
        }
    if !have_reg_version {
        atomic_write(&reg_root.join("sns_reg_version"), b"version=6\0")?;
    }
    atomic_write(&reg_root.join("sns_reg_config"), sns_reg_cfg.as_bytes())?;

    // Keep sensors/config empty when pre-parsed persist registry files are present so
    // SLPI loads all 278 pre-parsed + factory-calibrated files directly in ~2s without
    // trying to re-parse 66 vendor JSONs into hexagonrpcd's read-only filesystem.
    // Fall back to populating sensors/config only if persist had no pre-parsed files.
    let cfg_dir = hexagon_root.join("sensors/config");
    fs::create_dir_all(&cfg_dir).map_err(|e| format!("create sensors/config: {e}"))?;
    if reg_sub.join("default_sensors.accel").is_file() {
        if let Ok(entries) = fs::read_dir(&cfg_dir) {
            for entry in entries.flatten() {
                if entry.path().is_file() {
                    let _ = fs::remove_file(entry.path());
                }
            }
        }
    } else {
        let _ = copy_dir_files(&cfg_backup_dir, &cfg_dir, false, true);
    }

    // Populate socinfo expected by sns_reg_config (qcom,board-id = <0x10008 0x00>, soc_id = 415)
    let soc_id = read_trimmed(Path::new("/sys/devices/soc0/soc_id")).unwrap_or_else(|| "415".into());
    let revision = read_trimmed(Path::new("/sys/devices/soc0/revision")).unwrap_or_else(|| "2.1".into());
    for (k, v) in [
        ("hw_platform", "MTP"),
        ("platform_subtype", "Unknown"),
        ("platform_subtype_id", "0"),
        ("platform_version", "65536"),
        ("soc_id", soc_id.as_str()),
        ("revision", revision.as_str()),
    ] {
        atomic_write(&hexagon_root.join("socinfo").join(k), format!("{v}\n").as_bytes())?;
    }

    atomic_write(
        Path::new("/usr/share/hexagonrpcd/hexagonrpcd-sdsp.conf"),
        format!("hexagonrpcd_fw_dir=\"{}\"\n", hexagon_root.display()).as_bytes(),
    )?;

    let udev_rule_path = Path::new("/usr/lib/udev/rules.d/81-libssc-xiaomi-odin.rules");
    atomic_write(
        udev_rule_path,
        b"# iio-sensor-proxy with libssc: accelerometer mount matrix\nSUBSYSTEM==\"misc\", KERNEL==\"fastrpc-*\", ENV{ACCEL_MOUNT_MATRIX}+=\"-1, 0, 0; 0, -1, 0; 0, 0, -1\"\n",
    )?;

    // Ensure hexagonrpcd (running as fastrpc:fastrpc) can read all served files and write registry updates
    let _ = Command::new("chmod")
        .args(["-R", "a+rX"])
        .arg("/usr/share/qcom")
        .status();
    let _ = Command::new("chown")
        .args(["-R", "fastrpc:fastrpc"])
        .arg(hexagon_root.join("sensors/registry"))
        .status();

    println!(
        "[xiaomi-odin-firmware-util] Installed Xiaomi SLPI ({} B + {} .jsn) & HexagonFS ({} sensor configs, {} new registry files)",
        slpi_mbn.len(),
        jsn_count,
        cfg_count,
        reg_count
    );
    Ok(())
}

fn is_cdsp_provisioned(qcom_fw_root: &Path, hexagon_root: &Path) -> bool {
    let Ok(meta) = fs::metadata(qcom_fw_root.join(ODIN_CDSP_REL_PATH)) else {
        return false;
    };
    if !meta.is_file() || meta.len() <= 1024 * 1024 {
        return false;
    }
    hexagon_root.join("dsp/cdsp/libcalculator_skel.so").is_file()
        && Path::new("/usr/share/hexagonrpcd/hexagonrpcd-cdsp.conf").is_file()
        && Path::new("/usr/lib/rfsa/adsp/fastrpc_shell_unsigned_3").is_file()
}

fn start_remoteproc_if_offline(target_substr: &str) {
    let Ok(entries) = fs::read_dir("/sys/class/remoteproc") else {
        return;
    };
    for ent in entries.flatten() {
        let p = ent.path();
        let name = read_trimmed(&p.join("name")).unwrap_or_default();
        if name.contains(target_substr) {
            let state = read_trimmed(&p.join("state")).unwrap_or_default();
            if state == "offline" {
                println!("[xiaomi-odin-firmware-util] Starting remoteproc {} ({name})...", p.display());
                let _ = fs::write(p.join("state"), b"start\n");
            }
        }
    }
}

fn provision_cdsp_firmware(qcom_fw_root: &Path, hexagon_root: &Path) -> Result<(), String> {
    let modem_dev = resolve_block_dev(DEFAULT_MODEM_DEV, FALLBACK_MODEM_DEV)
        .ok_or_else(|| format!("modem partition not found ({DEFAULT_MODEM_DEV} / {FALLBACK_MODEM_DEV})"))?;

    println!(
        "[xiaomi-odin-firmware-util] Mounting {} read-only to squash Xiaomi signed CDSP firmware -> {ODIN_CDSP_REL_PATH}...",
        modem_dev.display()
    );
    let modem_mnt = RoMountGuard::mount_ro(&modem_dev, "vfat", "modem-cdsp")?;
    let image_dir = if modem_mnt.path().join("image").is_dir() {
        modem_mnt.path().join("image")
    } else {
        modem_mnt.path().to_path_buf()
    };

    let cdsp_mbn = mdt::squash_mdt_from_dir(&image_dir, "cdsp")?;
    let odin_dir = qcom_fw_root.join(ODIN_SUBDIR);
    atomic_write(&qcom_fw_root.join(ODIN_CDSP_REL_PATH), &cdsp_mbn)?;

    let mut jsn_count = 0usize;
    for jsn in ["cdspr.jsn", "cdspua.jsn"] {
        if let Ok(bytes) = fs::read(image_dir.join(jsn)) {
            atomic_write(&odin_dir.join(jsn), &bytes)?;
            jsn_count += 1;
        }
    }
    drop(modem_mnt);

    let cdsp_dst = hexagon_root.join("dsp/cdsp");
    let mut dsp_count = 0usize;
    if let Some(dsp_dev) = resolve_block_dev(DEFAULT_DSP_DEV, FALLBACK_DSP_DEV)
        && let Ok(dsp_mnt) = RoMountGuard::mount_ro(&dsp_dev, "ext4", "dsp-cdsp") {
            let cdsp_src = dsp_mnt.path().join("cdsp");
            if cdsp_src.is_dir() {
                dsp_count = copy_dir_files(&cdsp_src, &cdsp_dst, false, true)?;
            }
        }

    let super_dev = resolve_block_dev(DEFAULT_SUPER_DEV, FALLBACK_SUPER_DEV)
        .ok_or_else(|| format!("super partition not found ({DEFAULT_SUPER_DEV} / {FALLBACK_SUPER_DEV})"))?;
    let vendor_part = lp::find_super_partition(&super_dev, &["vendor_a", "vendor"])?;
    let mapper = SuperMapperGuard::map_ro(&super_dev, &vendor_part)?;
    let vendor_mnt = RoMountGuard::mount_ro(mapper.path(), "ext4", "vendor-cdsp")?;
    let rfsa_adsp = vendor_mnt.path().join("lib/rfsa/adsp");
    let mut skel_len = 0usize;
    if let Ok(bytes) = fs::read(rfsa_adsp.join("libcalculator_skel.so")) {
        skel_len = bytes.len();
        atomic_write(&cdsp_dst.join("libcalculator_skel.so"), &bytes)?;
    }
    drop(vendor_mnt);
    drop(mapper);

    atomic_write(
        Path::new("/usr/share/hexagonrpcd/hexagonrpcd-cdsp.conf"),
        format!("hexagonrpcd_fw_dir=\"{}\"\n", hexagon_root.display()).as_bytes(),
    )?;

    // Symlink standard libcdsprpc search paths so Linux FastRPC clients find
    // fastrpc_shell_unsigned_3 and CDSP skeleton modules without extra env vars.
    let _ = fs::create_dir_all("/usr/lib/rfsa");
    for (target, link) in [
        (hexagon_root.join("dsp"), Path::new("/usr/lib/dsp")),
        (cdsp_dst.clone(), Path::new("/usr/lib/rfsa/adsp")),
    ] {
        let _ = fs::remove_file(link);
        let _ = std::os::unix::fs::symlink(&target, link);
    }

    let _ = Command::new("chmod")
        .args(["-R", "a+rX"])
        .arg("/usr/share/qcom")
        .status();

    println!(
        "[xiaomi-odin-firmware-util] Installed Xiaomi CDSP ({} B + {} .jsn, {} dsp/cdsp files, libcalculator_skel.so={} B)",
        cdsp_mbn.len(),
        jsn_count,
        dsp_count,
        skel_len
    );
    start_remoteproc_if_offline("cdsp");
    Ok(())
}

fn is_bt_provisioned(qca_bt_root: &Path) -> bool {
    qca_bt_root.join("hpbtfw10.tlv").is_file()
        && qca_bt_root.join("hpnv10.bin").is_file()
        && qca_bt_root.join("wcnhpbtfw10.tlv").is_file()
        && qca_bt_root.join("wcnhpnv10.bin").is_file()
}

fn is_cirrus_provisioned(cirrus_fw_root: &Path) -> bool {
    for f in [
        "cs35l41-dsp1-spk-prot-xiaomi-odin.wmfw",
        "cs35l41-dsp1-spk-prot-xiaomi-odin-rcv.bin",
        "cs35l41-dsp1-spk-prot-xiaomi-odin-spk.bin",
    ] {
        let Ok(meta) = fs::metadata(cirrus_fw_root.join(f)) else {
            return false;
        };
        if !meta.is_file() || meta.len() == 0 {
            return false;
        }
    }
    true
}

fn copy_cirrus_files_from_dir(fw_src: &Path, cirrus_fw_root: &Path) -> Result<(), String> {
    let mappings = [
        (
            "cs35l41-dsp1-spk-prot-revb2.wmfw",
            "cs35l41-dsp1-spk-prot-xiaomi-odin.wmfw",
        ),
        (
            "cs35l41-dsp1-spk-prot-RCV-revb2.bin",
            "cs35l41-dsp1-spk-prot-xiaomi-odin-rcv.bin",
        ),
        (
            "cs35l41-dsp1-spk-prot-revb2.bin",
            "cs35l41-dsp1-spk-prot-xiaomi-odin-spk.bin",
        ),
    ];
    for (src_name, dst_name) in mappings {
        let bytes = fs::read(fw_src.join(src_name))
            .map_err(|e| format!("read vendor {src_name}: {e}"))?;
        atomic_write(&cirrus_fw_root.join(dst_name), &bytes)?;
    }
    println!(
        "[xiaomi-odin-firmware-util] Installed Cirrus CS35L41 Rev B2 speaker firmware into {}",
        cirrus_fw_root.display()
    );
    Ok(())
}

fn provision_cirrus_firmware(cirrus_fw_root: &Path) -> Result<(), String> {
    let super_dev = resolve_block_dev(DEFAULT_SUPER_DEV, FALLBACK_SUPER_DEV)
        .ok_or_else(|| format!("super partition not found ({DEFAULT_SUPER_DEV} / {FALLBACK_SUPER_DEV})"))?;
    let vendor_part = lp::find_super_partition(&super_dev, &["vendor_a", "vendor"])?;
    let mapper = SuperMapperGuard::map_ro(&super_dev, &vendor_part)?;
    let vendor_mnt = RoMountGuard::mount_ro(mapper.path(), "ext4", "vendor-cirrus")?;
    let fw_src = if vendor_mnt.path().join("firmware").is_dir() {
        vendor_mnt.path().join("firmware")
    } else {
        vendor_mnt.path().to_path_buf()
    };
    copy_cirrus_files_from_dir(&fw_src, cirrus_fw_root)
}

fn provision_bt_firmware(qca_bt_root: &Path) -> Result<(), String> {
    let Some(bt_dev) = resolve_block_dev(DEFAULT_BT_DEV, FALLBACK_BT_DEV) else {
        return Ok(());
    };
    let bt_mnt = RoMountGuard::mount_ro(&bt_dev, "vfat", "bt")?;
    let image_dir = if bt_mnt.path().join("image").is_dir() {
        bt_mnt.path().join("image")
    } else {
        bt_mnt.path().to_path_buf()
    };
    let copied = copy_dir_files(&image_dir, qca_bt_root, true, true)?;
    // Mainline btqca.c queries qca/wcnhpbtfw10.tlv and qca/wcnhpnv10.bin first on WCN6855
    // before falling back to hpbtfw10.tlv / hpnv10.bin; symlink to avoid -2 dmesg warnings.
    for (link_name, target_name) in [
        ("wcnhpbtfw10.tlv", "hpbtfw10.tlv"),
        ("wcnhpnv10.bin", "hpnv10.bin"),
    ] {
        let link_path = qca_bt_root.join(link_name);
        if qca_bt_root.join(target_name).is_file() && !link_path.exists() {
            let _ = fs::remove_file(&link_path);
            let _ = std::os::unix::fs::symlink(target_name, &link_path);
        }
    }
    println!(
        "[xiaomi-odin-firmware-util] Installed {} lowercase QCA6490/WCN6855 Bluetooth firmware files into {}",
        copied,
        qca_bt_root.display()
    );
    Ok(())
}

fn is_already_provisioned(fw_root: &Path) -> bool {
    let hw11 = fw_root.join("hw1.1");
    let hw20 = fw_root.join("hw2.0");
    for dir in [&hw11, &hw20] {
        for f in ["amss.bin", "m3.bin", "board-2.bin", "board.bin", "regdb.bin"] {
            if !dir.join(f).is_file() {
                return false;
            }
        }
        let Ok(meta) = fs::metadata(dir.join("board-2.bin")) else {
            return false;
        };
        if meta.len() > COMPACT_BD2_MAX_BYTES {
            return false;
        }
    }
    let Ok(raw_bd2) = fs::read(hw11.join("board-2.bin")) else {
        return false;
    };
    let subsys = detect_live_wcn6855_subsys();
    if let Some(&(sv, sd)) = subsys.first() {
        for cid in [0u32, 2] {
            let probe_name = format!(
                "bus=pci,vendor=17cb,device=1103,subsystem-vendor={sv:04x},subsystem-device={sd:04x},qmi-chip-id={cid},qmi-board-id=255,variant={VARIANT_NAME}"
            );
            if !matches!(
                Board2Bundle::kernel_lookup(&raw_bd2, ATH11K_BD_IE_BOARD, &probe_name),
                Ok(Some(_))
            ) {
                return false;
            }
        }
    }
    true
}

fn print_usage() {
    eprintln!(
        "Usage:\n  \
         xiaomi-odin-firmware-util provision [--if-needed] [--amss auto|upstream|vendor] [--include-ref-bdfs] [--fw-root DIR]\n  \
         xiaomi-odin-firmware-util provision-gpu [--if-needed] [--qcom-fw-root DIR]\n  \
         xiaomi-odin-firmware-util provision-adsp [--if-needed] [--qcom-fw-root DIR]\n  \
         xiaomi-odin-firmware-util bluetooth\n  \
         xiaomi-odin-firmware-util status"
    );
}

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    let Some(cmd) = args.first().map(String::as_str) else {
        print_usage();
        return ExitCode::from(2);
    };

    match cmd {
        "provision" => {
            let mut if_needed = false;
            let mut include_ref_bdfs = false;
            let mut amss_src = AmssSource::Auto;
            let mut fw_root = PathBuf::from(DEFAULT_FW_ROOT);
            let qcom_fw_root = PathBuf::from(DEFAULT_QCOM_FW_ROOT);
            let qca_bt_root = PathBuf::from(DEFAULT_QCA_BT_FW_ROOT);
            let cirrus_fw_root = PathBuf::from(DEFAULT_CIRRUS_FW_ROOT);
            let hexagon_root = PathBuf::from(DEFAULT_HEXAGON_SHARE_ROOT);
            let mut i = 1;
            while i < args.len() {
                match args[i].as_str() {
                    "--if-needed" => {
                        if_needed = true;
                        i += 1;
                    }
                    "--include-ref-bdfs" => {
                        include_ref_bdfs = true;
                        i += 1;
                    }
                    "--amss" if i + 1 < args.len() => {
                        amss_src = match args[i + 1].as_str() {
                            "upstream" => AmssSource::Upstream,
                            "vendor" => AmssSource::Vendor,
                            _ => AmssSource::Auto,
                        };
                        i += 2;
                    }
                    "--fw-root" if i + 1 < args.len() => {
                        fw_root = PathBuf::from(&args[i + 1]);
                        i += 2;
                    }
                    other => {
                        eprintln!("Unknown option: {other}");
                        print_usage();
                        return ExitCode::from(2);
                    }
                }
            }

            ensure_udev_rules();

            if (!if_needed || !is_gpu_provisioned(&qcom_fw_root) || !Path::new("/lib/firmware/aw8697_haptic.bin").is_file())
                && let Err(e) = provision_gpu_firmware(&qcom_fw_root) {
                    eprintln!("[xiaomi-odin-firmware-util] WARN: could not provision Adreno 660 firmware: {e}");
                }
            if (!if_needed || !is_adsp_provisioned(&qcom_fw_root))
                && let Err(e) = provision_adsp_firmware(&qcom_fw_root) {
                    eprintln!("[xiaomi-odin-firmware-util] WARN: could not provision ADSP firmware: {e}");
                }
            if (!if_needed || !is_slpi_provisioned(&qcom_fw_root, &hexagon_root))
                && let Err(e) = provision_slpi_and_sensors(&qcom_fw_root, &hexagon_root) {
                    eprintln!("[xiaomi-odin-firmware-util] WARN: could not provision SLPI/sensors firmware: {e}");
                }
            if !if_needed || !is_cdsp_provisioned(&qcom_fw_root, &hexagon_root) {
                if let Err(e) = provision_cdsp_firmware(&qcom_fw_root, &hexagon_root) {
                    eprintln!("[xiaomi-odin-firmware-util] WARN: could not provision CDSP firmware: {e}");
                }
            } else {
                start_remoteproc_if_offline("cdsp");
            }
            if (!if_needed || !is_bt_provisioned(&qca_bt_root))
                && let Err(e) = provision_bt_firmware(&qca_bt_root) {
                    eprintln!("[xiaomi-odin-firmware-util] WARN: could not provision Bluetooth firmware: {e}");
                }
            if (!if_needed || !is_cirrus_provisioned(&cirrus_fw_root))
                && let Err(e) = provision_cirrus_firmware(&cirrus_fw_root) {
                    eprintln!("[xiaomi-odin-firmware-util] WARN: could not provision Cirrus CS35L41 firmware: {e}");
                }

            if if_needed && !include_ref_bdfs && is_already_provisioned(&fw_root) {
                let mac = read_trimmed(Path::new(MAC_STATE_PATH))
                    .or_else(|| read_trimmed(Path::new(LEGACY_MAC_STATE_PATH)))
                    .and_then(|s| MacAddr::parse_hex12(&s))
                    .or_else(|| match sync_mac_address() {
                        Ok(m) => Some(m),
                        Err(e) => {
                            eprintln!("[xiaomi-odin-firmware-util] WARN: could not sync MAC address: {e}");
                            None
                        }
                    });
                if let Some(mac) = mac {
                    println!(
                        "[xiaomi-odin-firmware-util] Firmware (hw1.1 + hw2.0 + Adreno 660) & compact K8 board-2.bin verified; ensuring wlan0 ({mac})..."
                    );
                    ensure_modules_and_interface(mac);
                    return ExitCode::SUCCESS;
                }
            }

            if let Err(e) = provision_firmware(&fw_root, amss_src, include_ref_bdfs) {
                eprintln!("[xiaomi-odin-firmware-util] ERROR provisioning firmware: {e}");
                return ExitCode::from(1);
            }
            match sync_mac_address() {
                Ok(mac) => ensure_modules_and_interface(mac),
                Err(e) => {
                    eprintln!("[xiaomi-odin-firmware-util] ERROR syncing MAC address: {e}");
                    return ExitCode::from(1);
                }
            }
            ExitCode::SUCCESS
        }
        "provision-gpu" => {
            let mut if_needed = false;
            let mut qcom_fw_root = PathBuf::from(DEFAULT_QCOM_FW_ROOT);
            let mut i = 1;
            while i < args.len() {
                match args[i].as_str() {
                    "--if-needed" => {
                        if_needed = true;
                        i += 1;
                    }
                    "--qcom-fw-root" if i + 1 < args.len() => {
                        qcom_fw_root = PathBuf::from(&args[i + 1]);
                        i += 2;
                    }
                    other => {
                        eprintln!("Unknown option: {other}");
                        print_usage();
                        return ExitCode::from(2);
                    }
                }
            }

            if if_needed && is_gpu_provisioned(&qcom_fw_root) {
                println!(
                    "[xiaomi-odin-firmware-util] Adreno 660 firmware already verified under {}",
                    qcom_fw_root.display()
                );
                return ExitCode::SUCCESS;
            }

            match provision_gpu_firmware(&qcom_fw_root) {
                Ok(()) => ExitCode::SUCCESS,
                Err(e) => {
                    eprintln!("[xiaomi-odin-firmware-util] ERROR provisioning Adreno 660 firmware: {e}");
                    ExitCode::from(1)
                }
            }
        }
        "provision-adsp" => {
            let mut if_needed = false;
            let mut qcom_fw_root = PathBuf::from(DEFAULT_QCOM_FW_ROOT);
            let mut i = 1;
            while i < args.len() {
                match args[i].as_str() {
                    "--if-needed" => {
                        if_needed = true;
                        i += 1;
                    }
                    "--qcom-fw-root" if i + 1 < args.len() => {
                        qcom_fw_root = PathBuf::from(&args[i + 1]);
                        i += 2;
                    }
                    other => {
                        eprintln!("Unknown option: {other}");
                        print_usage();
                        return ExitCode::from(2);
                    }
                }
            }

            if if_needed && is_adsp_provisioned(&qcom_fw_root) {
                println!(
                    "[xiaomi-odin-firmware-util] ADSP firmware already verified under {}",
                    qcom_fw_root.join(ODIN_ADSP_REL_PATH).display()
                );
                return ExitCode::SUCCESS;
            }

            match provision_adsp_firmware(&qcom_fw_root) {
                Ok(()) => ExitCode::SUCCESS,
                Err(e) => {
                    eprintln!("[xiaomi-odin-firmware-util] ERROR provisioning ADSP firmware: {e}");
                    ExitCode::from(1)
                }
            }
        }
        "status" => {
            print_status();
            ExitCode::SUCCESS
        }
        "bluetooth" => {
            ensure_bluetooth_ready();
            ExitCode::SUCCESS
        }
        _ => {
            print_usage();
            ExitCode::from(2)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn k8_board_aliases_cover_live_odin_hw11_pci_ids_and_fallbacks() {
        let aliases = build_k8_board_aliases(&[(0x17cb, 0x0108)]);
        assert!(aliases.contains(&"bus=pci,vendor=17cb,device=1103,subsystem-vendor=17cb,subsystem-device=0108,qmi-chip-id=2,qmi-board-id=255,variant=Xiaomi_MIX4".to_owned()));
        assert!(aliases.contains(&"bus=pci,vendor=17cb,device=1103,subsystem-vendor=17cb,subsystem-device=0108,qmi-chip-id=2,qmi-board-id=255".to_owned()));
        assert!(aliases.contains(&"bus=pci,qmi-chip-id=2".to_owned()));

        let fake_elf = b"\x7fELFk8-calibration-payload".to_vec();
        let fake_regdb = b"REGDB-XIAOMI".to_vec();
        let bundle = Board2Bundle {
            boards: vec![BoardEntry {
                names: aliases,
                data: fake_elf.clone(),
            }],
            regdbs: vec![BoardEntry {
                names: vec!["bus=pci".to_owned()],
                data: fake_regdb.clone(),
            }],
        };
        let raw = bundle.encode().expect("encode compact k8 bundle");
        assert!(raw.len() < 16 * 1024);
        assert_eq!(
            Board2Bundle::kernel_lookup(
                &raw,
                ATH11K_BD_IE_BOARD,
                "bus=pci,vendor=17cb,device=1103,subsystem-vendor=17cb,subsystem-device=0108,qmi-chip-id=18,qmi-board-id=255,variant=Xiaomi_MIX4"
            )
            .unwrap(),
            Some(fake_elf.as_slice())
        );
        assert_eq!(
            Board2Bundle::kernel_lookup(&raw, ATH11K_BD_IE_BOARD, "bus=pci,qmi-chip-id=0").unwrap(),
            Some(fake_elf.as_slice())
        );
        assert_eq!(
            Board2Bundle::kernel_lookup(&raw, ATH11K_BD_IE_REGDB, "bus=pci").unwrap(),
            Some(fake_regdb.as_slice())
        );
    }
}
