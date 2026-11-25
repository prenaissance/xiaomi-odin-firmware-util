//! Pure-Rust parser for Android `liblp` (`LpMetadata`) dynamic partitions inside `super`.
//!
//! Used on Xiaomi MIX 4 (`xiaomi-odin`, SM8350) to locate `vendor_a` inside
//! `/dev/disk/by-partlabel/super` (`/dev/sda28`) and map it zero-copy read-only
//! via `dm-linear` (`dmsetup`) or `loop` (`losetup`) to extract factory-signed
//! Adreno 660 GPU firmware (`a660_sqe.fw`, `a660_gmu.bin`, `a660_zap.elf`).

use std::fs::File;
use std::io::Read;
use std::path::Path;

pub const LP_PARTITION_RESERVED_BYTES: usize = 4096;
pub const LP_METADATA_GEOMETRY_SIZE: usize = 4096;
pub const LP_METADATA_GEOMETRY_MAGIC: u32 = 0x616c_4467; // "gDla"
pub const LP_METADATA_HEADER_MAGIC: u32 = 0x414c_5030; // "0PLA"
pub const LP_METADATA_MAJOR_VERSION: u16 = 10;
pub const LP_TARGET_TYPE_LINEAR: u32 = 0;
pub const LP_SECTOR_SIZE: u64 = 512;

const SUPER_METADATA_READ_BYTES: usize = 256 * 1024;
const PARTITION_ENTRY_MIN_SIZE: usize = 52;
const EXTENT_ENTRY_MIN_SIZE: usize = 24;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LinearExtent {
    pub logical_sector: u64,
    pub num_sectors: u64,
    pub physical_sector: u64,
    pub target_source: u32,
}

impl LinearExtent {
    pub fn byte_offset(&self) -> u64 {
        self.physical_sector * LP_SECTOR_SIZE
    }

    pub fn byte_len(&self) -> u64 {
        self.num_sectors * LP_SECTOR_SIZE
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DynamicPartition {
    pub name: String,
    pub attributes: u32,
    pub extents: Vec<LinearExtent>,
}

impl DynamicPartition {
    pub fn total_sectors(&self) -> u64 {
        self.extents.iter().map(|e| e.num_sectors).sum()
    }

    pub fn total_bytes(&self) -> u64 {
        self.total_sectors() * LP_SECTOR_SIZE
    }

    /// Format a `dm-linear` table suitable for `dmsetup create --readonly`.
    pub fn dm_table(&self, backing_dev: &str) -> String {
        self.extents
            .iter()
            .map(|e| {
                format!(
                    "{} {} linear {} {}",
                    e.logical_sector, e.num_sectors, backing_dev, e.physical_sector
                )
            })
            .collect::<Vec<_>>()
            .join("\n")
    }
}

#[derive(Debug, Clone, Copy)]
struct LpGeometry {
    metadata_max_size: usize,
    metadata_slot_count: usize,
}

#[derive(Debug, Clone, Copy)]
struct TableDesc {
    offset: usize,
    num_entries: usize,
    entry_size: usize,
}

fn read_u16_le(buf: &[u8], off: usize) -> Result<u16, String> {
    let end = off.checked_add(2).ok_or("u16 offset overflow")?;
    let bytes: [u8; 2] = buf
        .get(off..end)
        .ok_or_else(|| format!("unexpected EOF reading u16 at {off:#x}"))?
        .try_into()
        .map_err(|_| "u16 slice conversion failed".to_owned())?;
    Ok(u16::from_le_bytes(bytes))
}

fn read_u32_le(buf: &[u8], off: usize) -> Result<u32, String> {
    let end = off.checked_add(4).ok_or("u32 offset overflow")?;
    let bytes: [u8; 4] = buf
        .get(off..end)
        .ok_or_else(|| format!("unexpected EOF reading u32 at {off:#x}"))?
        .try_into()
        .map_err(|_| "u32 slice conversion failed".to_owned())?;
    Ok(u32::from_le_bytes(bytes))
}

fn read_u64_le(buf: &[u8], off: usize) -> Result<u64, String> {
    let end = off.checked_add(8).ok_or("u64 offset overflow")?;
    let bytes: [u8; 8] = buf
        .get(off..end)
        .ok_or_else(|| format!("unexpected EOF reading u64 at {off:#x}"))?
        .try_into()
        .map_err(|_| "u64 slice conversion failed".to_owned())?;
    Ok(u64::from_le_bytes(bytes))
}

fn parse_geometry_at(buf: &[u8], off: usize) -> Result<LpGeometry, String> {
    let magic = read_u32_le(buf, off)?;
    if magic != LP_METADATA_GEOMETRY_MAGIC {
        return Err(format!(
            "invalid LpMetadataGeometry magic at {off:#x}: {magic:#010x}"
        ));
    }
    let metadata_max_size = read_u32_le(buf, off + 40)? as usize;
    let metadata_slot_count = read_u32_le(buf, off + 44)? as usize;
    if metadata_max_size == 0 || metadata_slot_count == 0 {
        return Err("zero metadata_max_size or metadata_slot_count in LpMetadataGeometry".into());
    }
    Ok(LpGeometry {
        metadata_max_size,
        metadata_slot_count,
    })
}

fn read_table_desc(buf: &[u8], off: usize) -> Result<TableDesc, String> {
    Ok(TableDesc {
        offset: read_u32_le(buf, off)? as usize,
        num_entries: read_u32_le(buf, off + 4)? as usize,
        entry_size: read_u32_le(buf, off + 8)? as usize,
    })
}

fn parse_slot(buf: &[u8], slot_off: usize) -> Result<Vec<DynamicPartition>, String> {
    let magic = read_u32_le(buf, slot_off)?;
    if magic != LP_METADATA_HEADER_MAGIC {
        return Err(format!(
            "invalid LpMetadataHeader magic at {slot_off:#x}: {magic:#010x}"
        ));
    }
    let major = read_u16_le(buf, slot_off + 4)?;
    if major != LP_METADATA_MAJOR_VERSION {
        return Err(format!("unsupported LpMetadata major version {major}"));
    }

    let header_size = read_u32_le(buf, slot_off + 8)? as usize;
    let tables_size = read_u32_le(buf, slot_off + 44)? as usize;
    let partitions_desc = read_table_desc(buf, slot_off + 80)?;
    let extents_desc = read_table_desc(buf, slot_off + 92)?;

    if partitions_desc.num_entries > 0 && partitions_desc.entry_size < PARTITION_ENTRY_MIN_SIZE {
        return Err(format!(
            "LpMetadataPartition entry_size {} < {PARTITION_ENTRY_MIN_SIZE}",
            partitions_desc.entry_size
        ));
    }
    if extents_desc.num_entries > 0 && extents_desc.entry_size < EXTENT_ENTRY_MIN_SIZE {
        return Err(format!(
            "LpMetadataExtent entry_size {} < {EXTENT_ENTRY_MIN_SIZE}",
            extents_desc.entry_size
        ));
    }

    let tables_base = slot_off
        .checked_add(header_size)
        .ok_or("tables_base overflow")?;
    let tables_end = tables_base
        .checked_add(tables_size)
        .ok_or("tables_end overflow")?;
    let tables = buf
        .get(tables_base..tables_end)
        .ok_or("LpMetadata tables exceed buffer length")?;

    let mut parsed_extents = Vec::with_capacity(extents_desc.num_entries);
    for idx in 0..extents_desc.num_entries {
        let e_off = extents_desc
            .offset
            .checked_add(
                idx.checked_mul(extents_desc.entry_size)
                    .ok_or("extent offset mul overflow")?,
            )
            .ok_or("extent offset add overflow")?;
        let num_sectors = read_u64_le(tables, e_off)?;
        let target_type = read_u32_le(tables, e_off + 8)?;
        let target_data = read_u64_le(tables, e_off + 12)?;
        let target_source = read_u32_le(tables, e_off + 20)?;
        parsed_extents.push((num_sectors, target_type, target_data, target_source));
    }

    let mut out = Vec::with_capacity(partitions_desc.num_entries);
    for idx in 0..partitions_desc.num_entries {
        let p_off = partitions_desc
            .offset
            .checked_add(
                idx.checked_mul(partitions_desc.entry_size)
                    .ok_or("partition offset mul overflow")?,
            )
            .ok_or("partition offset add overflow")?;
        let name_end = p_off.checked_add(36).ok_or("name_end overflow")?;
        let raw_name = tables
            .get(p_off..name_end)
            .ok_or("partition name out of bounds")?;
        let nul_pos = raw_name
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(raw_name.len());
        let name = String::from_utf8_lossy(&raw_name[..nul_pos]).into_owned();
        let attributes = read_u32_le(tables, p_off + 36)?;
        let first_extent = read_u32_le(tables, p_off + 40)? as usize;
        let num_extents = read_u32_le(tables, p_off + 44)? as usize;

        let last_extent = first_extent
            .checked_add(num_extents)
            .ok_or("extent range overflow")?;
        if last_extent > parsed_extents.len() {
            return Err(format!(
                "partition '{name}' extent range {first_extent}..{last_extent} exceeds {}",
                parsed_extents.len()
            ));
        }

        let mut logical_sector = 0u64;
        let mut extents = Vec::with_capacity(num_extents);
        for &(num_sectors, target_type, target_data, target_source) in
            &parsed_extents[first_extent..last_extent]
        {
            if target_type != LP_TARGET_TYPE_LINEAR {
                return Err(format!(
                    "partition '{name}' contains non-linear extent type {target_type}"
                ));
            }
            if num_sectors > 0 {
                extents.push(LinearExtent {
                    logical_sector,
                    num_sectors,
                    physical_sector: target_data,
                    target_source,
                });
                logical_sector = logical_sector
                    .checked_add(num_sectors)
                    .ok_or("logical_sector overflow")?;
            }
        }

        out.push(DynamicPartition {
            name,
            attributes,
            extents,
        });
    }

    Ok(out)
}

/// Parse all dynamic partitions from the leading metadata region of an Android `super` partition.
pub fn parse_super_partitions(prefix: &[u8]) -> Result<Vec<DynamicPartition>, String> {
    let primary_geom_off = LP_PARTITION_RESERVED_BYTES;
    let backup_geom_off = LP_PARTITION_RESERVED_BYTES + LP_METADATA_GEOMETRY_SIZE;
    let geom = parse_geometry_at(prefix, primary_geom_off)
        .or_else(|_| parse_geometry_at(prefix, backup_geom_off))?;

    let slots_base = LP_PARTITION_RESERVED_BYTES + 2 * LP_METADATA_GEOMETRY_SIZE;
    let mut last_err = String::from("no metadata slots examined");
    for slot in 0..geom.metadata_slot_count {
        let Some(slot_off) = slot
            .checked_mul(geom.metadata_max_size)
            .and_then(|o| slots_base.checked_add(o))
        else {
            break;
        };
        if slot_off >= prefix.len() {
            break;
        }
        match parse_slot(prefix, slot_off) {
            Ok(parts) => return Ok(parts),
            Err(e) => last_err = e,
        }
    }
    Err(format!("failed to parse LpMetadata slots: {last_err}"))
}

/// Open `super` block device read-only and resolve the first matching dynamic partition.
pub fn find_super_partition(dev: &Path, candidates: &[&str]) -> Result<DynamicPartition, String> {
    let mut f = File::open(dev).map_err(|e| format!("open {}: {e}", dev.display()))?;
    let mut buf = vec![0u8; SUPER_METADATA_READ_BYTES];
    let mut total = 0usize;
    while total < buf.len() {
        match f.read(&mut buf[total..]) {
            Ok(0) => break,
            Ok(n) => total += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(format!("read {}: {e}", dev.display())),
        }
    }
    buf.truncate(total);

    let parts = parse_super_partitions(&buf)?;
    for &want in candidates {
        if let Some(p) = parts
            .iter()
            .find(|p| p.name == want && !p.extents.is_empty())
        {
            return Ok(p.clone());
        }
    }

    let available: Vec<&str> = parts.iter().map(|p| p.name.as_str()).collect();
    Err(format!(
        "none of {:?} found in {} (available: {:?})",
        candidates,
        dev.display(),
        available
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_u16_le(buf: &mut [u8], off: usize, v: u16) {
        buf[off..off + 2].copy_from_slice(&v.to_le_bytes());
    }

    fn write_u32_le(buf: &mut [u8], off: usize, v: u32) {
        buf[off..off + 4].copy_from_slice(&v.to_le_bytes());
    }

    fn write_u64_le(buf: &mut [u8], off: usize, v: u64) {
        buf[off..off + 8].copy_from_slice(&v.to_le_bytes());
    }

    fn build_synthetic_super(corrupt_primary_geom: bool) -> Vec<u8> {
        let mut img = vec![0u8; 65536];
        let geom_off = if corrupt_primary_geom {
            write_u32_le(&mut img, 0x1000, 0xdead_beef);
            0x2000
        } else {
            0x1000
        };
        write_u32_le(&mut img, geom_off, LP_METADATA_GEOMETRY_MAGIC);
        write_u32_le(&mut img, geom_off + 4, 52);
        write_u32_le(&mut img, geom_off + 40, 0x10000); // metadata_max_size
        write_u32_le(&mut img, geom_off + 44, 3); // slot_count
        write_u32_le(&mut img, geom_off + 48, 4096);

        let hdr = 0x3000;
        write_u32_le(&mut img, hdr, LP_METADATA_HEADER_MAGIC);
        write_u16_le(&mut img, hdr + 4, 10);
        write_u16_le(&mut img, hdr + 6, 2);
        write_u32_le(&mut img, hdr + 8, 0x100); // header_size
        write_u32_le(&mut img, hdr + 44, 0x100); // tables_size

        // 2 partitions (52 B each at +0), 3 extents (24 B each at +104)
        write_u32_le(&mut img, hdr + 80, 0);
        write_u32_le(&mut img, hdr + 84, 2);
        write_u32_le(&mut img, hdr + 88, 52);

        write_u32_le(&mut img, hdr + 92, 104);
        write_u32_le(&mut img, hdr + 96, 3);
        write_u32_le(&mut img, hdr + 100, 24);

        let tbl = hdr + 0x100;
        // Partition 0: system_a (1 extent @ 0)
        img[tbl..tbl + 8].copy_from_slice(b"system_a");
        write_u32_le(&mut img, tbl + 36, 1);
        write_u32_le(&mut img, tbl + 40, 0);
        write_u32_le(&mut img, tbl + 44, 1);

        // Partition 1: vendor_a (2 extents @ 1..3, starting at Xiaomi MIX 4 sector 0x38c000)
        let p1 = tbl + 52;
        img[p1..p1 + 8].copy_from_slice(b"vendor_a");
        write_u32_le(&mut img, p1 + 36, 1);
        write_u32_le(&mut img, p1 + 40, 1);
        write_u32_le(&mut img, p1 + 44, 2);

        // Extent 0 (system_a)
        let e0 = tbl + 104;
        write_u64_le(&mut img, e0, 0x20fad8);
        write_u32_le(&mut img, e0 + 8, LP_TARGET_TYPE_LINEAR);
        write_u64_le(&mut img, e0 + 12, 0x1800);

        // Extent 1 (vendor_a part 1: 0x400000 sectors @ 0x38c000)
        let e1 = e0 + 24;
        write_u64_le(&mut img, e1, 0x40_0000);
        write_u32_le(&mut img, e1 + 8, LP_TARGET_TYPE_LINEAR);
        write_u64_le(&mut img, e1 + 12, 0x38_c000);

        // Extent 2 (vendor_a part 2: 0x82e0 sectors @ 0x79_0000)
        let e2 = e1 + 24;
        write_u64_le(&mut img, e2, 0x82e0);
        write_u32_le(&mut img, e2 + 8, LP_TARGET_TYPE_LINEAR);
        write_u64_le(&mut img, e2 + 12, 0x79_0000);

        img
    }

    #[test]
    fn parses_odin_vendor_a_extents_and_backup_geometry() {
        let img = build_synthetic_super(true);
        let parts = parse_super_partitions(&img).expect("parse synthetic super");
        assert_eq!(parts.len(), 2);
        assert_eq!(parts[0].name, "system_a");
        assert_eq!(parts[1].name, "vendor_a");
        assert_eq!(parts[1].total_sectors(), 0x40_82e0);
        assert_eq!(parts[1].total_bytes(), 2_164_637_696);
        assert_eq!(parts[1].extents[0].byte_offset(), 1_904_214_016);
        assert_eq!(
            parts[1].dm_table("/dev/sda28"),
            "0 4194304 linear /dev/sda28 3719168\n4194304 33504 linear /dev/sda28 7929856"
        );
    }

    #[test]
    fn rejects_corrupt_metadata() {
        let bad = vec![0u8; 16384];
        assert!(parse_super_partitions(&bad).is_err());
    }
}
