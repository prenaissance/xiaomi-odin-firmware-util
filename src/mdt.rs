//! Pure-Rust Qualcomm Peripheral Image Loader (`.mdt` + `.b00`..`.bNN` -> `.mbn`) squasher.
//!
//! Converts split Qualcomm ELF32 firmware images stored on Android `modem_a` / `vendor_a`
//! partitions (`adsp.mdt` + `adsp.b00`..`adsp.b25`, `cdsp.mdt`, `slpi.mdt`, `modem.mdt`)
//! into single-file `.mbn` images expected by mainline Linux Device Trees
//! (`drivers/soc/qcom/mdt_loader.c`).

use std::fs;
use std::path::Path;

const ELF_MAGIC: &[u8; 4] = b"\x7fELF";
const ELFCLASS32: u8 = 1;
const ELFDATA2LSB: u8 = 1;
const ELF32_HDR_SIZE: usize = 52;
const ELF32_PHDR_SIZE: usize = 32;

#[derive(Debug, Clone, Copy)]
struct Elf32Phdr {
    p_offset: usize,
    p_filesz: usize,
}

fn read_u16_le(buf: &[u8], off: usize) -> Result<u16, String> {
    let bytes: [u8; 2] = buf
        .get(off..off + 2)
        .ok_or_else(|| format!("EOF reading u16 at {off:#x}"))?
        .try_into()
        .map_err(|_| "u16 slice error".to_owned())?;
    Ok(u16::from_le_bytes(bytes))
}

fn read_u32_le(buf: &[u8], off: usize) -> Result<u32, String> {
    let bytes: [u8; 4] = buf
        .get(off..off + 4)
        .ok_or_else(|| format!("EOF reading u32 at {off:#x}"))?
        .try_into()
        .map_err(|_| "u32 slice error".to_owned())?;
    Ok(u32::from_le_bytes(bytes))
}

fn parse_elf32_phdrs(mdt: &[u8]) -> Result<Vec<Elf32Phdr>, String> {
    if mdt.len() < ELF32_HDR_SIZE {
        return Err(format!("MDT too small ({} B < {ELF32_HDR_SIZE} B)", mdt.len()));
    }
    if &mdt[0..4] != ELF_MAGIC {
        return Err("invalid ELF magic in MDT header".into());
    }
    if mdt[4] != ELFCLASS32 || mdt[5] != ELFDATA2LSB {
        return Err(format!(
            "unsupported ELF class/endian ({}, {}); expected 32-bit LE",
            mdt[4], mdt[5]
        ));
    }

    let e_phoff = read_u32_le(mdt, 28)? as usize;
    let e_phentsize = read_u16_le(mdt, 42)? as usize;
    let e_phnum = read_u16_le(mdt, 44)? as usize;
    if e_phentsize != ELF32_PHDR_SIZE {
        return Err(format!(
            "unexpected ELF32 e_phentsize {e_phentsize} (expected {ELF32_PHDR_SIZE})"
        ));
    }
    if e_phnum < 2 {
        return Err(format!("MDT has too few program headers ({e_phnum})"));
    }

    let ph_end = e_phoff
        .checked_add(
            e_phnum
                .checked_mul(ELF32_PHDR_SIZE)
                .ok_or("phdr table size overflow")?,
        )
        .ok_or("phdr table end overflow")?;
    if ph_end > mdt.len() {
        return Err(format!(
            "ELF program header table ({ph_end} B) exceeds MDT size ({} B)",
            mdt.len()
        ));
    }

    let mut phdrs = Vec::with_capacity(e_phnum);
    for idx in 0..e_phnum {
        let base = e_phoff + idx * ELF32_PHDR_SIZE;
        let p_offset = read_u32_le(mdt, base + 4)? as usize;
        let p_filesz = read_u32_le(mdt, base + 16)? as usize;
        phdrs.push(Elf32Phdr { p_offset, p_filesz });
    }
    Ok(phdrs)
}

/// Squash an in-memory `.mdt` header and per-segment slices into a single `.mbn` byte vector.
pub fn squash_segments<F>(mdt: &[u8], mut read_segment: F) -> Result<Vec<u8>, String>
where
    F: FnMut(usize, usize) -> Result<Vec<u8>, String>,
{
    let phdrs = parse_elf32_phdrs(mdt)?;
    let mut total_len = phdrs[0]
        .p_offset
        .checked_add(phdrs[0].p_filesz)
        .ok_or("phdr[0] end overflow")?;

    for (idx, ph) in phdrs.iter().enumerate() {
        if ph.p_filesz == 0 {
            continue;
        }
        let end = ph
            .p_offset
            .checked_add(ph.p_filesz)
            .ok_or_else(|| format!("segment {idx} offset+filesz overflow"))?;
        if end > total_len {
            total_len = end;
        }
    }

    let mut out = vec![0u8; total_len];
    for (idx, ph) in phdrs.iter().enumerate() {
        if ph.p_filesz == 0 {
            continue;
        }
        let seg = read_segment(idx, ph.p_filesz)?;
        if seg.len() != ph.p_filesz {
            return Err(format!(
                "segment b{idx:02} size mismatch: got {} B, expected {} B",
                seg.len(),
                ph.p_filesz
            ));
        }
        out[ph.p_offset..ph.p_offset + ph.p_filesz].copy_from_slice(&seg);
    }

    Ok(out)
}

/// Squash `<dir>/<stem>.mdt` + `<dir>/<stem>.b00`..`bNN` from disk into a single `.mbn` image.
pub fn squash_mdt_from_dir(dir: &Path, stem: &str) -> Result<Vec<u8>, String> {
    let mdt_path = dir.join(format!("{stem}.mdt"));
    let mdt = fs::read(&mdt_path).map_err(|e| format!("read {}: {e}", mdt_path.display()))?;

    squash_segments(&mdt, |idx, expected_len| {
        let seg_path = dir.join(format!("{stem}.b{idx:02}"));
        match fs::read(&seg_path) {
            Ok(bytes) => Ok(bytes),
            Err(_) if idx == 0 && mdt.len() >= expected_len => Ok(mdt[..expected_len].to_vec()),
            Err(e) => Err(format!("read {}: {e}", seg_path.display())),
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn squashes_real_xiaomi_odin_a660_zap_mdt_bit_identically_to_elf() {
        let dump_dir = Path::new("/home/prenaissance/xiaomi-odin/backups/device_dump/adreno660_fw");
        if !dump_dir.join("a660_zap.mdt").is_file() {
            return;
        }
        let squashed = squash_mdt_from_dir(dump_dir, "a660_zap").expect("squash a660_zap.mdt");
        let factory_elf = fs::read(dump_dir.join("a660_zap.elf")).expect("read a660_zap.elf");
        assert_eq!(squashed, factory_elf);
    }

    #[test]
    fn rejects_invalid_elf_header() {
        assert!(squash_segments(b"not-an-elf-file-at-all", |_, _| Ok(Vec::new())).is_err());
    }
}
