//! Encoder, parser, and verifier for Qualcomm `QCA-ATH11K-BOARD` (`board-2.bin`)
//! binary IE containers, matching `drivers/net/wireless/ath/ath11k/core.c`.

use std::fmt;

pub const ATH11K_BOARD_MAGIC: &[u8] = b"QCA-ATH11K-BOARD\0";
pub const ATH11K_BOARD_MAGIC_PADDED_LEN: usize = 20;

pub const ATH11K_BD_IE_BOARD: u32 = 0;
pub const ATH11K_BD_IE_REGDB: u32 = 1;

pub const ATH11K_BD_IE_BOARD_NAME: u32 = 0;
pub const ATH11K_BD_IE_BOARD_DATA: u32 = 1;

const IE_HDR_LEN: usize = 8;

#[inline]
pub const fn align4(len: usize) -> usize {
    (len + 3) & !3
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoardEntry {
    pub names: Vec<String>,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Board2Bundle {
    pub boards: Vec<BoardEntry>,
    pub regdbs: Vec<BoardEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Bd2Error {
    TooShort(usize),
    InvalidMagic,
    TruncatedIe { ie_id: u32, ie_len: usize, rem: usize },
    InvalidUtf8Name,
    EmptyEntry,
}

impl fmt::Display for Bd2Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooShort(n) => write!(f, "board-2.bin too short ({n} bytes)"),
            Self::InvalidMagic => write!(f, "invalid QCA-ATH11K-BOARD magic"),
            Self::TruncatedIe { ie_id, ie_len, rem } => {
                write!(f, "truncated IE id={ie_id} len={ie_len} remaining={rem}")
            }
            Self::InvalidUtf8Name => write!(f, "non-UTF8 board name in IE"),
            Self::EmptyEntry => write!(f, "board entry must have >=1 name and non-empty data"),
        }
    }
}

fn push_ie(out: &mut Vec<u8>, id: u32, payload: &[u8]) {
    out.extend_from_slice(&id.to_le_bytes());
    out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    out.extend_from_slice(payload);
    let pad = align4(payload.len()) - payload.len();
    for _ in 0..pad {
        out.push(0);
    }
}

fn encode_entry_list(out: &mut Vec<u8>, outer_ie_id: u32, entries: &[BoardEntry]) -> Result<(), Bd2Error> {
    for entry in entries {
        if entry.names.is_empty() || entry.data.is_empty() {
            return Err(Bd2Error::EmptyEntry);
        }
        let mut inner = Vec::with_capacity(entry.data.len() + entry.names.len() * 96);
        for name in &entry.names {
            if name.is_empty() {
                return Err(Bd2Error::EmptyEntry);
            }
            push_ie(&mut inner, ATH11K_BD_IE_BOARD_NAME, name.as_bytes());
        }
        push_ie(&mut inner, ATH11K_BD_IE_BOARD_DATA, &entry.data);
        push_ie(out, outer_ie_id, &inner);
    }
    Ok(())
}

impl Board2Bundle {
    pub fn encode(&self) -> Result<Vec<u8>, Bd2Error> {
        let mut out = Vec::with_capacity(128 * 1024);
        out.extend_from_slice(ATH11K_BOARD_MAGIC);
        while out.len() < ATH11K_BOARD_MAGIC_PADDED_LEN {
            out.push(0);
        }
        encode_entry_list(&mut out, ATH11K_BD_IE_BOARD, &self.boards)?;
        encode_entry_list(&mut out, ATH11K_BD_IE_REGDB, &self.regdbs)?;
        Ok(out)
    }

    pub fn parse(raw: &[u8]) -> Result<Self, Bd2Error> {
        if raw.len() < ATH11K_BOARD_MAGIC_PADDED_LEN {
            return Err(Bd2Error::TooShort(raw.len()));
        }
        if &raw[..ATH11K_BOARD_MAGIC.len()] != ATH11K_BOARD_MAGIC {
            return Err(Bd2Error::InvalidMagic);
        }

        let mut bundle = Self::default();
        let mut cur = &raw[ATH11K_BOARD_MAGIC_PADDED_LEN..];

        // Matches ath11k_core_fetch_board_data_api_n(): while (len > sizeof(ath11k_fw_ie))
        while cur.len() > IE_HDR_LEN {
            let ie_id = u32::from_le_bytes([cur[0], cur[1], cur[2], cur[3]]);
            let ie_len = u32::from_le_bytes([cur[4], cur[5], cur[6], cur[7]]) as usize;
            cur = &cur[IE_HDR_LEN..];
            let padded = align4(ie_len);
            if cur.len() < padded {
                return Err(Bd2Error::TruncatedIe {
                    ie_id,
                    ie_len,
                    rem: cur.len(),
                });
            }
            let payload = &cur[..ie_len];
            cur = &cur[padded..];

            match ie_id {
                ATH11K_BD_IE_BOARD => parse_inner_entries(payload, ie_id, &mut bundle.boards)?,
                ATH11K_BD_IE_REGDB => parse_inner_entries(payload, ie_id, &mut bundle.regdbs)?,
                _ => {}
            }
        }

        Ok(bundle)
    }

    /// Exact port of `ath11k_core_fetch_board_data_api_n()` so we can self-verify
    /// encoded `board-2.bin` blobs before writing them to `/lib/firmware`.
    pub fn kernel_lookup<'a>(raw: &'a [u8], outer_ie_match: u32, boardname: &str) -> Result<Option<&'a [u8]>, Bd2Error> {
        if raw.len() < ATH11K_BOARD_MAGIC_PADDED_LEN {
            return Err(Bd2Error::TooShort(raw.len()));
        }
        if &raw[..ATH11K_BOARD_MAGIC.len()] != ATH11K_BOARD_MAGIC {
            return Err(Bd2Error::InvalidMagic);
        }

        let mut cur = &raw[ATH11K_BOARD_MAGIC_PADDED_LEN..];
        while cur.len() > IE_HDR_LEN {
            let ie_id = u32::from_le_bytes([cur[0], cur[1], cur[2], cur[3]]);
            let ie_len = u32::from_le_bytes([cur[4], cur[5], cur[6], cur[7]]) as usize;
            cur = &cur[IE_HDR_LEN..];
            let padded = align4(ie_len);
            if cur.len() < padded {
                return Err(Bd2Error::TruncatedIe {
                    ie_id,
                    ie_len,
                    rem: cur.len(),
                });
            }
            if ie_id == outer_ie_match
                && let Some(found) = kernel_parse_inner(&cur[..ie_len], ie_id, boardname)? {
                    return Ok(Some(found));
                }
            cur = &cur[padded..];
        }
        Ok(None)
    }
}

fn parse_inner_entries(mut buf: &[u8], outer_id: u32, out: &mut Vec<BoardEntry>) -> Result<(), Bd2Error> {
    let mut pending_names = Vec::new();
    while buf.len() > IE_HDR_LEN {
        let id = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
        let len = u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]) as usize;
        buf = &buf[IE_HDR_LEN..];
        let padded = align4(len);
        if buf.len() < padded {
            return Err(Bd2Error::TruncatedIe {
                ie_id: outer_id,
                ie_len: len,
                rem: buf.len(),
            });
        }
        let data = &buf[..len];
        buf = &buf[padded..];

        if id == ATH11K_BD_IE_BOARD_NAME {
            let s = std::str::from_utf8(data).map_err(|_| Bd2Error::InvalidUtf8Name)?;
            pending_names.push(s.to_owned());
        } else if id == ATH11K_BD_IE_BOARD_DATA && !pending_names.is_empty() {
            out.push(BoardEntry {
                names: std::mem::take(&mut pending_names),
                data: data.to_vec(),
            });
        }
    }
    Ok(())
}

fn kernel_parse_inner<'a>(mut buf: &'a [u8], outer_id: u32, boardname: &str) -> Result<Option<&'a [u8]>, Bd2Error> {
    let mut name_match_found = false;
    while buf.len() > IE_HDR_LEN {
        let id = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
        let len = u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]) as usize;
        buf = &buf[IE_HDR_LEN..];
        let padded = align4(len);
        if buf.len() < padded {
            return Err(Bd2Error::TruncatedIe {
                ie_id: outer_id,
                ie_len: len,
                rem: buf.len(),
            });
        }
        let data = &buf[..len];
        buf = &buf[padded..];

        if id == ATH11K_BD_IE_BOARD_NAME {
            if data == boardname.as_bytes() {
                name_match_found = true;
            }
        } else if id == ATH11K_BD_IE_BOARD_DATA && name_match_found {
            return Ok(Some(data));
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    #[test]
    fn roundtrip_and_kernel_lookup_with_unaligned_lengths() {
        let bdf_k8 = vec![0x7f, b'E', b'L', b'F', 1, 2, 3, 4, 5]; // 9 bytes (unaligned)
        let bdf_alt = vec![0xaa, 0xbb, 0xcc, 0xdd, 0xee]; // 5 bytes (unaligned)
        let regdb = vec![0xDE, 0xAD, 0xBE]; // 3 bytes (unaligned)

        let bundle = Board2Bundle {
            boards: vec![
                BoardEntry {
                    names: vec![
                        "bus=pci,vendor=17cb,device=1103,subsystem-vendor=17cb,subsystem-device=0108,qmi-chip-id=2,qmi-board-id=255,variant=Xiaomi_MIX4".into(),
                        "bus=pci,qmi-chip-id=2".into(),
                    ],
                    data: bdf_k8.clone(),
                },
                BoardEntry {
                    names: vec!["bus=pci,qmi-chip-id=18".into()],
                    data: bdf_alt.clone(),
                },
            ],
            regdbs: vec![BoardEntry {
                names: vec!["bus=pci".into()],
                data: regdb.clone(),
            }],
        };

        let raw = bundle.encode().expect("encode should succeed");
        assert_eq!(raw.len() % 4, 0);

        let parsed = Board2Bundle::parse(&raw).expect("parse should succeed");
        assert_eq!(parsed, bundle);

        let hit1 = Board2Bundle::kernel_lookup(
            &raw,
            ATH11K_BD_IE_BOARD,
            "bus=pci,vendor=17cb,device=1103,subsystem-vendor=17cb,subsystem-device=0108,qmi-chip-id=2,qmi-board-id=255,variant=Xiaomi_MIX4",
        )
        .unwrap();
        assert_eq!(hit1, Some(bdf_k8.as_slice()));

        let hit2 = Board2Bundle::kernel_lookup(&raw, ATH11K_BD_IE_BOARD, "bus=pci,qmi-chip-id=2").unwrap();
        assert_eq!(hit2, Some(bdf_k8.as_slice()));

        let hit3 = Board2Bundle::kernel_lookup(&raw, ATH11K_BD_IE_BOARD, "bus=pci,qmi-chip-id=18").unwrap();
        assert_eq!(hit3, Some(bdf_alt.as_slice()));

        let miss = Board2Bundle::kernel_lookup(&raw, ATH11K_BD_IE_BOARD, "bus=pci,qmi-chip-id=99").unwrap();
        assert_eq!(miss, None);

        let reg_hit = Board2Bundle::kernel_lookup(&raw, ATH11K_BD_IE_REGDB, "bus=pci").unwrap();
        assert_eq!(reg_hit, Some(regdb.as_slice()));
    }

    #[test]
    fn parses_upstream_linux_firmware_wcn6855_board2_if_present() {
        let zst_path = "/usr/lib/firmware/ath11k/WCN6855/hw2.0/board-2.bin.zst";
        if !std::path::Path::new(zst_path).exists() {
            return;
        }
        let output = Command::new("zstd")
            .args(["-dc", zst_path])
            .output()
            .expect("zstd -dc failed");
        assert!(output.status.success());

        let upstream = Board2Bundle::parse(&output.stdout).expect("upstream board-2.bin must parse cleanly");
        assert!(!upstream.boards.is_empty(), "upstream WCN6855 board-2.bin should contain board entries");

        // Verify prepending Xiaomi_MIX4 entry takes priority while preserving upstream entries.
        let mut merged = Board2Bundle {
            boards: vec![BoardEntry {
                names: vec![
                    "bus=pci,vendor=17cb,device=1103,subsystem-vendor=17cb,subsystem-device=0108,qmi-chip-id=2,qmi-board-id=255,variant=Xiaomi_MIX4".into(),
                ],
                data: b"ODIN_K8_BDF".to_vec(),
            }],
            regdbs: upstream.regdbs.clone(),
        };
        merged.boards.extend(upstream.boards.clone());
        let encoded = merged.encode().expect("merged encode failed");
        let odin_hit = Board2Bundle::kernel_lookup(
            &encoded,
            ATH11K_BD_IE_BOARD,
            "bus=pci,vendor=17cb,device=1103,subsystem-vendor=17cb,subsystem-device=0108,qmi-chip-id=2,qmi-board-id=255,variant=Xiaomi_MIX4",
        )
        .unwrap();
        assert_eq!(odin_hit, Some(b"ODIN_K8_BDF".as_slice()));
    }
}
