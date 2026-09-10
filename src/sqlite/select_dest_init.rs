//! Initializes SQLite's SELECT-result destination descriptor —
//! `sqlite3SelectDestInit` from select.c.
//!
//! Original: `FUN_08383ca8` at load address `0x08383ca8`, 28 bytes
//! (`0x08383ca8..0x08383cc4`, bounded by the next `push {r4-r6, lr}`) and
//! 10 `bl` call sites. A raw-binary scan of every ARM B/BL instruction finds
//! all 10 calls unconditional; no caller uses a predicated call.
//!
//! The leaf function stores the destination kind and parameter, then clears
//! the affinity byte and the two destination-register bookkeeping words.
//! The two padding bytes between the byte fields and `i_sd_parm` are left
//! unchanged, exactly as the ARM `strb`/`str` sequence does. There are no
//! deliberate deviations from the firmware behavior.

/// SQLite's 16-byte `SelectDest` layout on the ARM target.
///
/// `#[repr(C)]` retains the target's 4-byte word spacing on 64-bit host
/// tests; its integer parameter is a firmware word, never a host pointer.
#[repr(C)]
pub struct SelectDest {
    pub e_dest: u8,
    pub aff_sdst: u8,
    _padding: [u8; 2],
    pub i_sd_parm: i32,
    pub i_sdst: i32,
    pub n_sdst: i32,
}

/// `select_dest_init` — original: `FUN_08383ca8` @ `0x08383ca8` (28 bytes;
/// 10 unconditional `bl` call sites).
///
/// Implements `sqlite3SelectDestInit`: set `e_dest` and `i_sd_parm`, and
/// clear `aff_sdst`, `i_sdst`, and `n_sdst`. Like the original leaf routine,
/// `destination` is dereferenced unconditionally.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn select_dest_init(
    destination: *mut SelectDest,
    destination_kind: u8,
    parameter: i32,
) {
    let destination = &mut *destination;
    destination.e_dest = destination_kind;
    destination.i_sd_parm = parameter;
    destination.aff_sdst = 0;
    destination.i_sdst = 0;
    destination.n_sdst = 0;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[repr(align(4))]
    struct DestinationBytes([u8; 0x10 + 8]);

    impl DestinationBytes {
        fn dirty() -> Self {
            Self([0xa5; 0x10 + 8])
        }

        fn destination(&mut self) -> *mut SelectDest {
            self.0[4..].as_mut_ptr().cast()
        }

        fn word(&self, offset: usize) -> i32 {
            i32::from_le_bytes(self.0[4 + offset..4 + offset + 4].try_into().unwrap())
        }
    }

    #[test]
    fn initializes_all_destination_fields_without_clobbering_padding() {
        let mut destination = DestinationBytes::dirty();
        unsafe { select_dest_init(destination.destination(), 10, -1) };

        assert_eq!(destination.0[4], 10, "eDest");
        assert_eq!(destination.0[5], 0, "affSdst");
        assert_eq!(&destination.0[6..8], &[0xa5; 2], "SelectDest padding");
        assert_eq!(destination.word(4), -1, "iSDParm");
        assert_eq!(destination.word(8), 0, "iSdst");
        assert_eq!(destination.word(12), 0, "nSdst");
        assert!(destination.0[..4].iter().chain(destination.0[20..].iter()).all(|&byte| byte == 0xa5));
    }

    #[test]
    fn replaces_stale_values_for_a_second_destination_kind() {
        let mut destination = DestinationBytes::dirty();
        unsafe { select_dest_init(destination.destination(), 4, 0x1234_5678) };

        assert_eq!(destination.0[4], 4);
        assert_eq!(destination.word(4), 0x1234_5678);
        assert_eq!(destination.0[5], 0);
        assert_eq!(destination.word(8), 0);
        assert_eq!(destination.word(12), 0);
    }
}
