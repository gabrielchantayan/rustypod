//! Span of one entry in a downward-growing u16 offset table.

/// offset_table_entry_span — original: `FUN_08054a90` @ 0x08054a90
/// (40 bytes, leaf, 5 verified incoming plain BL call sites at 0x0804b748,
/// 0x080539b4, 0x08064d88, 0x08064e68, 0x0806b7b8; no predicated BLs).
///
/// A record header carries at +0x1c a u16 offset from `base` to the END of a
/// u16 offset table whose entries grow downward (entry `i` lives at
/// `end - 2*(i+1)`). The function returns
/// `entry[index] - entry[index+1]`... precisely
/// `ldrh(end - 2*index - 4) - ldrh(end - 2*index - 2)` truncated to 16 bits
/// (the original zero-extends with `lsl #16`/`lsr #16`). Callers use the
/// value as the byte span of record `index` (one caller shifts it left by 3
/// for a bit count).
///
/// Original listing:
/// ```text
///   ldrh r0,[r0,#0x1c]      ; table offset from header
///   add  r0,r0,r1           ; + base
///   sub  r0,r0,r2, lsl #0x1 ; - 2*index
///   sub  r0,r0,#0x2         ; - 2
///   ldrh r1,[r0,#-0x2]      ; entry[index]
///   ldrh r0,[r0,#0x0]       ; entry[index+1]
///   sub  r0,r1,r0
///   mov  r0,r0, lsl #0x10
///   mov  r0,r0, lsr #0x10   ; zero-extend to u16
///   bx   lr
/// ```
///
/// # Safety
/// `header` must be valid for an aligned u16 read at +0x1c. The computed
/// table address `base + off - 2*index - 2` must be valid for two aligned
/// u16 reads at -2 and +0. All reads are naturally aligned halfword reads,
/// matching the original.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn offset_table_entry_span(
    header: *const u8,
    base: *const u8,
    index: u32,
) -> u16 {
    let table_end = base.add((header.add(0x1c) as *const u16).read() as usize);
    let entry = table_end.sub(2 * index as usize + 2) as *const u16;
    entry.sub(1).read().wrapping_sub(entry.read())
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::offset_table_entry_span;
    use std::vec::Vec;

    /// Build a header (u16 table offset at +0x1c) plus a downward-growing
    /// offset table; returns (header_buf, base_buf) with the table at the
    /// end of `base_buf`.
    fn fixture(table: &[u16]) -> (Vec<u8>, Vec<u16>) {
        let mut header = Vec::new();
        header.resize(0x1c, 0u8);
        // Header offset is the offset from base to the END of the table.
        header.extend_from_slice(&(2 * table.len() as u16).to_ne_bytes());
        // Table at base start; entries grow downward from its end, so the
        // logical entry[i] is at words[len-1-i].
        let mut words = table.to_vec();
        words.reverse();
        (header, words)
    }

    /// Independent reference: span of entry `index` in a downward-growing
    /// table of ascending offsets is offsets[index+1] - offsets[index].
    fn reference_span(table: &[u16], index: usize) -> u16 {
        table[index + 1].wrapping_sub(table[index])
    }

    #[test]
    fn returns_span_of_each_entry() {
        let table = [0x0010u16, 0x0024, 0x0100, 0x0108];
        let (header, base) = fixture(&table);
        for index in 0..table.len() - 1 {
            let got = unsafe {
                offset_table_entry_span(header.as_ptr(), base.as_ptr() as *const u8, index as u32)
            };
            assert_eq!(got, reference_span(&table, index), "index {index}");
        }
    }

    #[test]
    fn nonzero_table_offset_in_header() {
        // Header offset selects the table end relative to base.
        let mut header = Vec::new();
        header.resize(0x1c, 0u8);
        header.extend_from_slice(&4u16.to_ne_bytes()); // table ends at base+4
        // One table word at base[0..2]; pad word at base[2..4].
        // entry[0] is at end-2 = base+0... need two words: place table of
        // two entries ending at base+4: words at base[0] (entry[1]) and
        // base[2] (entry[0]).
        let base: [u16; 2] = [0x0050, 0x0030];
        let got = unsafe {
            offset_table_entry_span(header.as_ptr(), base.as_ptr() as *const u8, 0)
        };
        assert_eq!(got, 0x0050u16.wrapping_sub(0x0030));
    }

    #[test]
    fn result_is_truncated_to_u16_on_decreasing_table() {
        // entry[index] < entry[index+1]: the original's sub wraps to 32 bits
        // then the lsl/lsr pair truncates to 16 bits.
        let table = [0x0005u16, 0x8001];
        let (header, base) = fixture(&table);
        let got = unsafe {
            offset_table_entry_span(header.as_ptr(), base.as_ptr() as *const u8, 0)
        };
        assert_eq!(got, 0x8001u16.wrapping_sub(0x0005));
    }
}
