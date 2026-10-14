/// `filebuf_is_open` — retailOS `FUN_083d6f20` @ load address `0x083d6f20`.
///
/// **16 bytes**, `0x083d6f20..0x083d6f2c`, bounded by the independently
/// linked duplicate predicate at `0x083d6f30`. Whole-image ARM B/BL decoding
/// finds three direct, unconditional `bl` callers and no predicated `bl`
/// callers. The raw `ldr r0,[r0,#0x30]; cmp r0,#0; movne r0,#1; mov pc,lr`
/// reads the file handle word at target offset `+0x30` and normalizes its
/// non-nullness to a C++ bool. No deliberate deviations.
///
/// # Safety
///
/// `filebuf` must designate a readable target-layout file buffer containing
/// at least 13 words.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn filebuf_is_open(filebuf: *const u32) -> bool {
    filebuf.add(12).read() != 0
}

/// `wide_filebuf_is_open` — retailOS `FUN_083d6f30` @ `0x083d6f30`.
///
/// True extent: **16 bytes**, `[0x083d6f30, 0x083d6f40)`, where the next
/// independent dereferenced-word comparison begins. Raw ARM words:
/// `e5900030 e3500000 13a00001 e1a0f00e` — load the handle at +0x30,
/// compare with zero, normalize nonzero to one, and return via `mov pc,lr`.
/// Whole-image ARM immediate decoding finds one incoming plain BL
/// (0x083d9b54), zero predicated BLs, and no outgoing BLs. The caller
/// 0x083d9b20 writes two-byte characters through the handle at +0x30,
/// identifying the wide-character file-buffer variant of `is_open`.
/// No behavioral deviations; word indexing preserves target offsets on
/// hosts. A dedicated text section prevents LLVM folding this body with
/// identical predicates, retaining a separately inspectable BL target.
///
/// # Safety
///
/// `filebuf` must designate a readable, word-aligned target-layout file
/// buffer containing at least 13 words. The handle itself is not dereferenced.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.wide_filebuf_is_open")]
#[inline(never)]
pub unsafe extern "C" fn wide_filebuf_is_open(filebuf: *const u32) -> bool {
    filebuf.add(12).read() != 0
}

#[cfg(test)]
#[test]
fn wide_filebuf_is_open_normalizes_the_handle_without_touching_other_words() {
    for handle in [0, 1, 2, 0x8000_0000, u32::MAX] {
        for surrounding in [0, u32::MAX] {
            let mut filebuf = [surrounding; 13];
            filebuf[12] = handle;
            let before = filebuf;
            assert_eq!(unsafe { wide_filebuf_is_open(filebuf.as_ptr()) }, handle != 0);
            assert_eq!(filebuf, before);
        }
    }
}

#[cfg(test)]
#[test]
fn filebuf_is_open_checks_only_the_handle_word() {
    let mut closed = [u32::MAX; 13];
    closed[12] = 0;
    assert!(!unsafe { filebuf_is_open(closed.as_ptr()) });

    let mut open = [0; 13];
    open[12] = 1;
    assert!(unsafe { filebuf_is_open(open.as_ptr()) });
    open[12] = u32::MAX;
    assert!(unsafe { filebuf_is_open(open.as_ptr()) });
}
