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
