//! Scoped-context playlist membership — FUN_08059c4c @ 0x08059c4c.
//!
//! True extent [0x08059c4c, 0x08059c60): 20 instruction bytes, no literals;
//! the next function is LDRB/BX LR. Whole-image ARM-word decoding finds two
//! incoming plain BLs (0x080bed30, 0x080bed4c), zero predicated BLs. The body
//! has one plain BL to 0x08050c48, zero predicated BLs. Pass context and
//! playlist unchanged to the lookup, then normalize its entry pointer to 0/1.
//! The lookup validates the playlist's plst class and the context's tdat
//! owner, then scans context +0x24, comparing entry word zero with playlist
//! and following entry +0x28. Both callers supply playlist in r1 despite
//! Ghidra's incorrect zero-argument wrapper signature.
//!
//! Deviations: none on target; the unported lookup remains a firmware seam.
//! Hosts must install a lookup implementation before calling the export.

/// Lookup at 0x08050c48; returns the matching entry or NULL.
pub type ScopedContextFindPlaylistEntry = unsafe extern "C" fn(*const u8, *const u8) -> *mut u8;

unsafe extern "C" fn firmware_scoped_context_find_playlist_entry(
    context: *const u8, playlist: *const u8,
) -> *mut u8 {
    #[cfg(target_os = "none")]
    {
        let lookup: ScopedContextFindPlaylistEntry = core::mem::transmute(0x0805_0c48usize);
        lookup(context, playlist)
    }
    #[cfg(not(target_os = "none"))]
    {
        let _ = (context, playlist);
        panic!("scoped context playlist lookup requires a host implementation")
    }
}

pub static mut SCOPED_CONTEXT_FIND_PLAYLIST_ENTRY_IMPL: ScopedContextFindPlaylistEntry =
    firmware_scoped_context_find_playlist_entry;

/// Return 1 if the context has an entry for the playlist, otherwise 0.
///
/// # Safety
/// Arguments must satisfy the installed lookup's contract. On firmware,
/// non-NULL objects and the context's linked entries must be readable and
/// valid for the retail class predicates. Seam replacement requires exclusive
/// access; it must not race with callers.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn scoped_context_contains_playlist(
    context: *const u8, playlist: *const u8,
) -> u32 {
    let lookup = core::ptr::read_volatile(
        core::ptr::addr_of!(SCOPED_CONTEXT_FIND_PLAYLIST_ENTRY_IMPL),
    );
    (!lookup(context, playlist).is_null()) as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    // The wrapper must test the entire pointer, not its sign or low byte.
    unsafe extern "C" fn result_from_playlist(_: *const u8, playlist: *const u8) -> *mut u8 {
        playlist as *mut u8
    }

    #[test]
    fn null_and_noncanonical_nonzero_results_normalize_to_boolean() {
        unsafe {
            let saved = SCOPED_CONTEXT_FIND_PLAYLIST_ENTRY_IMPL;
            SCOPED_CONTEXT_FIND_PLAYLIST_ENTRY_IMPL = result_from_playlist;
            for bits in [0usize, 1, 0x100, 0x8000_0000, 0xffff_ffff, usize::MAX] {
                assert_eq!(scoped_context_contains_playlist(core::ptr::null(), bits as *const u8),
                    if bits == 0 { 0 } else { 1 }, "result={bits:#x}");
            }
            SCOPED_CONTEXT_FIND_PLAYLIST_ENTRY_IMPL = saved;
        }
    }
}
