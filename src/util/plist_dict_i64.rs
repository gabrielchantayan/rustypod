//! Keyed signed-64 plist access — `FUN_0829c2a4` @ 0x0829c2a4.
//!
//! True extent: 44 bytes, 0x0829c2a4..0x0829c2d0, including the final
//! `mov r0,r0` NOP. Raw-word decoding finds two plain incoming BLs
//! (0x080ab2bc, 0x080ab360), zero predicated incoming BLs, one plain
//! outgoing BL (0x0829c2b4 -> 0x0829c09c), and no predicated outgoing BLs.
//! Resolve the dictionary key to its pair index, then fall through to the
//! indexed signed-64 accessor at 0x0829c2d0 with the original fallback.
//! That accessor reads the value child's text and tail-calls 0x0802fb9c.
//!
//! Deliberate deviations: Rust expresses the NOP/fall-through as a call;
//! LLVM chooses the frame and tail-call sequence. Unported retail helpers
//! remain fixed-address calls on ARM and typed, installable seams on host.
//! No node layout is reinterpreted, and no bounds or parser behavior changes.

pub type PlistDictFindKey = unsafe extern "C" fn(
    dictionary: *const u8, key: *const u8,
) -> u32;
pub type PlistIndexedI64 = unsafe extern "C" fn(
    dictionary: *const u8, index: u32, fallback: i64,
) -> i64;

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_find_key(_: *const u8, _: *const u8) -> u32 {
    panic!("plist_dict_i64 requires the retail dictionary lookup host seam")
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_indexed_i64(_: *const u8, _: u32, _: i64) -> i64 {
    panic!("plist_dict_i64 requires the retail indexed integer host seam")
}

/// Host replacement for the unported dictionary key lookup at 0x0829c09c.
#[cfg(not(target_os = "none"))]
pub static mut PLIST_DICT_FIND_KEY: PlistDictFindKey = missing_find_key;
/// Host replacement for the unported indexed signed-64 accessor at 0x0829c2d0.
#[cfg(not(target_os = "none"))]
pub static mut PLIST_INDEXED_I64: PlistIndexedI64 = missing_indexed_i64;

/// Read a dictionary value as a signed 64-bit integer, or return `fallback`.
///
/// `dictionary` must satisfy both retail helpers' plist-view contract; `key`
/// points to a retail string handle, not directly to NUL-terminated text.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn plist_dict_i64(
    dictionary: *const u8, key: *const u8, fallback: i64,
) -> i64 {
    #[cfg(target_os = "none")]
    let (find_key, indexed_i64): (PlistDictFindKey, PlistIndexedI64) = (
        core::mem::transmute(0x0829_c09cusize),
        core::mem::transmute(0x0829_c2d0usize),
    );
    #[cfg(not(target_os = "none"))]
    let (find_key, indexed_i64) = (
        core::ptr::read_volatile(core::ptr::addr_of!(PLIST_DICT_FIND_KEY)),
        core::ptr::read_volatile(core::ptr::addr_of!(PLIST_INDEXED_I64)),
    );
    let index = find_key(dictionary, key);
    indexed_i64(dictionary, index, fallback)
}
