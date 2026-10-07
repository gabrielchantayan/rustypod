//! SQLite soft-heap-limit entry veneer.
//!
//! Original: `thunk_FUN_08391408` @ `0x0813eb3c`, **4 bytes**.
//! Raw word `0xea094a31` decodes to `b 0x08391408`; the next real
//! function starts with `push {r4,lr}` at `0x0813eb40`. Binary-wide
//! decoding finds **2 plain BL callers, 0 predicated BL callers**
//! (`0x0811f794`, `0x0816ea80`) and one tail B (`0x0816ebdc`).
//!
//! Passes the signed byte limit unchanged to the resident SQLite soft
//! heap limit setter/reclaimer and returns its result unchanged. The
//! target clamps negative limits to zero for the stats setter, then
//! subtracts the original signed limit from current usage and tail-calls
//! the memory-release walk when the low-word difference is positive.
//! This veneer owns none of that target body.
//!
//! Deliberate deviation: an 8-byte absolute-PC-load veneer replaces the
//! original relative B so the Rust payload can be linked anywhere without
//! an external relocation. All registers, flags, SP and LR are preserved
//! on entry to the verified, unported target at `0x08391408`. No host
//! substitute is provided: the resident firmware and its globals are
//! required. Naked assembly avoids introducing an ABI wrapper that could
//! discard the target's secondary return register or change LR.

/// Tail-enters the resident soft-limit setter/reclaimer with `limit` in r0.
///
/// Requires the original retailOS image and allocator state to be resident.
#[cfg(target_os = "none")]
#[unsafe(naked)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn sqlite_soft_heap_limit_entry(_limit: i32) -> i32 {
    core::arch::naked_asm!("ldr pc, [pc, #-4]", ".word 0x08391408");
}
