//! Queue insertion veneer — `thunk_FUN_08087594` @ `0x08061d1c`.
//!
//! True extent [0x08061d1c, 0x08061d20), 4 bytes: raw A32 word
//! 0xea00961c is `b 0x08087594`; the next word starts an independent push.
//! Whole-image decoding verifies two incoming plain BLs (0x0817a2a0,
//! 0x082268c4), zero predicated incoming BLs, and zero outgoing BLs.
//! Tail-transfer owner, index, and entry unchanged to the retail queue
//! insertion routine, preserving its result. That routine rejects unavailable
//! or over-capacity queues with -41 and otherwise inserts and notifies.
//! Deliberate deviations: LLVM adds a restored frame and loads the verified
//! retail target from a literal before tail-transferring with BX. The target
//! remains unported. Host invocation is unsupported because the target requires
//! retail globals and virtual calls. Compiled ARM execution matches the stock
//! branch for 144 argument/result boundary cases, including stack restoration
//! and callee-saved registers; this does not simulate the queue implementation.

/// # Safety
/// Arguments must satisfy retail `0x08087594`'s unchecked object contracts.
/// An index of -1 selects collection insertion; other indices select one entry.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn queue_insert_veneer(owner: *mut u8, index: i32, entry: *mut u8) -> i32 {
    #[cfg(target_os = "none")]
    {
        let insert: unsafe extern "C" fn(*mut u8, i32, *mut u8) -> i32 =
            core::mem::transmute(0x0808_7594usize);
        insert(owner, index, entry)
    }
    #[cfg(not(target_os = "none"))]
    {
        let _ = (owner, index, entry);
        panic!("retail queue insertion at 0x08087594 is unavailable on host")
    }
}
