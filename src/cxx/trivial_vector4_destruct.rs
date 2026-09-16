//! `trivial_vector4_destruct` — originals: `FUN_083e68a0` @ `0x083e68a0`
//! and `FUN_083e4b2c` @ `0x083e4b2c` (64 bytes each; `0x083e68a0..0x083e68e0`
//! ends where the next separately linked function starts `push
//! {r4,r5,r6,r7,r8,lr}` at `0x083e68e0`, and `0x083e4b2c..0x083e4b6c` ends
//! where `FUN_083e4b6c` starts `push {r4,r5,r6,r7,r8,lr}` at `0x083e4b6c`).
//!
//! Source: `ipod-decomp/decomp/c/038/083e68a0_FUN_083e68a0.c` and
//! `ipod-decomp/decomp/c/038/083e4b2c_FUN_083e4b2c.c` (Ghidra's recovered
//! loops are wrong; raw ARM below is ground truth).
//!
//! The four-byte-element sibling of [`super::trivial_vector8_destruct`].
//! Destroys a `std::vector<T>` whose four-byte elements have trivial
//! destruction: walks the half-open `[begin, end)` range in four-byte
//! increments with an empty body (the element destructor was optimized
//! away but the walk is retained), then releases the backing allocation
//! and returns the vector descriptor.
//!
//! Raw osos.dec confirms both 64-byte bodies are word-for-word identical
//! except for the `bl` immediate (each reaches the `0x08266f2c` veneer from
//! its own address), so a single Rust symbol covers both and the fold is
//! intentional. The `0x083e4b2c` body:
//!
//! ```text
//! 083e4b2c:  push {r4,lr}
//! 083e4b30:  mov r4,r0
//! 083e4b34:  ldr r0,[r0,#0x0]      ; begin
//! 083e4b38:  ldr r1,[r4,#0x4]      ; end
//! 083e4b3c:  mov r2,r0             ; r2 = begin
//! 083e4b40:  cmp r0,r1
//! 083e4b44:  addne r0,r0,#0x4      ; walk begin -> end by 4
//! 083e4b48:  bne 0x083e4b40
//! 083e4b4c:  ldr r1,[r4,#0x8]      ; end_of_storage
//! 083e4b50:  mov r0,r2             ; arg0 = begin
//! 083e4b54:  sub r1,r1,r2
//! 083e4b58:  mov r1,r1, asr #0x2   ; arg1 = capacity in elements
//! 083e4b5c:  mov r2,#0x0           ; arg2 = 0
//! 083e4b60:  bl 0x08266f2c         ; veneer: b 0x082aad24 (operator_delete)
//! 083e4b64:  mov r0,r4
//! 083e4b68:  pop {r4,pc}
//! ```
//!
//! **Call count (0x083e4b2c):** complete aligned ARM B/BL-immediate
//! decoding of `osos.dec` finds exactly four direct inbound calls:
//! unconditional `bl` at `0x081e0640`, `0x081e0648`, and `0x081e0cdc`,
//! plus one predicated `blne` at `0x083ba018`; there are no tail branches.
//!
//! Raw ARM of the `0x083e68a0` instance:
//!
//! ```text
//! 083e68a0:  push {r4,lr}
//! 083e68a4:  mov r4,r0
//! 083e68a8:  ldr r0,[r0,#0x0]      ; begin
//! 083e68ac:  ldr r1,[r4,#0x4]      ; end
//! 083e68b0:  mov r2,r0             ; r2 = begin
//! 083e68b4:  cmp r0,r1
//! 083e68b8:  addne r0,r0,#0x4      ; walk begin -> end by 4
//! 083e68bc:  bne 0x083e68b4
//! 083e68c0:  ldr r1,[r4,#0x8]      ; end_of_storage
//! 083e68c4:  mov r0,r2             ; arg0 = begin
//! 083e68c8:  sub r1,r1,r2
//! 083e68cc:  mov r1,r1, asr #0x2   ; arg1 = capacity in elements
//! 083e68d0:  mov r2,#0x0           ; arg2 = 0
//! 083e68d4:  bl 0x08266f2c         ; veneer: b 0x082aad24 (operator_delete)
//! 083e68d8:  mov r0,r4
//! 083e68dc:  pop {r4,pc}
//! ```
//!
//! The single `bl` reaches the `0x08266f2c` veneer, an unconditional
//! branch to the ported `operator_delete` @ `0x082aad24` (tag 2,
//! NULL-guarded). That cleanup routine's C signature has only its first
//! argument, so r1/r2 are dead auxiliary registers. The port retains the
//! descriptor reads, the retained walk, and the capacity calculation
//! while reaching the existing allocator `free` seam with the sole live
//! cleanup argument. The vector descriptor is never written.
//!
//! **Call count (0x083e68a0):** complete aligned ARM B/BL-immediate
//! decoding of `osos.dec` finds exactly four direct inbound calls, all
//! unconditional `bl`, at `0x08177890`, `0x08177898`, `0x081778a0`, and
//! `0x08177be4`; there are no predicated forms and no tail branches.
//!
//! # Deliberate deviations
//!
//! The original's veneer dispatch to `operator_delete` is routed through
//! the ported `free` seam, matching `trivial_vector8_destruct`.
//!
//! # Safety
//!
//! `vector` must address three consecutive pointer-width fields:
//! `{begin, end, end_of_storage}`; the range must advance from `begin`
//! to `end` in four-byte increments, as required by the raw loop.

type StorageFree = unsafe extern "C" fn(*mut u8);

/// Routes the original cleanup call through the ported allocator seam.
#[inline(never)]
unsafe extern "C" fn free_storage(storage: *mut u8) {
    crate::runtime::malloc_rt::free(storage);
}

/// Destroys a vector whose elements occupy four bytes, releases its backing
/// allocation, and returns `vector`. `vector` must address three consecutive
/// pointer-width fields: `{begin, end, end_of_storage}`; the range must
/// advance from `begin` to `end` in four-byte increments, as required by the
/// raw loop.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.trivial_vector4_destruct")]
#[inline(never)]
pub unsafe extern "C" fn trivial_vector4_destruct(vector: *mut *mut u8) -> *mut *mut u8 {
    unsafe { trivial_vector4_destruct_with(vector, free_storage) }
}

/// Separates the raw walk and cleanup call from the allocator seam so host
/// tests can observe the released pointer without freeing fixture data.
#[inline(always)]
unsafe fn trivial_vector4_destruct_with(vector: *mut *mut u8, release: StorageFree) -> *mut *mut u8 {
    unsafe {
        let begin = vector.read();
        let end = vector.add(1).read();
        let capacity = vector.add(2).read();

        let mut current = begin;
        while current != end {
            current = current.wrapping_add(4);
            core::hint::black_box(current);
        }

        let capacity_slots = (capacity as usize).wrapping_sub(begin as usize) >> 2;
        core::hint::black_box(capacity_slots);
        release(begin);
        vector
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::{AtomicUsize, Ordering};

    static FREE_CALLS: AtomicUsize = AtomicUsize::new(0);
    static FREED_STORAGE: AtomicUsize = AtomicUsize::new(0);
    unsafe extern "C" fn record_free(storage: *mut u8) {
        FREE_CALLS.fetch_add(1, Ordering::SeqCst);
        FREED_STORAGE.store(storage as usize, Ordering::SeqCst);
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct VectorStorage {
        before: usize,
        begin: *mut u8,
        end: *mut u8,
        capacity: *mut u8,
        after: usize,
    }

    #[test]
    fn walks_trivial_elements_releases_begin_and_never_writes_the_descriptor() {
        let mut allocation = [0u8; 32];
        let mut vector = VectorStorage {
            before: 0x1122_3344_5566_7788,
            begin: allocation.as_mut_ptr(),
            end: unsafe { allocation.as_mut_ptr().add(16) },
            capacity: unsafe { allocation.as_mut_ptr().add(32) },
            after: 0x8877_6655_4433_2211,
        };
        let before = vector;
        FREE_CALLS.store(0, Ordering::SeqCst);
        FREED_STORAGE.store(0, Ordering::SeqCst);

        let result = unsafe { trivial_vector4_destruct_with(&mut vector.begin, record_free) };

        assert_eq!(result, core::ptr::addr_of_mut!(vector.begin));
        assert_eq!(vector.before, before.before, "prefix guard");
        assert_eq!(vector.begin, before.begin, "begin");
        assert_eq!(vector.end, before.end, "end");
        assert_eq!(vector.capacity, before.capacity, "capacity");
        assert_eq!(vector.after, before.after, "suffix guard");
        assert_eq!(FREE_CALLS.load(Ordering::SeqCst), 1);
        assert_eq!(FREED_STORAGE.load(Ordering::SeqCst), before.begin as usize);

        let mut empty_allocation = [0u8; 8];
        let mut empty_vector = VectorStorage {
            before: 0x1020_3040_5060_7080,
            begin: empty_allocation.as_mut_ptr(),
            end: empty_allocation.as_mut_ptr(),
            capacity: unsafe { empty_allocation.as_mut_ptr().add(8) },
            after: 0x8070_6050_4030_2010,
        };
        let empty_before = empty_vector;
        FREE_CALLS.store(0, Ordering::SeqCst);
        FREED_STORAGE.store(0, Ordering::SeqCst);

        let empty_result = unsafe { trivial_vector4_destruct_with(&mut empty_vector.begin, record_free) };

        assert_eq!(empty_result, core::ptr::addr_of_mut!(empty_vector.begin));
        assert_eq!(empty_vector.before, empty_before.before, "empty prefix guard");
        assert_eq!(empty_vector.begin, empty_before.begin, "empty begin");
        assert_eq!(empty_vector.end, empty_before.end, "empty end");
        assert_eq!(empty_vector.capacity, empty_before.capacity, "empty capacity");
        assert_eq!(empty_vector.after, empty_before.after, "empty suffix guard");
        assert_eq!(FREE_CALLS.load(Ordering::SeqCst), 1);
        assert_eq!(FREED_STORAGE.load(Ordering::SeqCst), empty_before.begin as usize);
    }
}
