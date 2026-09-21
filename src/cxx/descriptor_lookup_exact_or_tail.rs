//! Descriptor lookup with exact-or-tail parse — retailOS `FUN_082c59f4` at
//! load address `0x082c59f4` (100 bytes; `0x082c59f4..0x082c5a58`). The next
//! distinct function is the `ldr r3, [pc]; b 0x0803a7f0` thunk at `0x082c5a5c`.
//!
//! Raw `osos.dec` decoding finds three plain unconditional `bl` calls and no
//! predicated `bl` calls. The routine resolves an opaque primary descriptor,
//! accepts it only when it consumes the requested byte count, otherwise tries
//! an opaque tail descriptor against the resolved object's +0x50 output word
//! and unconsumed input. A failed tail lookup releases the primary allocation.
//!
//! Deliberate deviation: target builds retain the 25 original ARM words. Host
//! builds use the existing descriptor-parser and allocation-release seams,
//! because the retail parser and release engine are not host-mapped.

#[cfg(not(target_arch = "arm"))]
use super::generic_descriptor_lookup::generic_descriptor_lookup;
#[cfg(not(target_arch = "arm"))]
use super::typed_allocation_release::typed_allocation_release_helper;

const PRIMARY_DESCRIPTOR: usize = 0x0890_63e8;
const TAIL_DESCRIPTOR: usize = 0x0891_fb08;

/// Resolves a primary descriptor, requiring exact consumption or a valid tail.
#[cfg(not(target_arch = "arm"))]
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn descriptor_lookup_exact_or_tail(
    _unused: u32, cursor: *mut u32, input_len: u32,
) -> *mut u8 {
    let initial_cursor = cursor.read();
    let allocation = generic_descriptor_lookup(
        core::ptr::null_mut(), cursor.cast(), input_len, PRIMARY_DESCRIPTOR as *mut u8,
    );
    if allocation.is_null() { return core::ptr::null_mut(); }
    let consumed = cursor.read().wrapping_sub(initial_cursor);
    if consumed == input_len || !generic_descriptor_lookup(
        allocation.add(0x50).cast(), cursor.cast(), input_len.wrapping_sub(consumed),
        TAIL_DESCRIPTOR as *mut u8,
    ).is_null() {
        allocation
    } else {
        typed_allocation_release_helper(allocation, PRIMARY_DESCRIPTOR as *const u8);
        core::ptr::null_mut()
    }
}

#[cfg(target_arch = "arm")]
core::arch::global_asm!(r#"
    .syntax unified
    .section .text.descriptor_lookup_exact_or_tail, "ax", %progbits
    .p2align 2
    .globl descriptor_lookup_exact_or_tail
    .type descriptor_lookup_exact_or_tail, %function
descriptor_lookup_exact_or_tail:
    push    {{r4, r5, r6, r7, r8, lr}}
    ldr     r6, [r1]
    ldr     r3, [pc, #84]
    mov     r7, r2
    mov     r5, r1
    bl      0x0803a7f0
    movs    r4, r0
    bne     1f
    mov     r0, #0
    pop     {{r4, r5, r6, r7, r8, pc}}
1:
    ldr     r0, [r5]
    sub     r0, r0, r6
    subs    r2, r7, r0
    beq     2f
    mov     r1, r5
    add     r0, r4, #80
    bl      0x082c5a5c
    cmp     r0, #0
    beq     3f
2:
    mov     r0, r4
    pop     {{r4, r5, r6, r7, r8, pc}}
3:
    ldr     r1, [pc, #8]
    mov     r0, r4
    bl      0x0803b3a4
    b       descriptor_lookup_exact_or_tail + 0x20
    .word   0x089063e8
    .size descriptor_lookup_exact_or_tail, . - descriptor_lookup_exact_or_tail
"#);

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::cxx::generic_descriptor_lookup::{DescriptorParser, DESCRIPTOR_PARSER, DESCRIPTOR_PARSER_TEST_LOCK};
    use crate::cxx::typed_allocation_release::{AllocationReleaseFrame, TypeErasedReleaseEngine, TYPE_ERASED_RELEASE_ENGINE, TYPE_ERASED_RELEASE_ENGINE_TEST_LOCK};
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use core::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
    use std::sync::LazyLock;

    static PRIMARY_RESULT: AtomicUsize = AtomicUsize::new(0);
    static TAIL_RESULT: AtomicUsize = AtomicUsize::new(0);
    static PRIMARY_ADVANCE: AtomicU32 = AtomicU32::new(0);
    static TAIL_CALLS: AtomicUsize = AtomicUsize::new(0);
    static RELEASED_ALLOCATION: AtomicUsize = AtomicUsize::new(0);
    static RELEASED_DESCRIPTOR: AtomicUsize = AtomicUsize::new(0);
    static ALLOCATION: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::DESCRIPTOR_LOOKUP_EXACT_OR_TAIL, 0x1000).map(|p| p as usize)
    });

    unsafe extern "C" fn parser(output: *mut u32, input: *mut u8, _len: u32, descriptor: *mut u8, _selector: i32, _a: u32, _b: u32, _status: *mut u8) -> i32 {
        if descriptor as usize == PRIMARY_DESCRIPTOR {
            (input as *mut u32).write((input as *mut u32).read().wrapping_add(PRIMARY_ADVANCE.load(Ordering::SeqCst)));
            output.write(PRIMARY_RESULT.load(Ordering::SeqCst) as u32);
            1
        } else {
            TAIL_CALLS.fetch_add(1, Ordering::SeqCst);
            output.write(TAIL_RESULT.load(Ordering::SeqCst) as u32);
            (TAIL_RESULT.load(Ordering::SeqCst) != 0) as i32
        }
    }
    unsafe extern "C" fn record_release(frame: *mut AllocationReleaseFrame, descriptor: *const u8, _state: u32) {
        RELEASED_ALLOCATION.store((*frame).allocation as usize, Ordering::SeqCst);
        RELEASED_DESCRIPTOR.store(descriptor as usize, Ordering::SeqCst);
    }
    struct SeamReset { parser: DescriptorParser, release: TypeErasedReleaseEngine }
    impl Drop for SeamReset { fn drop(&mut self) { unsafe { DESCRIPTOR_PARSER = self.parser; TYPE_ERASED_RELEASE_ENGINE = self.release; } } }
    fn install(primary: usize, advance: u32, tail: usize) -> SeamReset {
        let reset = SeamReset { parser: unsafe { DESCRIPTOR_PARSER }, release: unsafe { TYPE_ERASED_RELEASE_ENGINE } };
        PRIMARY_RESULT.store(primary, Ordering::SeqCst); PRIMARY_ADVANCE.store(advance, Ordering::SeqCst); TAIL_RESULT.store(tail, Ordering::SeqCst);
        TAIL_CALLS.store(0, Ordering::SeqCst); RELEASED_ALLOCATION.store(0, Ordering::SeqCst); RELEASED_DESCRIPTOR.store(0, Ordering::SeqCst);
        unsafe { DESCRIPTOR_PARSER = parser; TYPE_ERASED_RELEASE_ENGINE = record_release; }
        reset
    }
    #[test]
    fn exact_primary_consumption_skips_tail_and_release() {
        let _parser_guard = DESCRIPTOR_PARSER_TEST_LOCK.lock(); let _release_guard = TYPE_ERASED_RELEASE_ENGINE_TEST_LOCK.lock();
        let Some(allocation) = *ALLOCATION else { assert!(note_missing_u32_fixture("cxx/descriptor_lookup_exact_or_tail")); return; };
        unsafe { (allocation as *mut u8).write_bytes(0, 0x1000) };
        let _reset = install(allocation, 12, 0); let mut cursor = 0x4000u32;
        assert_eq!(unsafe { descriptor_lookup_exact_or_tail(0, &mut cursor, 12) as usize }, allocation);
        assert_eq!(TAIL_CALLS.load(Ordering::SeqCst), 0); assert_eq!(RELEASED_ALLOCATION.load(Ordering::SeqCst), 0);
    }
    #[test]
    fn tail_failure_releases_primary_allocation() {
        let _parser_guard = DESCRIPTOR_PARSER_TEST_LOCK.lock(); let _release_guard = TYPE_ERASED_RELEASE_ENGINE_TEST_LOCK.lock();
        let Some(allocation) = *ALLOCATION else { assert!(note_missing_u32_fixture("cxx/descriptor_lookup_exact_or_tail")); return; };
        unsafe { (allocation as *mut u8).write_bytes(0, 0x1000) };
        let _reset = install(allocation, 4, 0); let mut cursor = 0x4000u32;
        assert!(unsafe { descriptor_lookup_exact_or_tail(0, &mut cursor, 12) }.is_null());
        assert_eq!(TAIL_CALLS.load(Ordering::SeqCst), 1); assert_eq!(RELEASED_ALLOCATION.load(Ordering::SeqCst), allocation);
        assert_eq!(RELEASED_DESCRIPTOR.load(Ordering::SeqCst), PRIMARY_DESCRIPTOR);
    }
}
