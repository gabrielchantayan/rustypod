//! Parser stack item lookup — `FUN_082987b4` @ `0x082987b4`.
//!
//! True extent: 44 bytes, `0x082987b4..0x082987e0`; the next instruction
//! starts a distinct push prologue. Raw ARM has two plain inbound BL sites
//! (0x081199fc, 0x0811ddd4), zero predicated inbound BLs, zero direct BLs
//! in the body, and one register-indirect BLX.
//!
//! Rejects negative indices without reading the object; otherwise rejects
//! index >= signed count. Calls vtable slot 16 with object and index, then
//! returns the pointer stored in the returned slot. No null-slot guard.
//! Deliberate deviation: repr(C) uses native-width pointers on hosts; on ARM
//! count remains at +4 and vtable slot 16 at +0x40. No guessed callee seam.

#[repr(C)]
pub struct ParserStack {
    pub vtable: *const usize,
    pub count: i32,
}

/// Retrieves the pointer stored in a valid parser stack slot.
///
/// # Safety
/// For nonnegative indices, `stack` must be readable. For an in-range index,
/// vtable slot 16 must be an ABI-compatible method returning a readable
/// pointer slot. The runtime determines the concrete method implementation.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn parser_stack_item(stack: *mut ParserStack, index: i32) -> *mut u8 {
    if index < 0 || (*stack).count <= index {
        return core::ptr::null_mut();
    }
    let slot_at: unsafe extern "C" fn(*mut ParserStack, i32) -> *mut *mut u8 =
        core::mem::transmute((*stack).vtable.add(16).read());
    slot_at(stack, index).read()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[repr(C)]
    struct Fixture {
        stack: ParserStack,
        slots: [*mut u8; 3],
        last_index: i32,
    }

    unsafe extern "C" fn slot_at(stack: *mut ParserStack, index: i32) -> *mut *mut u8 {
        let fixture = &mut *stack.cast::<Fixture>();
        fixture.last_index = index;
        fixture.slots.as_mut_ptr().add(index as usize)
    }

    unsafe extern "C" fn remove_at(stack: *mut ParserStack, index: i32) {
        let fixture = &mut *stack.cast::<Fixture>();
        if index >= 0 {
            fixture.slots[index as usize] = core::ptr::null_mut();
            fixture.stack.count -= 1;
        }
    }

    #[test]
    fn negative_index_never_reads_object() {
        for index in [i32::MIN, -1] {
            assert!(unsafe { parser_stack_item(core::ptr::null_mut(), index) }.is_null());
        }
    }

    #[test]
    fn signed_bounds_reject_without_dispatch() {
        for count in [i32::MIN, -1, 0, 1, i32::MAX] {
            let mut stack = ParserStack { vtable: core::ptr::null(), count };
            for index in [count.max(0), i32::MAX] {
                assert!(unsafe { parser_stack_item(&mut stack, index) }.is_null());
            }
        }
    }

    #[test]
    fn dereferences_slots_and_pop_retains_removed_item() {
        let mut table = [0usize; 17];
        table[16] = slot_at as *const () as usize;
        table[11] = remove_at as *const () as usize;
        let mut first = 7u8;
        let mut last = 9u8;
        let mut fixture = Fixture {
            stack: ParserStack { vtable: table.as_ptr(), count: 3 },
            slots: [&mut first, core::ptr::null_mut(), &mut last],
            last_index: -1,
        };
        for index in 0..3 {
            assert_eq!(unsafe { parser_stack_item(&mut fixture.stack, index) }, fixture.slots[index as usize]);
            assert_eq!(fixture.last_index, index);
        }
        assert_eq!(unsafe { super::super::parser_stack_pop::parser_stack_pop((&mut fixture.stack as *mut ParserStack).cast()) }, &mut last as *mut u8);
        assert_eq!(fixture.stack.count, 2);
        assert!(fixture.slots[2].is_null());
        fixture.stack.count = 0;
        assert!(unsafe { super::super::parser_stack_pop::parser_stack_pop((&mut fixture.stack as *mut ParserStack).cast()) }.is_null());
    }
}
