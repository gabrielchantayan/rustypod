//! Resolve a scoped context's result identifier.
//!
//! Original `FUN_082a3018` @ `0x082a3018`, 60 bytes, ending at
//! `0x082a3054` where the next independent push prologue begins. Raw A32
//! decoding finds zero outgoing plain/predicated BLs, one unconditional BLX
//! through vtable slot +8, and two inbound plain BLs (0x08052c1c and
//! 0x080535b8), with no predicated inbound BLs.
//!
//! Call the unresolved virtual predicate, then reload context word +4. If
//! either is zero, return zero without touching output. Otherwise copy the
//! pointed object's word +0x18 to output and return one, even for identifier
//! zero. No concrete virtual callee identity is assumed. Deliberate deviation:
//! host vtable slots widen to usize, as in the existing ScopedContext layout;
//! its owner_valid word remains a target-width pointer, not the owner at +8.

use crate::app::scoped_context::ScopedContext;

/// # Safety
/// `context` must have a valid vtable slot two accepting this receiver. After
/// that call, a nonzero `owner_valid` must point to seven readable u32 words.
/// `output` must be writable only on the successful path; it may alias a field.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn scoped_context_result_id(context: *mut ScopedContext, output: *mut u32) -> u32 {
    let vtable = core::ptr::addr_of!((*context).vtable).read();
    let predicate = core::mem::transmute::<usize, unsafe extern "C" fn(*mut ScopedContext) -> u32>(
        (*vtable).slots[2],
    );
    if predicate(context) == 0 {
        return 0;
    }
    let result = core::ptr::addr_of!((*context).owner_valid).read() as usize as *const u32;
    if result.is_null() {
        return 0;
    }
    output.write(result.add(6).read());
    1
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::scoped_context::ScopedContextVtable;
    use crate::testing::{hints, try_map_u32_slab};

    unsafe extern "C" fn reject(context: *mut ScopedContext) -> u32 {
        // A rejected query must not dereference even a nonzero invalid word.
        (*context).owner_valid = 1;
        0
    }
    unsafe extern "C" fn accept(_context: *mut ScopedContext) -> u32 { 0x8000_0000 }
    unsafe extern "C" fn clear(context: *mut ScopedContext) -> u32 {
        (*context).owner_valid = 0;
        1
    }
    unsafe extern "C" fn advance(context: *mut ScopedContext) -> u32 {
        (*context).owner_valid += 32;
        1
    }

    #[test]
    fn gates_reload_zero_identifier_and_aliasing() {
        let Some(slab) = try_map_u32_slab(hints::SCOPED_CONTEXT_RESULT_ID, 4096) else { return; };
        let mut vtable = ScopedContextVtable { slots: [0; 15] };
        let mut context = ScopedContext {
            vtable: &vtable, owner_valid: 0, owner: core::ptr::null_mut(),
            service_context: core::ptr::null_mut(), registry_token: core::ptr::null_mut(), mode: 0,
        };
        unsafe {
            let words = slab.cast::<u32>();
            words.add(6).write(0x1234_5678);
            words.add(14).write(0);
            let mut output = 0xdead_beef;
            vtable.slots[2] = reject as *const () as usize;
            assert_eq!(scoped_context_result_id(&mut context, &mut output), 0);
            assert_eq!(output, 0xdead_beef);
            vtable.slots[2] = clear as *const () as usize;
            context.owner_valid = slab as usize as u32;
            assert_eq!(scoped_context_result_id(&mut context, core::ptr::null_mut()), 0);
            vtable.slots[2] = advance as *const () as usize;
            context.owner_valid = slab as usize as u32;
            assert_eq!(scoped_context_result_id(&mut context, &mut output), 1);
            assert_eq!(output, 0);
            vtable.slots[2] = accept as *const () as usize;
            context.owner_valid = slab as usize as u32;
            assert_eq!(scoped_context_result_id(&mut context, core::ptr::addr_of_mut!(context.owner_valid)), 1);
            assert_eq!(context.owner_valid, 0x1234_5678);
        }
    }
}
