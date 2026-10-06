//! Genius request source construction, FUN_08159bcc at 0x08159bcc.
//! True extent [0x08159bcc,0x08159c08): 60 bytes, ending in POP {r4,pc}
//! before the next function's PUSH. Raw aligned A32 decoding verifies two
//! incoming plain BLs, zero predicated; six outgoing plain BLs, zero predicated.
//! Construct three sources, advancing each returned pointer by 0x15c; derive
//! the aggregate base from the final result minus 0x2b8. Dispatch vtable slots
//! +0x1c then +0x08 on each source, and return the aggregate base.
//! Deviations: unrecovered constructors retain exact-address typed BLX seams;
//! host tests use word-based source state because host pointers are wider.
//! No null checks or assumption that constructors return their input are added.

const STRIDE: usize = 0x15c;
const CONSTRUCTORS: [usize; 3] = [0x082335d8, 0x0821a92c, 0x0823132c];

unsafe fn construct(storage: *mut u8, mut constructor: impl FnMut(usize, *mut u8) -> *mut u8,
    mut dispatch: impl FnMut(*mut u8)) -> *mut u8 {
    let first = constructor(CONSTRUCTORS[0], storage);
    let second = constructor(CONSTRUCTORS[1], first.wrapping_add(STRIDE));
    let third = constructor(CONSTRUCTORS[2], second.wrapping_add(STRIDE));
    let base = third.wrapping_sub(2 * STRIDE);
    for offset in [0, STRIDE, 2 * STRIDE] {
        dispatch(base.wrapping_add(offset));
    }
    base
}

/// Construct and activate the three embedded Genius request sources.
/// # Safety
/// Storage and all constructor-returned objects must satisfy the retail
/// constructors' contracts, including writable space for three 0x15c-byte
/// sources and valid virtual dispatch tables after construction.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn genius_request_source_construct(storage: *mut u8) -> *mut u8 {
    construct(storage, |address, object| {
        #[cfg(target_os = "none")]
        {
            let constructor: unsafe extern "C" fn(*mut u8) -> *mut u8 = core::mem::transmute(address);
            constructor(object)
        }
        #[cfg(not(target_os = "none"))]
        { let _ = (address, object); panic!("Source construction requires retail firmware constructors") }
    }, |object| crate::cxx::vtable_slot_1c_then_slot_08_dispatch::vtable_slot_1c_then_slot_08_dispatch(object))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn returned_storage_controls_activation_without_touching_neighbors() {
        for relocation in [0usize, 4, 16] {
            let mut words = [0xfeedfaceu32; 280];
            let start = words.as_mut_ptr().cast::<u8>();
            let base = start.wrapping_add(relocation);
            let mut stage = 0;
            let result = unsafe { construct(start, |_, object| {
                let returned = if stage == 0 { object.wrapping_add(relocation) } else { object };
                returned.cast::<u32>().write(1);
                stage += 1;
                returned
            }, |object| {
                for offset in [0, STRIDE, 2 * STRIDE] {
                    assert_eq!(base.wrapping_add(offset).cast::<u32>().read() & 1, 1);
                }
                let state = object.cast::<u32>();
                assert_eq!(state.read(), 1);
                state.write(3);
            }) };
            assert_eq!(result, base);
            for (index, value) in words.iter().enumerate() {
                let offset = index * 4;
                let is_source = [relocation, relocation + STRIDE, relocation + 2 * STRIDE].contains(&offset);
                assert_eq!(*value, if is_source { 3 } else { 0xfeedface });
            }
        }
    }
}
