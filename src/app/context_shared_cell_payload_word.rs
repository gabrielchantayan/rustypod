//! Retrieves the second word of the payload stored in a context's shared-cell
//! handle.

use crate::cxx::handle::handle_deref_or_null;

const SHARED_CELL_SLOT_OFFSET: usize = 0x890;
const DEFAULT_VALUE: u32 = 3;

/// `context_shared_cell_payload_word_or_default` — retailOS `FUN_0822b0e4`
/// @ `0x0822b0e4` (76 bytes; 4 incoming plain `bl` call sites, zero predicated
/// `bl` call sites, verified by decoding every ARM B/BL word in `osos.dec`).
///
/// Tests whether the one-word shared-cell handle at `context + 0x890` is
/// empty. It returns 3 when empty; otherwise it dereferences the cell's
/// payload and returns payload word 1 (+4).
///
/// Deliberate deviation: the original constructs, compares against, and
/// releases a temporary NULL shared-cell handle. Those operations have no
/// observable effect, so this port directly tests the context handle before
/// using the existing NULL-guarded handle seam.
///
/// # Safety
/// `context + 0x890` must be a readable shared-cell slot. A non-NULL slot
/// must point to a readable cell whose payload has a readable word at +4.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn context_shared_cell_payload_word_or_default(context: *const u8) -> u32 {
    let slot = context.add(SHARED_CELL_SLOT_OFFSET).cast::<*const *mut u8>();
    let payload = handle_deref_or_null(slot);
    if payload.is_null() {
        DEFAULT_VALUE
    } else {
        payload.add(4).cast::<u32>().read()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cxx::shared_cell::SharedCell;
    use core::mem::MaybeUninit;

    #[test]
    fn returns_default_for_an_empty_handle() {
        let mut context = [MaybeUninit::<usize>::uninit(); (SHARED_CELL_SLOT_OFFSET + 8) / 8];
        unsafe {
            context
                .as_mut_ptr()
                .cast::<u8>()
                .add(SHARED_CELL_SLOT_OFFSET)
                .cast::<*mut u8>()
                .write(core::ptr::null_mut());
            assert_eq!(context_shared_cell_payload_word_or_default(context.as_ptr().cast()), 3);
        }
    }

    #[test]
    fn returns_the_payloads_second_word() {
        let mut context = [MaybeUninit::<usize>::uninit(); (SHARED_CELL_SLOT_OFFSET + 8) / 8];
        let mut payload = [0x1234_5678_u32, 0x89ab_cdef];
        let cell = SharedCell {
            value: payload.as_mut_ptr() as usize,
            refcount: 1,
        };
        unsafe {
            context
                .as_mut_ptr()
                .cast::<u8>()
                .add(SHARED_CELL_SLOT_OFFSET)
                .cast::<*mut u8>()
                .write((&cell as *const SharedCell).cast_mut().cast::<u8>());
            assert_eq!(
                context_shared_cell_payload_word_or_default(context.as_ptr().cast()),
                0x89ab_cdef
            );
        }
    }
}
