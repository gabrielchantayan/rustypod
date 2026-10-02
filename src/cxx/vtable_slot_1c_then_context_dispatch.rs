//! Returned-object context dispatch @ 0x0827c2a4 (FUN_0827c2a4).
//! True extent: 48 bytes, ending before the real entry at 0x0827c2d4;
//! Ghidra's 80-byte extent includes the following function and another prologue.
//! Raw words verify zero outgoing plain or predicated BLs, one BLX through
//! vtable slot +0x1c, and a tail B to 0x0827c668. Two incoming plain BLs
//! at 0x08159a8c and 0x08159b34; zero incoming predicated BLs.
//!
//! Obtain an object through receiver.vtable[7], preserving three argument
//! words across the virtual call, then pass that object and the words to
//! the unported context operation at 0x0827c668. Preserve its r0 result.
//! That boundary loads +0x88/+0x8c and calls 0x08215bf4; neither boundary
//! has a names.yaml identity, so their domain-specific meaning is not guessed.
//! Deliberate deviations: the tail branch is expressed as a final typed call;
//! host vtables use pointer-width cells and an injectable retail boundary.

pub type ContextDispatch = unsafe extern "C" fn(*mut u8, u32, u32, u32) -> u32;
type GetContext = unsafe extern "C" fn(*mut u8) -> *mut u8;

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_context(_: *mut u8, _: u32, _: u32, _: u32) -> u32 {
    panic!("install returned-object context dispatch host seam")
}
#[cfg(not(target_os = "none"))]
pub static mut RETURNED_OBJECT_CONTEXT_DISPATCH: ContextDispatch = missing_context;

/// # Safety
/// `receiver` must contain a readable vtable pointer with a valid slot +0x1c.
/// Its returned object and all arguments must satisfy the retail operation
/// at 0x0827c668 (including readable target words at +0x88 and +0x8c).
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn vtable_slot_1c_then_context_dispatch(
    receiver: *mut u8, operation: u32, first_word: u32, second_word: u32,
) -> u32 {
    let vtable = unsafe { (receiver as *const *const usize).read() };
    let entry = unsafe { vtable.add(0x1c / 4).read() };
    let get_context: GetContext = unsafe { core::mem::transmute(entry) };
    let context = unsafe { get_context(receiver) };
    #[cfg(target_os = "none")]
    let dispatch: ContextDispatch = unsafe { core::mem::transmute(0x0827_c668usize) };
    #[cfg(not(target_os = "none"))]
    let dispatch = unsafe { core::ptr::addr_of!(RETURNED_OBJECT_CONTEXT_DISPATCH).read_volatile() };
    unsafe { dispatch(context, operation, first_word, second_word) }
}

#[cfg(test)]
mod tests {
    use super::*;
    static LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());

    #[repr(C)]
    struct Receiver {
        vtable: *const usize,
        context: *mut u8,
        acquisitions: u32,
    }

    unsafe extern "C" fn acquire(receiver: *mut u8) -> *mut u8 {
        let receiver = unsafe { &mut *receiver.cast::<Receiver>() };
        receiver.acquisitions += 1;
        // A virtual acquisition can invalidate the original object's vtable.
        receiver.vtable = core::ptr::null();
        receiver.context
    }

    unsafe extern "C" fn update(context: *mut u8, operation: u32, first: u32, second: u32) -> u32 {
        let words = context.cast::<u32>();
        let value = unsafe { words.read() }.wrapping_add(first).wrapping_sub(second);
        unsafe { words.write(value); words.add(1).write(operation); }
        value ^ operation
    }

    #[test]
    fn acquired_context_survives_receiver_invalidation_and_word_wraparound() {
        let _lock = LOCK.lock();
        let saved = unsafe { RETURNED_OBJECT_CONTEXT_DISPATCH };
        unsafe { RETURNED_OBJECT_CONTEXT_DISPATCH = update };
        let mut vtable = [0usize; 8];
        vtable[7] = acquire as usize;
        for (operation, first, second) in [(0, 0, 0), (1, u32::MAX, 1), (u32::MAX, 1, u32::MAX)] {
            let mut context = [0xdead_beef; 36];
            context[1] = u32::MAX;
            let mut receiver = Receiver {
                vtable: vtable.as_ptr(), context: unsafe { context.as_mut_ptr().add(1).cast() }, acquisitions: 0,
            };
            let result = unsafe {
                vtable_slot_1c_then_context_dispatch((&mut receiver as *mut Receiver).cast(), operation, first, second)
            };
            let expected = u32::MAX.wrapping_add(first).wrapping_sub(second);
            assert_eq!(result, expected ^ operation);
            assert_eq!(receiver.acquisitions, 1);
            assert!(receiver.vtable.is_null());
            assert_eq!(&context[..3], &[0xdead_beef, expected, operation]);
            assert!(context[3..].iter().all(|&word| word == 0xdead_beef));
        }
        unsafe { RETURNED_OBJECT_CONTEXT_DISPATCH = saved };
    }
}
