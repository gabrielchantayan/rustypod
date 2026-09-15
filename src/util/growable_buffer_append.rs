//! growable_buffer_append — original: `FUN_08143f38` @ `0x08143f38` (52
//! bytes: 13 ARM words; next function starts at `0x08143f6c`).
//!
//! **Verified call count:** five direct `bl` call sites: four unconditional
//! and one predicated. The body has one outbound `bl`, to the unported
//! capacity helper at `0x08143f6c`; its terminal `b 0x08037db0` reaches the
//! ported ADS `__rt_memcpy` veneer.
//!
//! Reads the current logical length, grows the three-word `{data, length,
//! capacity}` buffer to cover `length + len`, then appends `len` source bytes
//! at the (possibly reallocated) data base plus the saved old length.
//!
//! Deliberate deviations: the terminal branch is a normal Rust call to the
//! ported `__rt_memcpy`, and the unported capacity helper is an address seam.
//! The buffer remains target-width words on every architecture so its physical
//! ARM offsets are not widened by host pointers.

/// ABI of the unported capacity helper at `0x08143f6c`.
pub type GrowableBufferEnsureCapacity = unsafe extern "C" fn(*mut u32, u32);

#[cfg(target_os = "none")]
unsafe fn ensure_capacity(buffer: *mut u32, required_length: u32) {
    let ensure: GrowableBufferEnsureCapacity = core::mem::transmute(0x0814_3f6cusize);
    ensure(buffer, required_length);
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_ensure_capacity(_buffer: *mut u32, _required_length: u32) {}

#[cfg(not(target_os = "none"))]
static mut ENSURE_CAPACITY: GrowableBufferEnsureCapacity = missing_ensure_capacity;

#[cfg(not(target_os = "none"))]
unsafe fn ensure_capacity(buffer: *mut u32, required_length: u32) {
    ENSURE_CAPACITY(buffer, required_length);
}

/// Appends bytes to a target-width growable buffer.
///
/// # Safety
/// `buffer` must address three readable target words `{data, length, capacity}`.
/// The capacity helper and the resulting `data + old_length` range must accept
/// `len` bytes from `source`; as in retailOS, no NULL or overflow checks occur.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn growable_buffer_append(buffer: *mut u32, source: *const u8, len: u32) {
    let old_length = buffer.add(1).read_volatile();
    ensure_capacity(buffer, old_length.wrapping_add(len));
    let data = buffer.read_volatile() as usize as *mut u8;
    crate::libc::rt_memcpy::__rt_memcpy(data.add(old_length as usize), source, len as usize);
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::testing::{hints, note_missing_u32_fixture, try_map_u32_slab};
    use core::ptr::{addr_of_mut, null};
    use parking_lot::Mutex;
    use std::sync::LazyLock;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static FIXTURE: LazyLock<Option<usize>> = LazyLock::new(|| {
        try_map_u32_slab(hints::GROWABLE_BUFFER_APPEND, 0x1000).map(|slab| slab as usize)
    });
    static mut ENSURE_CALL: (*mut u32, u32) = (core::ptr::null_mut(), 0);
    static mut REPLACEMENT_DATA: *mut u8 = core::ptr::null_mut();

    unsafe extern "C" fn recording_ensure_capacity(buffer: *mut u32, required_length: u32) {
        ENSURE_CALL = (buffer, required_length);
        if !REPLACEMENT_DATA.is_null() {
            buffer.write(REPLACEMENT_DATA as u32);
        }
        buffer.add(1).write(required_length);
    }

    struct EnsureReset(GrowableBufferEnsureCapacity);

    impl Drop for EnsureReset {
        fn drop(&mut self) {
            unsafe { ENSURE_CAPACITY = self.0; }
        }
    }

    unsafe fn install_recording_ensure() -> EnsureReset {
        let previous = ENSURE_CAPACITY;
        ENSURE_CAPACITY = recording_ensure_capacity;
        EnsureReset(previous)
    }

    #[test]
    fn grows_then_appends_at_the_saved_old_length_after_reallocation() {
        let _guard = TEST_LOCK.lock();
        let Some(slab) = *FIXTURE else {
            note_missing_u32_fixture(module_path!());
            return;
        };
        let slab = slab as *mut u8;
        let _reset = unsafe { install_recording_ensure() };
        let old_data = unsafe { slab.add(0x100) };
        let new_data = unsafe { slab.add(0x200) };
        let mut buffer = [old_data as u32, 3, 3];
        let source = [0x81, 0x00, 0xfe, 0x19];
        unsafe {
            old_data.copy_from_nonoverlapping([0x11, 0x22, 0x33].as_ptr(), 3);
            new_data.write_bytes(0xa5, 16);
            ENSURE_CALL = (core::ptr::null_mut(), 0);
            REPLACEMENT_DATA = new_data;
            growable_buffer_append(addr_of_mut!(buffer).cast(), source.as_ptr(), source.len() as u32);
            REPLACEMENT_DATA = core::ptr::null_mut();
            assert_eq!(ENSURE_CALL, (addr_of_mut!(buffer).cast(), 7));
            assert_eq!(buffer[1], 7);
            assert_eq!(&*new_data.add(3).cast::<[u8; 4]>(), &source);
            assert_eq!(*new_data, 0xa5);
        }
    }

    #[test]
    fn zero_length_still_updates_length_and_accepts_a_null_source() {
        let _guard = TEST_LOCK.lock();
        let Some(slab) = *FIXTURE else {
            note_missing_u32_fixture(module_path!());
            return;
        };
        let slab = slab as *mut u8;
        let _reset = unsafe { install_recording_ensure() };
        let data = unsafe { slab.add(0x300) };
        let mut buffer = [data as u32, 9, 16];
        unsafe {
            ENSURE_CALL = (core::ptr::null_mut(), 0);
            REPLACEMENT_DATA = core::ptr::null_mut();
            growable_buffer_append(addr_of_mut!(buffer).cast(), null(), 0);
            assert_eq!(ENSURE_CALL, (addr_of_mut!(buffer).cast(), 9));
            assert_eq!(buffer[1], 9);
        }
    }
}
