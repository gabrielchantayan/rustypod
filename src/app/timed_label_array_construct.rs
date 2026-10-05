//! Timed, labeled observable-array owner constructor.
//!
//! `FUN_081d15ec` @ 0x081d15ec: 96 bytes to the next real function at
//! 0x081d164c (88 code bytes and two vtable literals). Raw A32 decoding
//! finds three outbound plain BLs, zero predicated BLs; whole-image decoding
//! finds two inbound plain BLs at 0x0815e144 and 0x081d0ee0, zero predicated.
//! Installs the owner vtable, constructs the embedded array at +0x30,
//! installs its derived vtable, enables byte +0x40, clears +0x44, samples
//! Timer E into +4, clears +8/+0xc/+0x10/+0x20, and initializes the ten-byte
//! label at +0x24. Returns the array constructor's return minus 0x30.
//!
//! No target behavioral deviations. Unrecovered fields remain untouched.
//! Host builds require an injected label initializer (firmware resources
//! are unavailable); the existing timer port supplies its host counter.
//! Codegen review: LLVM proves the base constructor returns its input,
//! retaining the owner in r4 instead of subtracting from r0. The label seam
//! becomes BLX through a loaded function pointer; both ported calls and all
//! partial-initialization stores remain. Register allocation differs.
//!

use crate::cxx::observable_array::{observable_array_construct, ObservableArray};
use crate::drivers::timer::read_usec_timer_into;

pub const TIMED_LABEL_OWNER_VTABLE: u32 = 0x0898_dd00;
pub const TIMED_LABEL_ARRAY_VTABLE: u32 = 0x089a_58c8;

/// Firmware helper uses a lazily cached resource provider, key 0x4474546d,
/// resource 0x80aa, then tail-calls 0x08037db0 with (label, resource, 10).
#[cfg(target_os = "none")]
unsafe extern "C" fn firmware_label_initialize(owner: *mut u8, label: *mut u8) {
    core::mem::transmute::<usize, unsafe extern "C" fn(*mut u8, *mut u8)>(0x081d_11ec)(owner, label);
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn unavailable_label_initialize(_: *mut u8, _: *mut u8) {
    panic!("timed label initialization requires firmware resources or a host seam");
}

#[cfg(target_os = "none")]
pub static mut TIMED_LABEL_INITIALIZE: unsafe extern "C" fn(*mut u8, *mut u8) = firmware_label_initialize;
#[cfg(not(target_os = "none"))]
pub static mut TIMED_LABEL_INITIALIZE: unsafe extern "C" fn(*mut u8, *mut u8) = unavailable_label_initialize;

/// Construct a 72-byte target-layout owner; does not clear padding or the
/// unrecovered +0x14..+0x1f words.
///
/// # Safety
/// `this` must name 72 writable, word-aligned bytes. The label seam must
/// implement the firmware helper's ABI and must not invalidate the object.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn timed_label_array_construct(this: *mut u8) -> *mut u8 {
    construct_with_label(this, core::ptr::read_volatile(core::ptr::addr_of!(TIMED_LABEL_INITIALIZE)))
}

#[inline(always)]
unsafe fn construct_with_label(this: *mut u8, initialize: unsafe extern "C" fn(*mut u8, *mut u8)) -> *mut u8 {
    this.cast::<u32>().write_volatile(TIMED_LABEL_OWNER_VTABLE);
    let array = observable_array_construct(this.add(0x30).cast::<ObservableArray>()).cast::<u8>();
    array.cast::<u32>().write_volatile(TIMED_LABEL_ARRAY_VTABLE);
    array.add(0x10).write_volatile(1);
    array.add(0x14).cast::<u32>().write_volatile(0);
    let owner = array.sub(0x30);
    read_usec_timer_into(owner.add(4).cast());
    owner.add(8).cast::<u32>().write_volatile(0);
    owner.add(12).cast::<u32>().write_volatile(0);
    owner.add(16).cast::<u32>().write_volatile(0);
    owner.add(32).cast::<u32>().write_volatile(0);
    initialize(owner, owner.add(36));
    owner
}

#[cfg(test)]
mod tests {
    use super::*;

    unsafe extern "C" fn label(_: *mut u8, dst: *mut u8) {
        core::ptr::copy_nonoverlapping(b"0123456789".as_ptr(), dst, 10);
    }

    #[test]
    fn initializes_members_without_clearing_unowned_bytes() {
        for sentinel in [0xa5u8, 0xff, 0] {
            let mut words = [u32::from_ne_bytes([sentinel; 4]); 20];
            let base = words.as_mut_ptr().cast::<u8>();
            unsafe {
                assert_eq!(construct_with_label(base.add(4), label), base.add(4));
                assert_eq!(words[0], u32::from_ne_bytes([sentinel; 4]));
                assert_eq!(words[19], u32::from_ne_bytes([sentinel; 4]));
                assert_eq!(words[1], TIMED_LABEL_OWNER_VTABLE);
                assert_eq!(&words[3..6], &[0; 3]);
                assert_eq!(&words[6..9], &[u32::from_ne_bytes([sentinel; 4]); 3]);
                assert_eq!(words[9], 0);
                assert_eq!(core::slice::from_raw_parts(base.add(40), 10), b"0123456789");
                assert_eq!(core::slice::from_raw_parts(base.add(50), 2), &[sentinel; 2]);
                assert_eq!(words[13], TIMED_LABEL_ARRAY_VTABLE);
                assert_eq!(&words[14..17], &[0; 3]);
                assert_eq!(base.add(68).read(), 1);
                assert_eq!(core::slice::from_raw_parts(base.add(69), 3), &[sentinel; 3]);
                assert_eq!(words[18], 0);
            }
        }
    }
}
