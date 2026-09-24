//! OpenSSL's `PKCS7_set_detached`.
//!
//! `pkcs7_set_detached` — retailOS `FUN_0805fa50` @ 0x0805fa50 (212 bytes,
//! 0x0805fa50..0x0805fb23; the next separately linked function begins at
//! 0x0805fb24). Raw A32 decoding finds exactly three inbound plain `bl` call
//! sites and no predicated `bl` calls.
//!
//! For signed PKCS7 messages (`NID_pkcs7_signed` = 22), mode 1 records the
//! requested detached state and, when detaching a data content (`NID_pkcs7_data`
//! = 21), frees that inner content and clears its slot. Mode 2 queries whether
//! the signed content slot is absent and stores/returns that boolean. Other
//! types record `ERR_LIB_PKCS7` error `(0x21, 0x68, 0x68, 0, 0)`; unsupported
//! modes record `(0x21, 0x68, 0x6e, 0, 0)`. Both return zero.
//!
//! Deliberate deviation: `PKCS7_free` @ 0x0803a240 is not ported, so target
//! builds dispatch to its fixed address and host tests install a volatile seam.

use core::ptr;

use crate::crypto::obj_dat::{obj_obj2nid, Asn1Object};
use crate::kernel::diag_ring_record::diag_ring_record;

const NID_PKCS7_DATA: i32 = 21;
const NID_PKCS7_SIGNED: i32 = 22;
const DETACHED_WORD: usize = 3;
const TYPE_WORD: usize = 4;
const CONTENT_WORD: usize = 5;

/// Target-width `PKCS7` words used by `PKCS7_set_detached`.
///
/// The union starts at +0x14, so the signed-content pointer is word 5.
#[repr(C)]
pub struct Pkcs7 {
    words: [u32; 6],
}

type Pkcs7Free = unsafe extern "C" fn(*mut Pkcs7);

#[cfg(target_os = "none")]
#[inline(always)]
unsafe fn pkcs7_free(value: *mut Pkcs7) {
    let worker: Pkcs7Free = unsafe { core::mem::transmute(0x0803_a240usize) };
    unsafe { worker(value) };
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_pkcs7_free(_value: *mut Pkcs7) {
    panic!("pkcs7_set_detached requires PKCS7_free at 0x0803a240")
}

#[cfg(not(target_os = "none"))]
static mut PKCS7_FREE: Pkcs7Free = missing_pkcs7_free;

#[cfg(not(target_os = "none"))]
#[inline(always)]
unsafe fn pkcs7_free(value: *mut Pkcs7) {
    let worker = unsafe { ptr::read_volatile(ptr::addr_of!(PKCS7_FREE)) };
    unsafe { worker(value) };
}

#[inline(always)]
unsafe fn word_pointer(value: *mut Pkcs7, index: usize) -> *mut Pkcs7 {
    unsafe { ptr::read_volatile(ptr::addr_of!((*value).words[index])) as usize as *mut Pkcs7 }
}

/// pkcs7_set_detached — retailOS `FUN_0805fa50` @ 0x0805fa50 (212 bytes).
///
/// See the module header for the raw extent, verified inbound call count, and
/// the `PKCS7_free` seam deviation.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn pkcs7_set_detached(message: *mut Pkcs7, mode: i32, detached: i32) -> i32 {
    let kind = unsafe { obj_obj2nid(word_pointer(message, TYPE_WORD).cast::<Asn1Object>()) };

    if mode == 1 && kind == NID_PKCS7_SIGNED {
        unsafe { ptr::addr_of_mut!((*message).words[DETACHED_WORD]).write_volatile(detached as u32) };
        if detached == 0 {
            return 0;
        }

        let signed = unsafe { word_pointer(message, CONTENT_WORD) };
        let content = unsafe { word_pointer(signed, CONTENT_WORD) };
        if unsafe { obj_obj2nid(word_pointer(content, TYPE_WORD).cast::<Asn1Object>()) } == NID_PKCS7_DATA {
            unsafe { pkcs7_free(content) };
            unsafe { ptr::addr_of_mut!((*signed).words[CONTENT_WORD]).write_volatile(0) };
        }
        return detached;
    }

    if mode == 2 && kind == NID_PKCS7_SIGNED {
        let signed = unsafe { word_pointer(message, CONTENT_WORD) };
        let detached = unsafe { word_pointer(signed, CONTENT_WORD).is_null() } as i32;
        unsafe { ptr::addr_of_mut!((*message).words[DETACHED_WORD]).write_volatile(detached as u32) };
        return detached;
    }

    let reason = if mode == 1 || mode == 2 { 0x68 } else { 0x6e };
    unsafe { diag_ring_record(0x21, 0x68, reason, 0, 0) };
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{hints, try_map_u32_slab};
    use core::sync::atomic::{AtomicUsize, Ordering};
    use parking_lot::Mutex;

    static PKCS7_FREE_TEST_LOCK: Mutex<()> = Mutex::new(());
    static FREED: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn record_free(value: *mut Pkcs7) {
        FREED.store(value as usize, Ordering::SeqCst);
    }

    unsafe fn object_at(slab: *mut u8, offset: usize, nid: i32) -> *mut Asn1Object {
        let object = unsafe { slab.add(offset).cast::<Asn1Object>() };
        unsafe {
            object.write(Asn1Object {
                sn: ptr::null(), ln: ptr::null(), nid, length: 0, data: ptr::null(), flags: 0,
            });
        }
        object
    }

    #[test]
    fn handles_detach_query_and_rejected_modes_at_target_offsets() {
        let _lock = PKCS7_FREE_TEST_LOCK.lock();
        let Some(slab) = try_map_u32_slab(hints::PKCS7_SET_DETACHED, 4096) else { return };
        unsafe { ptr::write_bytes(slab, 0, 4096) };

        let message = slab.cast::<Pkcs7>();
        let signed = unsafe { slab.add(0x40).cast::<Pkcs7>() };
        let data = unsafe { slab.add(0x80).cast::<Pkcs7>() };
        let signed_type = unsafe { object_at(slab, 0x100, NID_PKCS7_SIGNED) };
        let data_type = unsafe { object_at(slab, 0x180, NID_PKCS7_DATA) };
        unsafe {
            (*message).words[TYPE_WORD] = signed_type as usize as u32;
            (*message).words[CONTENT_WORD] = signed as usize as u32;
            (*signed).words[CONTENT_WORD] = data as usize as u32;
            (*data).words[TYPE_WORD] = data_type as usize as u32;
            PKCS7_FREE = record_free;
        }
        FREED.store(0, Ordering::SeqCst);

        assert_eq!(unsafe { pkcs7_set_detached(message, 1, 7) }, 7);
        assert_eq!(unsafe { (*message).words[DETACHED_WORD] }, 7);
        assert_eq!(unsafe { (*signed).words[CONTENT_WORD] }, 0);
        assert_eq!(FREED.load(Ordering::SeqCst), data as usize);

        assert_eq!(unsafe { pkcs7_set_detached(message, 2, 0) }, 1);
        assert_eq!(unsafe { (*message).words[DETACHED_WORD] }, 1);
        unsafe { (*signed).words[CONTENT_WORD] = data as usize as u32 };
        assert_eq!(unsafe { pkcs7_set_detached(message, 2, 0) }, 0);

        assert_eq!(unsafe { pkcs7_set_detached(message, 3, 0) }, 0);
        assert_eq!(unsafe { (*message).words[DETACHED_WORD] }, 0);
        unsafe { PKCS7_FREE = missing_pkcs7_free };
    }
}
