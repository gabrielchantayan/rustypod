//! OpenSSL's `i2a_ASN1_OBJECT` BIO printer.
//!
//! Port: `i2a_asn1_object` — `FUN_082d3528` @ **0x082d3528** (108 bytes,
//! `0x082d3528..0x082d3594`; the next separately linked function starts at
//! `0x082d359c`, after the `"NULL\0"` literal at `0x082d3594`). Raw ARM
//! decoding finds five unconditional inbound `bl` calls at `0x080511a4`,
//! `0x080758c0`, `0x08078204`, `0x0809c040`, and `0x080aed20`; there are no
//! predicated `bl`, `blx`, or direct tail-`b` callers.
//!
//! # Algorithm
//!
//! A null object writes the four-byte `"NULL"` literal to the BIO and returns
//! that write's result. Otherwise it renders the object as a numeric OID into
//! an 80-byte stack buffer through `OBJ_obj2txt`, caps only values above 80,
//! writes exactly that many bytes through `BIO_write`, and returns the rendered
//! length rather than the write result.
//!
//! # Deliberate deviations
//!
//! `OBJ_obj2txt` and `BIO_write` remain unported and are volatile host seams;
//! firmware builds call their verified retailOS addresses directly. The signed
//! length is intentionally passed through unchanged, including a negative
//! renderer result, as the ARM register flow does.

#[cfg(not(target_os = "none"))]
use core::ptr;
use core::mem::MaybeUninit;

use crate::crypto::bio_ctrl::Bio;
use crate::crypto::obj_dat::Asn1Object;

pub type ObjObj2TxtFn = unsafe extern "C" fn(*mut u8, i32, *const Asn1Object, i32) -> i32;
pub type BioWriteFn = unsafe extern "C" fn(*mut Bio, *const u8, i32) -> i32;

const OBJ_OBJ2TXT_ADDRESS: usize = 0x0805_f110;
const BIO_WRITE_ADDRESS: usize = 0x0803_da74;

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_obj_obj2txt(
    _output: *mut u8,
    _capacity: i32,
    _object: *const Asn1Object,
    _no_name: i32,
) -> i32 {
    panic!("i2a_asn1_object requires OBJ_obj2txt at 0x0805f110")
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_bio_write(_bio: *mut Bio, _data: *const u8, _len: i32) -> i32 {
    panic!("i2a_asn1_object requires BIO_write at 0x0803da74")
}

#[cfg(not(target_os = "none"))]
pub static mut OBJ_OBJ2TXT: ObjObj2TxtFn = missing_obj_obj2txt;
#[cfg(not(target_os = "none"))]
pub static mut BIO_WRITE: BioWriteFn = missing_bio_write;

#[inline(always)]
unsafe fn obj_obj2txt(output: *mut u8, capacity: i32, object: *const Asn1Object) -> i32 {
    #[cfg(target_os = "none")]
    {
        let render: ObjObj2TxtFn = unsafe { core::mem::transmute(OBJ_OBJ2TXT_ADDRESS) };
        unsafe { render(output, capacity, object, 0) }
    }
    #[cfg(not(target_os = "none"))]
    {
        let render = unsafe { ptr::read_volatile(ptr::addr_of!(OBJ_OBJ2TXT)) };
        unsafe { render(output, capacity, object, 0) }
    }
}

#[inline(always)]
unsafe fn bio_write(bio: *mut Bio, data: *const u8, len: i32) -> i32 {
    #[cfg(target_os = "none")]
    {
        let write: BioWriteFn = unsafe { core::mem::transmute(BIO_WRITE_ADDRESS) };
        unsafe { write(bio, data, len) }
    }
    #[cfg(not(target_os = "none"))]
    {
        let write = unsafe { ptr::read_volatile(ptr::addr_of!(BIO_WRITE)) };
        unsafe { write(bio, data, len) }
    }
}

#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn i2a_asn1_object(bio: *mut Bio, object: *const Asn1Object) -> i32 {
    if object.is_null() {
        return unsafe { bio_write(bio, c"NULL".as_ptr().cast(), 4) };
    }

    let mut text = [MaybeUninit::<u8>::uninit(); 80];
    let mut length = unsafe { obj_obj2txt(text.as_mut_ptr().cast(), text.len() as i32, object) };
    if length > text.len() as i32 {
        length = text.len() as i32;
    }
    unsafe { bio_write(bio, text.as_ptr().cast(), length) };
    length
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex;

    static SEAM_LOCK: Mutex<()> = Mutex::new(());
    static mut RENDER_RESULT: i32 = 0;
    static mut WRITTEN: [u8; 80] = [0; 80];
    static mut WRITTEN_LEN: i32 = 0;

    unsafe extern "C" fn render(
        output: *mut u8,
        capacity: i32,
        _object: *const Asn1Object,
        no_name: i32,
    ) -> i32 {
        assert_eq!(capacity, 80);
        assert_eq!(no_name, 0);
        unsafe { core::ptr::write_bytes(output, b'x', 80) };
        unsafe { RENDER_RESULT }
    }

    unsafe extern "C" fn write(_bio: *mut Bio, data: *const u8, len: i32) -> i32 {
        unsafe {
            WRITTEN_LEN = len;
            if len > 0 {
                WRITTEN[..len as usize].copy_from_slice(core::slice::from_raw_parts(data, len as usize));
            }
        }
        -17
    }

    struct Seams {
        obj_obj2txt: ObjObj2TxtFn,
        bio_write: BioWriteFn,
    }

    impl Seams {
        unsafe fn install() -> Self {
            unsafe {
                let seams = Self { obj_obj2txt: OBJ_OBJ2TXT, bio_write: BIO_WRITE };
                OBJ_OBJ2TXT = render;
                BIO_WRITE = write;
                WRITTEN_LEN = 0;
                seams
            }
        }
    }

    impl Drop for Seams {
        fn drop(&mut self) {
            unsafe {
                OBJ_OBJ2TXT = self.obj_obj2txt;
                BIO_WRITE = self.bio_write;
            }
        }
    }

    #[test]
    fn null_object_returns_bio_write_result() {
        let _lock = SEAM_LOCK.lock();
        let _seams = unsafe { Seams::install() };
        assert_eq!(unsafe { i2a_asn1_object(ptr::null_mut(), ptr::null()) }, -17);
        assert_eq!(unsafe { WRITTEN_LEN }, 4);
        assert_eq!(unsafe { &WRITTEN[..4] }, b"NULL");
    }

    #[test]
    fn oversized_render_is_capped_and_write_result_is_ignored() {
        let _lock = SEAM_LOCK.lock();
        let _seams = unsafe { Seams::install() };
        unsafe { RENDER_RESULT = 123 };
        assert_eq!(unsafe { i2a_asn1_object(ptr::null_mut(), 1usize as *const Asn1Object) }, 80);
        assert_eq!(unsafe { WRITTEN_LEN }, 80);
        assert_eq!(unsafe { WRITTEN }, [b'x'; 80]);
    }

    #[test]
    fn negative_render_length_reaches_bio_write_unchanged() {
        let _lock = SEAM_LOCK.lock();
        let _seams = unsafe { Seams::install() };
        unsafe { RENDER_RESULT = -3 };
        assert_eq!(unsafe { i2a_asn1_object(ptr::null_mut(), 1usize as *const Asn1Object) }, -3);
        assert_eq!(unsafe { WRITTEN_LEN }, -3);
    }
}
