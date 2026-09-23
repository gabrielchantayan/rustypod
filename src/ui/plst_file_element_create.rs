//! Creates and initializes a `'plst'` file element.
//!
//! - `plst_file_element_create` — original: `FUN_0817c0b0` @ `0x0817c0b0`
//!   (156 bytes: 152 instruction bytes plus the `"file"` literal-pool word
//!   at `0x0817c148`; 3 direct callers, all unconditional).

use core::{mem::MaybeUninit, ptr};

use crate::libc::memzero::memzero_aligned;
use super::navigation_mode::set_navigation_mode;
use super::plst_counted_string::plst_element_store_counted_string;

const FILE_TAG: u32 = 0x6669_6c65;
const OWNER_REGISTRY_WORD: usize = 0xf60 / 4;
const OWNER_NAVIGATION_SOURCE_WORD: usize = 0xf00 / 4;
const OWNER_LINK_TARGET_OFFSET: usize = 0xf04;
const ELEMENT_FLAGS_OFFSET: usize = 0x18c;
const REGISTRY_NAVIGATION_MODE_OFFSET: usize = 0x18;

type CreatePlstElement = unsafe extern "C" fn(*mut u8, u32, u32, u32, *mut *mut u8) -> i32;
type LinkPlstElement = unsafe extern "C" fn(*mut u8, *mut u8) -> i32;

#[cfg(target_os = "none")]
unsafe extern "C" fn retail_create_plst_element(
    registry: *mut u8,
    tag: u32,
    flags: u32,
    reserved: u32,
    element_out: *mut *mut u8,
) -> i32 {
    let create: CreatePlstElement = core::mem::transmute(0x0805_e36cusize);
    create(registry, tag, flags, reserved, element_out)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn retail_create_plst_element(
    _registry: *mut u8,
    _tag: u32,
    _flags: u32,
    _reserved: u32,
    _element_out: *mut *mut u8,
) -> i32 {
    panic!("plst_file_element_create requires factory 0x0805e36c")
}

#[cfg(target_os = "none")]
unsafe extern "C" fn retail_link_plst_element(element: *mut u8, target: *mut u8) -> i32 {
    let link: LinkPlstElement = core::mem::transmute(0x0805_bc34usize);
    link(element, target)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn retail_link_plst_element(_element: *mut u8, _target: *mut u8) -> i32 {
    panic!("plst_file_element_create requires linker 0x0805bc34")
}

/// Calls outside this one-function port.
///
/// `names.yaml` has no `ported` entry for factory `0x0805e36c` or linker
/// `0x0805bc34`. Their observed ABIs are retained without assigning either an
/// unsupported identity. Target builds call their retail addresses; host tests
/// install recorders.
#[derive(Clone, Copy)]
pub struct PlstFileElementCreateOps {
    pub create: CreatePlstElement,
    pub link: LinkPlstElement,
}

pub const DEFAULT_PLST_FILE_ELEMENT_CREATE_OPS: PlstFileElementCreateOps = PlstFileElementCreateOps {
    create: retail_create_plst_element,
    link: retail_link_plst_element,
};

pub static mut PLST_FILE_ELEMENT_CREATE_OPS: PlstFileElementCreateOps =
    DEFAULT_PLST_FILE_ELEMENT_CREATE_OPS;

#[inline(always)]
fn create_ops() -> PlstFileElementCreateOps {
    unsafe { ptr::read_volatile(ptr::addr_of!(PLST_FILE_ELEMENT_CREATE_OPS)) }
}

/// plst_file_element_create — original: `FUN_0817c0b0` @ `0x0817c0b0`
/// (156 bytes).
///
/// Raw ARM spans `0x0817c0b0..0x0817c14c`: instructions end at `pop
/// {r4,r5,pc}` @ `0x0817c144`, and the referenced `"file"` literal word at
/// `0x0817c148` belongs to this function; the next independently linked
/// function begins at `0x0817c14c`. Decoding its words finds four plain `bl`
/// instructions (`0x08037db8`, `0x0805e36c`, `0x08067274`, `0x0805bc34`) and
/// zero predicated `bl` instructions. Its three inbound calls are likewise
/// plain `bl` at `0x081799d8`, `0x0817b284`, and `0x0817b3a0`.
///
/// It clears a 512-byte counted-string buffer, asks the owner registry at
/// +0xf60 to construct a zero-flags `"file"` element, stores the empty
/// counted string, and links element+0x48 to owner+0xf04. If each status is
/// zero, it sets element+0x18c bit 7 and applies the low halfword of
/// `*(owner+0xf00)+0x18` as its navigation mode. The first argument is never
/// read by the ARM body.
///
/// Deliberate deviations: the IRAM memzero veneer `0x08037db8` is replaced by
/// the already ported `memzero_aligned`; its function pointer is loaded
/// volatile to retain a call. The factory and linker remain volatile dispatch
/// seams because neither has a ported ledger entry. The two already ported
/// PLST operations are called directly.
///
/// # Safety
///
/// `owner` must provide readable target-width words through +0xf60 and
/// +0xf04. On success its factory output must be a live writable `'plst'`
/// element through +0x18c; the registry and link target fields must be valid
/// for their respective retail callees.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.plst_file_element_create")]
#[inline(never)]
pub unsafe extern "C" fn plst_file_element_create(
    _context: *mut u8,
    owner: *mut u8,
    element_out: *mut *mut u8,
) -> i32 {
    let mut counted_words = MaybeUninit::<[u32; 128]>::uninit();
    let clear: unsafe extern "C" fn(*mut u8, usize) -> *mut u8 = memzero_aligned;
    ptr::read_volatile(ptr::addr_of!(clear))(counted_words.as_mut_ptr().cast(), 0x200);

    let owner_words = owner.cast::<u32>();
    let status = (create_ops().create)(
        owner_words.add(OWNER_REGISTRY_WORD).read() as usize as *mut u8,
        FILE_TAG,
        0,
        0,
        element_out,
    );
    if status != 0 {
        return status;
    }

    let element = element_out.read();
    let status = plst_element_store_counted_string(element, counted_words.as_ptr().cast());
    if status != 0 {
        return status;
    }

    let status = (create_ops().link)(element.add(0x48), owner.add(OWNER_LINK_TARGET_OFFSET));
    if status != 0 {
        return status;
    }

    let flags = element.add(ELEMENT_FLAGS_OFFSET).read();
    element.add(ELEMENT_FLAGS_OFFSET).write(flags | 0x80);
    let navigation_source = owner_words.add(OWNER_NAVIGATION_SOURCE_WORD).read() as usize as *mut u8;
    let mode = navigation_source.add(REGISTRY_NAVIGATION_MODE_OFFSET).cast::<u32>().read() & 0xffff;
    set_navigation_mode(element, mode);
    0
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::testing::{hints, try_map_u32_slab};
    use crate::util::string_pool::{StringPool, StringPoolStore, STRING_POOL_SEAM_LOCK, STRING_POOL_STORE};
    use core::ptr;
    use parking_lot::Mutex;

    const FIXTURE_LEN: usize = 0x3000;
    const ELEMENT_OFFSET: usize = 0x1800;
    const REGISTRY_OFFSET: usize = 0x2000;
    const NAVIGATION_SOURCE_OFFSET: usize = 0x2100;

    static OPS_LOCK: Mutex<()> = Mutex::new(());
    static mut FACTORY_STATUS: i32 = 0;
    static mut LINK_STATUS: i32 = 0;
    static mut FACTORY_CALLS: u32 = 0;
    static mut LINK_CALLS: u32 = 0;
    static mut OBSERVED_TAG: u32 = 0;
    static mut OBSERVED_REGISTRY: usize = 0;
    static mut FACTORY_ELEMENT: *mut u8 = ptr::null_mut();

    unsafe extern "C" fn record_create(registry: *mut u8, tag: u32, _flags: u32, _reserved: u32, out: *mut *mut u8) -> i32 {
        FACTORY_CALLS += 1;
        OBSERVED_REGISTRY = registry as usize;
        OBSERVED_TAG = tag;
        if FACTORY_STATUS == 0 {
            out.write(FACTORY_ELEMENT);
        }
        FACTORY_STATUS
    }

    unsafe extern "C" fn record_link(_element: *mut u8, _target: *mut u8) -> i32 {
        LINK_CALLS += 1;
        LINK_STATUS
    }

    unsafe extern "C" fn record_store(_pool: *mut StringPool, _data: *const u8, _len: u32, id_out: *mut i32) -> i32 {
        id_out.write(7);
        0
    }

    struct Reset {
        saved_store: StringPoolStore,
    }

    impl Drop for Reset {
        fn drop(&mut self) {
            unsafe {
                PLST_FILE_ELEMENT_CREATE_OPS = DEFAULT_PLST_FILE_ELEMENT_CREATE_OPS;
                STRING_POOL_STORE = self.saved_store;
            }
        }
    }

    fn fixture() -> Option<(*mut u8, *mut u8, *mut u8, *mut u8)> {
        let base = try_map_u32_slab(hints::PLST_FILE_ELEMENT_CREATE, FIXTURE_LEN)?;
        unsafe {
            base.write_bytes(0, FIXTURE_LEN);
            Some((base, base.add(ELEMENT_OFFSET), base.add(REGISTRY_OFFSET), base.add(NAVIGATION_SOURCE_OFFSET)))
        }
    }

    #[test]
    fn creates_links_and_marks_file_element() {
        let _ops_lock = OPS_LOCK.lock();
        let _pool_lock = STRING_POOL_SEAM_LOCK.lock().unwrap();
        let Some((owner, element, registry, navigation_source)) = fixture() else { return; };
        let _reset = unsafe { Reset { saved_store: STRING_POOL_STORE } };
        unsafe {
            FACTORY_STATUS = 0;
            LINK_STATUS = 0;
            FACTORY_CALLS = 0;
            LINK_CALLS = 0;
            FACTORY_ELEMENT = element;
            PLST_FILE_ELEMENT_CREATE_OPS = PlstFileElementCreateOps { create: record_create, link: record_link };
            STRING_POOL_STORE = record_store;
            owner.add(0xf60).cast::<u32>().write(registry as u32);
            owner.add(0xf00).cast::<u32>().write(navigation_source as u32);
            element.add(4).cast::<u32>().write(0x706c_7374);
            element.add(ELEMENT_FLAGS_OFFSET).write(0x12);
            navigation_source.add(0x18).cast::<u32>().write(2);
            let mut out = ptr::null_mut();
            assert_eq!(plst_file_element_create(ptr::null_mut(), owner, &mut out), 0);
            assert_eq!(out, element);
            assert_eq!(FACTORY_CALLS, 1);
            assert_eq!(OBSERVED_REGISTRY, registry as usize);
            assert_eq!(OBSERVED_TAG, FILE_TAG);
            assert_eq!(LINK_CALLS, 1);
            assert_eq!(element.add(ELEMENT_FLAGS_OFFSET).read(), 0x92);
        }
    }

    #[test]
    fn factory_failure_is_returned_without_following_calls() {
        let _ops_lock = OPS_LOCK.lock();
        let Some((owner, element, registry, navigation_source)) = fixture() else { return; };
        let _reset = unsafe { Reset { saved_store: STRING_POOL_STORE } };
        unsafe {
            FACTORY_STATUS = -42;
            LINK_CALLS = 0;
            FACTORY_ELEMENT = element;
            PLST_FILE_ELEMENT_CREATE_OPS = PlstFileElementCreateOps { create: record_create, link: record_link };
            owner.add(0xf60).cast::<u32>().write(registry as u32);
            owner.add(0xf00).cast::<u32>().write(navigation_source as u32);
            let mut out = ptr::null_mut();
            assert_eq!(plst_file_element_create(ptr::null_mut(), owner, &mut out), -42);
            assert_eq!(LINK_CALLS, 0);
        }
    }
}
