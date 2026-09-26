//! `embedded_list_operation_dispatch` — original: `FUN_083dc06c` @
//! **0x083dc06c** (**56 bytes exactly**, `0x083dc06c..0x083dc0a3`; the
//! following `push {r1-r5, lr}` at `0x083dc0a4` starts a sibling).
//!
//! Raw A32 decoding finds one unconditional plain body `bl`, to the unported
//! list operation at **0x083cf1d8**, and no predicated body `bl`. Full-image
//! decoding finds two inbound plain `bl` sites (0x080d1f50, 0x080d200c) and
//! no predicated inbound direct call.
//!
//! # Algorithm
//!
//! Reads the target-width embedded-list pointer at `owner + 0x10`, obtains its
//! `+0x08` link, then calls the list operation with stack-local output, link,
//! and embedded-list words. The target reloads `owner + 0x10` after reading the
//! link; this port preserves that ordered pair of volatile reads.
//!
//! # Deliberate deviations
//!
//! The 0x083cf1d8 callee has no recovered semantic identity. Target builds call
//! its verified load address; host builds use a volatile replaceable seam. The
//! list and link remain `u32` target addresses so host pointer width cannot
//! alter the retail offsets.

pub type EmbeddedListOperation = unsafe extern "C" fn(*mut u32, *mut u32, *mut u32, *mut u32);

const EMBEDDED_LIST_OPERATION_ADDRESS: usize = 0x083c_f1d8;
const OWNER_EMBEDDED_LIST_WORD: usize = 0x10 / 4;
const LIST_LINK_WORD: usize = 0x08 / 4;

#[cfg(target_os = "none")]
unsafe extern "C" fn retail_embedded_list_operation(
    output: *mut u32,
    owner: *mut u32,
    link: *mut u32,
    embedded_list: *mut u32,
) {
    unsafe {
        core::mem::transmute::<usize, EmbeddedListOperation>(EMBEDDED_LIST_OPERATION_ADDRESS)(
            output,
            owner,
            link,
            embedded_list,
        )
    }
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_embedded_list_operation(
    _output: *mut u32,
    _owner: *mut u32,
    _link: *mut u32,
    _embedded_list: *mut u32,
) {
    panic!("embedded_list_operation_dispatch requires retail operation 0x083cf1d8")
}

#[cfg(target_os = "none")]
pub static mut EMBEDDED_LIST_OPERATION: EmbeddedListOperation = retail_embedded_list_operation;
#[cfg(not(target_os = "none"))]
pub static mut EMBEDDED_LIST_OPERATION: EmbeddedListOperation = missing_embedded_list_operation;

#[inline(always)]
fn embedded_list_operation() -> EmbeddedListOperation {
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(EMBEDDED_LIST_OPERATION)) }
}

/// Calls the retail list operation for the list embedded at `owner + 0x10`.
///
/// # Safety
///
/// `owner` and its target-width embedded-list and link pointers must be valid
/// for the reads and the unported operation's full ABI.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", unsafe(link_section = ".text.embedded_list_operation_dispatch"))]
#[inline(never)]
pub unsafe extern "C" fn embedded_list_operation_dispatch(owner: *mut u32) {
    let first_embedded_list = unsafe { owner.add(OWNER_EMBEDDED_LIST_WORD).read_volatile() };
    let mut link = unsafe { (first_embedded_list as *const u32).add(LIST_LINK_WORD).read_volatile() };
    let mut embedded_list = unsafe { owner.add(OWNER_EMBEDDED_LIST_WORD).read_volatile() };
    let mut output = embedded_list;
    unsafe { embedded_list_operation()(&mut output, owner, &mut link, &mut embedded_list) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{hints, try_map_u32_slab};
    use parking_lot::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static mut CALLS: u32 = 0;
    static mut ARGUMENT_WORDS: [u32; 4] = [0; 4];

    unsafe extern "C" fn record_operation(
        output: *mut u32,
        owner: *mut u32,
        link: *mut u32,
        embedded_list: *mut u32,
    ) {
        unsafe {
            CALLS += 1;
            ARGUMENT_WORDS = [
                output.read_volatile(),
                owner as usize as u32,
                link.read_volatile(),
                embedded_list.read_volatile(),
            ];
        }
    }

    #[test]
    fn forwards_normal_and_null_links_as_target_words() {
        let Some(slab) = try_map_u32_slab(hints::EMBEDDED_LIST_OPERATION_DISPATCH, 0x1000) else {
            return;
        };
        let _guard = TEST_LOCK.lock();
        unsafe {
            slab.write_bytes(0, 0x1000);
            let owner = slab.cast::<u32>();
            let list = slab.add(0x100).cast::<u32>();
            owner.add(OWNER_EMBEDDED_LIST_WORD).write_volatile(list as usize as u32);
            list.add(LIST_LINK_WORD).write_volatile(0x1234_5678);
            CALLS = 0;
            ARGUMENT_WORDS = [0; 4];
            EMBEDDED_LIST_OPERATION = record_operation;
            embedded_list_operation_dispatch(owner);
            assert_eq!(CALLS, 1);
            assert_eq!(ARGUMENT_WORDS, [list as usize as u32, owner as usize as u32, 0x1234_5678, list as usize as u32]);
            list.add(LIST_LINK_WORD).write_volatile(0);
            embedded_list_operation_dispatch(owner);
            assert_eq!(CALLS, 2);
            assert_eq!(ARGUMENT_WORDS, [list as usize as u32, owner as usize as u32, 0, list as usize as u32]);
            EMBEDDED_LIST_OPERATION = missing_embedded_list_operation;
        }
    }
}
