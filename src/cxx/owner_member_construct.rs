//! Owner-member constructor @ 0x0827c4e4 (FUN_0827c4e4).
//! True extent: 32 bytes, 28 code + 4 literal; next entry 0x0827c504.
//! Verified raw words: one outgoing plain BL to 0x0827c094, no predicated
//! BLs; two incoming plain BLs at 0x0827c6b4 and 0x0827c868, none predicated.
//! Construct the two-word base, replace its vtable with 0x089a8354, store
//! the owner word at +8, and return the base result (retail base preserves r0).
//! Deliberate deviations: none on target; host uses an injectable unported
//! base boundary. Owner is a target-width word, not a host-sized pointer.

pub type BaseConstruct = unsafe extern "C" fn(*mut u32) -> *mut u32;

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn missing_base(_: *mut u32) -> *mut u32 {
    panic!("install owner-member base constructor host seam")
}
#[cfg(not(target_os = "none"))]
pub static mut OWNER_MEMBER_BASE_CONSTRUCT: BaseConstruct = missing_base;

/// # Safety
/// `this` must point to at least three aligned writable target words and
/// satisfy the retail base constructor's preconditions. Owner is not dereferenced.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn owner_member_construct(this: *mut u32, owner: u32) -> *mut u32 {
    #[cfg(target_os = "none")]
    let base: BaseConstruct = unsafe { core::mem::transmute(0x0827_c094usize) };
    #[cfg(not(target_os = "none"))]
    let base = unsafe { core::ptr::addr_of!(OWNER_MEMBER_BASE_CONSTRUCT).read_volatile() };
    let object = unsafe { base(this) };
    unsafe {
        object.write_volatile(0x089a_8354);
        object.add(2).write_volatile(owner);
    }
    object
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    pub(crate) static LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());

    // Reference effects decoded independently from 0x0827c094's five words.
    pub(crate) unsafe extern "C" fn base(this: *mut u32) -> *mut u32 {
        unsafe {
            this.write(0x089a_8268);
            this.add(1).write(0);
        }
        this
    }

    #[test]
    fn initializes_exactly_three_words_and_preserves_return_address() {
        let _lock = LOCK.lock();
        let saved = unsafe { OWNER_MEMBER_BASE_CONSTRUCT };
        unsafe { OWNER_MEMBER_BASE_CONSTRUCT = base };
        for owner in [0, 1, 0x8000_0000, u32::MAX] {
            let mut words = [0xdead_beef; 5];
            let this = unsafe { words.as_mut_ptr().add(1) };
            assert_eq!(unsafe { owner_member_construct(this, owner) }, this);
            assert_eq!(words, [0xdead_beef, 0x089a_8354, 0, owner, 0xdead_beef]);
        }
        unsafe { OWNER_MEMBER_BASE_CONSTRUCT = saved };
    }
}
