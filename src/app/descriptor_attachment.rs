//! Links a matching descriptor to an owner and reports the attachment.
//!
//! - `attach_matching_descriptor` — original: `FUN_0803c034` @
//!   `0x0803c034` (184 bytes, including literal event key `0x61706c69` at
//!   `0x0803c0ec`; 8 direct `bl` call sites: 5 unconditional and 3 `blne`).

use core::ptr;

/// Owner word containing the descriptor type used for the exact match.
const OWNER_DESCRIPTOR_TYPE_WORD: usize = 0x0c / core::mem::size_of::<u32>();
/// Owner word containing the list searched for an existing descriptor link.
const OWNER_DUPLICATE_LIST_WORD: usize = 0x40 / core::mem::size_of::<u32>();
/// Word containing the owner flag byte at byte index one.
const OWNER_FLAGS_WORD: usize = 0x18c / core::mem::size_of::<u32>();
const OWNER_DUPLICATE_CHECK_FLAG: u8 = 0x10;
/// Owner word accumulating descriptor pending flags after allocation is tried.
const OWNER_PENDING_FLAGS_WORD: usize = 0x1a8 / core::mem::size_of::<u32>();

const DESCRIPTOR_TYPE_WORD: usize = 0;
const DESCRIPTOR_LINK_HEAD_WORD: usize = 0x24 / core::mem::size_of::<u32>();
const DESCRIPTOR_PENDING_FLAGS_WORD: usize = 0xbc / core::mem::size_of::<u32>();

const LINK_OWNER_WORD: usize = 0;
const LINK_INITIAL_PREVIOUS_WORD: usize = 4;
const LINK_DESCRIPTOR_WORD: usize = 8;
const LINK_PREVIOUS_WORD: usize = 9;
const LINK_NEXT_WORD: usize = 10;
const OWNER_TAGGED_LIST_OFFSET: usize = 0x48;
/// Literal pool word at 0x0803c0ec. Its semantic identity is unrecovered.
const ATTACH_NOTIFY_TAG: u32 = 0x6170_6c69;

/// ABI of unported duplicate finder `FUN_080daa7c`.
pub type DescriptorAttachmentFindDuplicate = unsafe extern "C" fn(*mut u8, *mut u32) -> *mut u32;
/// ABI of unported link allocator `FUN_0808e228`.
pub type DescriptorAttachmentAllocateLink = unsafe extern "C" fn(*mut u32) -> *mut u32;
/// ABI of unported link initializer `FUN_08093dfc`.
pub type DescriptorAttachmentInitializeLink = unsafe extern "C" fn(*mut u32, *mut u8, u32);
/// ABI of unported tagged-list walker `FUN_08066bb8`.
pub type DescriptorAttachmentNotify = unsafe extern "C" fn(*mut u8, u32, *mut u32, u32, u32);

#[cfg(target_os = "none")]
unsafe extern "C" fn retail_find_duplicate(list: *mut u8, descriptor: *mut u32) -> *mut u32 {
    let find_duplicate: DescriptorAttachmentFindDuplicate = core::mem::transmute(0x080d_aa7cusize);
    find_duplicate(list, descriptor)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn retail_find_duplicate(_list: *mut u8, _descriptor: *mut u32) -> *mut u32 {
    ptr::null_mut()
}

#[cfg(target_os = "none")]
unsafe extern "C" fn retail_allocate_link(owner: *mut u32) -> *mut u32 {
    let allocate_link: DescriptorAttachmentAllocateLink = core::mem::transmute(0x0808_e228usize);
    allocate_link(owner)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn retail_allocate_link(_owner: *mut u32) -> *mut u32 {
    ptr::null_mut()
}

#[cfg(target_os = "none")]
unsafe extern "C" fn retail_initialize_link(link: *mut u32, context: *mut u8, enabled: u32) {
    let initialize_link: DescriptorAttachmentInitializeLink = core::mem::transmute(0x0809_3dfcusize);
    initialize_link(link, context, enabled)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn retail_initialize_link(_link: *mut u32, _context: *mut u8, _enabled: u32) {}

#[cfg(target_os = "none")]
unsafe extern "C" fn retail_notify(
    list: *mut u8,
    tag: u32,
    context: *mut u32,
    flags: u32,
    stack_arg: u32,
) {
    let notify: DescriptorAttachmentNotify = core::mem::transmute(0x0806_6bb8usize);
    notify(list, tag, context, flags, stack_arg)
}

#[cfg(not(target_os = "none"))]
unsafe extern "C" fn retail_notify(
    _list: *mut u8,
    _tag: u32,
    _context: *mut u32,
    _flags: u32,
    _stack_arg: u32,
) {}

/// Calls outside this one-function port.
///
/// `names.yaml` has no `ported` entry for `FUN_080daa7c`, `FUN_0808e228`,
/// `FUN_08093dfc`, or `FUN_08066bb8`; target builds retain those retail
/// boundaries while host tests install recorders.
#[derive(Clone, Copy)]
pub struct DescriptorAttachmentOps {
    pub find_duplicate: DescriptorAttachmentFindDuplicate,
    pub allocate_link: DescriptorAttachmentAllocateLink,
    pub initialize_link: DescriptorAttachmentInitializeLink,
    pub notify: DescriptorAttachmentNotify,
}

pub const DEFAULT_DESCRIPTOR_ATTACHMENT_OPS: DescriptorAttachmentOps = DescriptorAttachmentOps {
    find_duplicate: retail_find_duplicate,
    allocate_link: retail_allocate_link,
    initialize_link: retail_initialize_link,
    notify: retail_notify,
};

/// Volatile dispatch boundary for the four unported retail functions.
pub static mut DESCRIPTOR_ATTACHMENT_OPS: DescriptorAttachmentOps = DEFAULT_DESCRIPTOR_ATTACHMENT_OPS;

#[inline(always)]
unsafe fn descriptor_attachment_ops() -> DescriptorAttachmentOps {
    ptr::read_volatile(ptr::addr_of!(DESCRIPTOR_ATTACHMENT_OPS))
}

/// Attaches a descriptor whose type exactly matches `owner`.
///
/// Raw ARM decoded from `work/firmware/osos.dec`:
///
/// ```text
/// 0803c034  push {r3,r4,r5,r6,r7,lr}
/// 0803c038  mov  r6,r0
/// 0803c03c  ldr  r0,[r1]
/// 0803c040  mov  r5,r1
/// 0803c044  ldr  r1,[r6,#0xc]
/// 0803c048  mov  r7,r2
/// 0803c04c  cmp  r0,r1
/// 0803c050  movne r0,#0
/// 0803c054  bne  0x0803c0e8
/// 0803c058  ldr  r0,[r5,#0x24]
/// 0803c05c  cmp  r0,#0
/// 0803c060  ldrbne r0,[r6,#0x18d]
/// 0803c064  tstne r0,#0x10
/// 0803c068  beq  0x0803c080
/// 0803c06c  ldr  r0,[r6,#0x40]
/// 0803c070  mov  r1,r5
/// 0803c074  bl   0x080daa7c
/// 0803c078  cmp  r0,#0
/// 0803c07c  bne  0x0803c0e8
/// 0803c080  mov  r0,r6
/// 0803c084  bl   0x0808e228
/// 0803c088  movs r4,r0
/// 0803c08c  beq  0x0803c0d4
/// 0803c090  str  r5,[r4,#0x20]
/// 0803c094  ldr  r0,[r4,#0x10]
/// 0803c098  mov  r2,#1
/// 0803c09c  str  r0,[r4,#0x24]
/// 0803c0a0  ldr  r0,[r5,#0x24]
/// 0803c0a4  mov  r1,r7
/// 0803c0a8  str  r0,[r4,#0x28]
/// 0803c0ac  mov  r0,r4
/// 0803c0b0  str  r4,[r5,#0x24]
/// 0803c0b4  bl   0x08093dfc
/// 0803c0b8  mov  r3,#0
/// 0803c0bc  str  r3,[sp]
/// 0803c0c0  ldr  r0,[r4]
/// 0803c0c4  ldr  r1,[pc,#0x20]   ; 0x61706c69 @ 0x0803c0ec
/// 0803c0c8  mov  r2,r4
/// 0803c0cc  add  r0,r0,#0x48
/// 0803c0d0  bl   0x08066bb8
/// 0803c0d4  ldr  r0,[r6,#0x1a8]
/// 0803c0d8  ldr  r1,[r5,#0xbc]
/// 0803c0dc  orr  r0,r0,r1
/// 0803c0e0  str  r0,[r6,#0x1a8]
/// 0803c0e4  mov  r0,r4
/// 0803c0e8  pop  {r3,r4,r5,r6,r7,pc}
/// 0803c0ec  .word 0x61706c69
/// ```
///
/// The next independently linked function starts at `0x0803c0f0`, making the
/// raw extent exactly 184 bytes. Decoding every ARM B/BL word in `osos.dec`
/// finds 8 direct callers: unconditional `bl` at 0x0803bf38, 0x08094ef8,
/// 0x080ab0e0, 0x081792e0, and 0x08283ec4; `blne` at 0x080ab3b0,
/// 0x080ab448, and 0x0816eeec. The predicated callers gate attachment on
/// their own successful lookup or inequality result; this function itself has
/// no NULL guards.
///
/// Algorithm: return NULL without side effects if descriptor word 0 differs
/// from owner word +0x0c. When the descriptor already has a link and owner
/// flag byte +0x18d has bit 4 set, ask the unported list helper whether an
/// equivalent link exists; a non-NULL result suppresses attachment. Otherwise
/// allocate a link, splice it at the descriptor's +0x24 head, initialize it
/// with `context` and one, then notify the owner list at +0x48 with the raw
/// literal tag and zero flags. Whether allocation succeeds or fails, OR the
/// descriptor +0xbc word into owner +0x1a8. The notification result is
/// discarded; the allocated link is returned.
///
/// Deliberate deviations: all four callees remain unported and dispatch through
/// [`DESCRIPTOR_ATTACHMENT_OPS`]; their identities beyond their observed roles
/// are not claimed. The literal notification tag remains raw because its
/// semantic identity is unrecovered.
///
/// # Safety
///
/// `owner` and `descriptor` must be valid aligned target-width word arrays
/// through words 106 and 47 respectively. On a matching path `owner` must
/// also satisfy the installed callee contracts; an allocated link must be
/// writable through word 10 and contain its owner word at word 0 before the
/// notification call.
#[cfg_attr(target_os = "none", no_mangle)]
#[cfg_attr(target_os = "none", link_section = ".text.attach_matching_descriptor")]
#[inline(never)]
pub unsafe extern "C" fn attach_matching_descriptor(
    owner: *mut u32,
    descriptor: *mut u32,
    context: *mut u8,
) -> *mut u32 {
    if descriptor.add(DESCRIPTOR_TYPE_WORD).read() != owner.add(OWNER_DESCRIPTOR_TYPE_WORD).read() {
        return ptr::null_mut();
    }

    if descriptor.add(DESCRIPTOR_LINK_HEAD_WORD).read() != 0
        && owner
            .add(OWNER_FLAGS_WORD)
            .cast::<u8>()
            .add(1)
            .read()
            & OWNER_DUPLICATE_CHECK_FLAG
            != 0
        && !(descriptor_attachment_ops().find_duplicate)(
            owner.add(OWNER_DUPLICATE_LIST_WORD).cast::<u8>(),
            descriptor,
        )
        .is_null()
    {
        return ptr::null_mut();
    }

    let link = (descriptor_attachment_ops().allocate_link)(owner);
    if !link.is_null() {
        link.add(LINK_DESCRIPTOR_WORD).write(descriptor as usize as u32);
        link.add(LINK_PREVIOUS_WORD).write(link.add(LINK_INITIAL_PREVIOUS_WORD).read());
        link.add(LINK_NEXT_WORD).write(descriptor.add(DESCRIPTOR_LINK_HEAD_WORD).read());
        descriptor.add(DESCRIPTOR_LINK_HEAD_WORD).write(link as usize as u32);
        (descriptor_attachment_ops().initialize_link)(link, context, 1);
        (descriptor_attachment_ops().notify)(
            (link.add(LINK_OWNER_WORD).read() as usize as *mut u8)
                .add(OWNER_TAGGED_LIST_OFFSET),
            ATTACH_NOTIFY_TAG,
            link,
            0,
            0,
        );
    }

    owner.add(OWNER_PENDING_FLAGS_WORD).write(
        owner.add(OWNER_PENDING_FLAGS_WORD).read()
            | descriptor.add(DESCRIPTOR_PENDING_FLAGS_WORD).read(),
    );
    link
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::sync::{LazyLock, Mutex};

    const FIXTURE_BYTES: usize = 0x500;
    const OWNER_WORD_OFFSET: usize = 0;
    const DESCRIPTOR_WORD_OFFSET: usize = 128;
    const OLD_LINK_WORD_OFFSET: usize = 176;
    const NEW_LINK_WORD_OFFSET: usize = 224;
    const CONTEXT_WORD_OFFSET: usize = 280;

    static OPS_LOCK: Mutex<()> = Mutex::new(());
    static FIXTURE: LazyLock<Option<usize>> = LazyLock::new(|| {
        crate::testing::try_map_u32_slab(
            crate::testing::hints::DESCRIPTOR_ATTACHMENT,
            FIXTURE_BYTES,
        )
        .map(|pointer| pointer as usize)
    });
    static mut FIND_CALLS: u32 = 0;
    static mut ALLOCATE_CALLS: u32 = 0;
    static mut INITIALIZE_CALLS: u32 = 0;
    static mut NOTIFY_CALLS: u32 = 0;
    static mut FIND_RESULT: usize = 0;
    static mut ALLOCATE_RESULT: usize = 0;
    static mut ALLOCATE_OWNER: u32 = 0;
    static mut INITIALIZE_LINK: usize = 0;
    static mut INITIALIZE_CONTEXT: usize = 0;
    static mut INITIALIZE_ENABLED: u32 = 0;
    static mut NOTIFY_LIST: usize = 0;
    static mut NOTIFY_TAG: u32 = 0;
    static mut NOTIFY_CONTEXT: usize = 0;
    static mut NOTIFY_FLAGS: u32 = u32::MAX;
    static mut NOTIFY_STACK_ARG: u32 = u32::MAX;

    unsafe extern "C" fn record_find_duplicate(_list: *mut u8, _descriptor: *mut u32) -> *mut u32 {
        FIND_CALLS += 1;
        FIND_RESULT as *mut u32
    }

    unsafe extern "C" fn record_allocate_link(_owner: *mut u32) -> *mut u32 {
        ALLOCATE_CALLS += 1;
        let link = ALLOCATE_RESULT as *mut u32;
        if !link.is_null() {
            link.add(LINK_OWNER_WORD).write(ALLOCATE_OWNER);
        }
        link
    }

    unsafe extern "C" fn record_initialize_link(link: *mut u32, context: *mut u8, enabled: u32) {
        INITIALIZE_CALLS += 1;
        INITIALIZE_LINK = link as usize;
        INITIALIZE_CONTEXT = context as usize;
        INITIALIZE_ENABLED = enabled;
    }

    unsafe extern "C" fn record_notify(
        list: *mut u8,
        tag: u32,
        context: *mut u32,
        flags: u32,
        stack_arg: u32,
    ) {
        NOTIFY_CALLS += 1;
        NOTIFY_LIST = list as usize;
        NOTIFY_TAG = tag;
        NOTIFY_CONTEXT = context as usize;
        NOTIFY_FLAGS = flags;
        NOTIFY_STACK_ARG = stack_arg;
    }

    struct OpsGuard(DescriptorAttachmentOps);

    impl Drop for OpsGuard {
        fn drop(&mut self) {
            unsafe { DESCRIPTOR_ATTACHMENT_OPS = self.0 };
        }
    }

    unsafe fn install_recorders() -> OpsGuard {
        let previous = DESCRIPTOR_ATTACHMENT_OPS;
        DESCRIPTOR_ATTACHMENT_OPS = DescriptorAttachmentOps {
            find_duplicate: record_find_duplicate,
            allocate_link: record_allocate_link,
            initialize_link: record_initialize_link,
            notify: record_notify,
        };
        FIND_CALLS = 0;
        ALLOCATE_CALLS = 0;
        INITIALIZE_CALLS = 0;
        NOTIFY_CALLS = 0;
        FIND_RESULT = 0;
        ALLOCATE_RESULT = 0;
        ALLOCATE_OWNER = 0;
        INITIALIZE_LINK = 0;
        INITIALIZE_CONTEXT = 0;
        INITIALIZE_ENABLED = 0;
        NOTIFY_LIST = 0;
        NOTIFY_TAG = 0;
        NOTIFY_CONTEXT = 0;
        NOTIFY_FLAGS = u32::MAX;
        NOTIFY_STACK_ARG = u32::MAX;
        OpsGuard(previous)
    }

    unsafe fn fixture() -> Option<(*mut u32, *mut u32, *mut u32, *mut u32, *mut u8)> {
        let base = (*FIXTURE)? as *mut u8;
        base.write_bytes(0, FIXTURE_BYTES);
        let words = base.cast::<u32>();
        Some((
            words.add(OWNER_WORD_OFFSET),
            words.add(DESCRIPTOR_WORD_OFFSET),
            words.add(OLD_LINK_WORD_OFFSET),
            words.add(NEW_LINK_WORD_OFFSET),
            words.add(CONTEXT_WORD_OFFSET).cast::<u8>(),
        ))
    }

    #[test]
    fn matching_descriptor_splices_initializes_notifies_and_accumulates_flags() {
        let _lock = OPS_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let Some((owner, descriptor, old_link, new_link, context)) = (unsafe { fixture() }) else {
            crate::testing::note_missing_u32_fixture("app::descriptor_attachment");
            return;
        };
        let _ops = unsafe { install_recorders() };

        unsafe {
            owner.add(OWNER_DESCRIPTOR_TYPE_WORD).write(0x4b1d);
            owner.add(OWNER_FLAGS_WORD).cast::<u8>().add(1).write(OWNER_DUPLICATE_CHECK_FLAG);
            owner.add(OWNER_PENDING_FLAGS_WORD).write(0x1020);
            descriptor.add(DESCRIPTOR_TYPE_WORD).write(0x4b1d);
            descriptor.add(DESCRIPTOR_LINK_HEAD_WORD).write(old_link as usize as u32);
            descriptor.add(DESCRIPTOR_PENDING_FLAGS_WORD).write(0x0804);
            new_link.add(LINK_INITIAL_PREVIOUS_WORD).write(0xa5a5_5a5a);
            ALLOCATE_OWNER = owner as usize as u32;
            ALLOCATE_RESULT = new_link as usize;

            assert_eq!(attach_matching_descriptor(owner, descriptor, context), new_link);
            assert_eq!(descriptor.add(DESCRIPTOR_LINK_HEAD_WORD).read(), new_link as usize as u32);
            assert_eq!(new_link.add(LINK_DESCRIPTOR_WORD).read(), descriptor as usize as u32);
            assert_eq!(new_link.add(LINK_PREVIOUS_WORD).read(), 0xa5a5_5a5a);
            assert_eq!(new_link.add(LINK_NEXT_WORD).read(), old_link as usize as u32);
            assert_eq!(owner.add(OWNER_PENDING_FLAGS_WORD).read(), 0x1824);
            assert_eq!((FIND_CALLS, ALLOCATE_CALLS, INITIALIZE_CALLS, NOTIFY_CALLS), (1, 1, 1, 1));
            assert_eq!((INITIALIZE_LINK, INITIALIZE_CONTEXT, INITIALIZE_ENABLED), (new_link as usize, context as usize, 1));
            assert_eq!(NOTIFY_LIST, owner.cast::<u8>().add(OWNER_TAGGED_LIST_OFFSET) as usize);
            assert_eq!((NOTIFY_TAG, NOTIFY_CONTEXT, NOTIFY_FLAGS, NOTIFY_STACK_ARG), (ATTACH_NOTIFY_TAG, new_link as usize, 0, 0));
        }
    }

    #[test]
    fn mismatched_descriptor_returns_null_without_side_effects() {
        let _lock = OPS_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let Some((owner, descriptor, _old_link, _new_link, context)) = (unsafe { fixture() }) else {
            crate::testing::note_missing_u32_fixture("app::descriptor_attachment");
            return;
        };
        let _ops = unsafe { install_recorders() };

        unsafe {
            owner.add(OWNER_DESCRIPTOR_TYPE_WORD).write(7);
            owner.add(OWNER_PENDING_FLAGS_WORD).write(0x1100);
            descriptor.add(DESCRIPTOR_TYPE_WORD).write(8);
            descriptor.add(DESCRIPTOR_LINK_HEAD_WORD).write(0xfeed_beef);
            descriptor.add(DESCRIPTOR_PENDING_FLAGS_WORD).write(0x44);

            assert!(attach_matching_descriptor(owner, descriptor, context).is_null());
            assert_eq!(descriptor.add(DESCRIPTOR_LINK_HEAD_WORD).read(), 0xfeed_beef);
            assert_eq!(owner.add(OWNER_PENDING_FLAGS_WORD).read(), 0x1100);
            assert_eq!((FIND_CALLS, ALLOCATE_CALLS, INITIALIZE_CALLS, NOTIFY_CALLS), (0, 0, 0, 0));
        }
    }

    #[test]
    fn existing_equivalent_link_suppresses_attachment_and_flag_update() {
        let _lock = OPS_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let Some((owner, descriptor, old_link, _new_link, context)) = (unsafe { fixture() }) else {
            crate::testing::note_missing_u32_fixture("app::descriptor_attachment");
            return;
        };
        let _ops = unsafe { install_recorders() };

        unsafe {
            owner.add(OWNER_DESCRIPTOR_TYPE_WORD).write(7);
            owner.add(OWNER_FLAGS_WORD).cast::<u8>().add(1).write(OWNER_DUPLICATE_CHECK_FLAG);
            owner.add(OWNER_PENDING_FLAGS_WORD).write(0x1100);
            descriptor.add(DESCRIPTOR_TYPE_WORD).write(7);
            descriptor.add(DESCRIPTOR_LINK_HEAD_WORD).write(old_link as usize as u32);
            descriptor.add(DESCRIPTOR_PENDING_FLAGS_WORD).write(0x44);
            FIND_RESULT = old_link as usize;

            assert!(attach_matching_descriptor(owner, descriptor, context).is_null());
            assert_eq!(descriptor.add(DESCRIPTOR_LINK_HEAD_WORD).read(), old_link as usize as u32);
            assert_eq!(owner.add(OWNER_PENDING_FLAGS_WORD).read(), 0x1100);
            assert_eq!((FIND_CALLS, ALLOCATE_CALLS, INITIALIZE_CALLS, NOTIFY_CALLS), (1, 0, 0, 0));
        }
    }

    #[test]
    fn allocation_failure_still_accumulates_descriptor_flags() {
        let _lock = OPS_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let Some((owner, descriptor, _old_link, _new_link, context)) = (unsafe { fixture() }) else {
            crate::testing::note_missing_u32_fixture("app::descriptor_attachment");
            return;
        };
        let _ops = unsafe { install_recorders() };

        unsafe {
            owner.add(OWNER_DESCRIPTOR_TYPE_WORD).write(7);
            owner.add(OWNER_PENDING_FLAGS_WORD).write(0x1100);
            descriptor.add(DESCRIPTOR_TYPE_WORD).write(7);
            descriptor.add(DESCRIPTOR_PENDING_FLAGS_WORD).write(0x44);

            assert!(attach_matching_descriptor(owner, descriptor, context).is_null());
            assert_eq!(owner.add(OWNER_PENDING_FLAGS_WORD).read(), 0x1144);
            assert_eq!((FIND_CALLS, ALLOCATE_CALLS, INITIALIZE_CALLS, NOTIFY_CALLS), (0, 1, 0, 0));
        }
    }
}
