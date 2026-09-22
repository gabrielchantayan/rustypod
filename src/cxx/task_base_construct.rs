//! Constructor for the common task base object.
//!
//! Original: `FUN_08290704` @ 0x08290704 (76 bytes of code plus the
//! 4-byte vtable literal at 0x08290750). Raw A32 decoding establishes the
//! extent 0x08290704..0x0829074f; 0x08290754 begins the deleting destructor.
//! Full-image decoding finds three plain inbound `bl` calls (0x0819c208,
//! 0x081b91cc, 0x082027ac), no predicated inbound calls, and two internal
//! plain calls: `string_object_copy_construct` then `mailbox_slot_create`.
//!
//! It plants vtable 0x089a7160, copy-constructs the embedded StringObject at
//! +0x08 from `name`, stores the task scheduling fields at +0x10..+0x1c,
//! clears flags +0x20/+0x21, creates the mailbox slot at +0x24, and returns
//! `this`. The field at +0x04 is zeroed before the StringObject constructor.
//!
//! Deliberate deviation: host pointers are wider than retailOS words, so this
//! port addresses the target layout with byte offsets instead of a host-native
//! struct. Host-only call seams make the two target calls observable; target
//! builds call the already ported callees directly.

#[cfg(not(target_os = "none"))]
use core::ptr;

use crate::cxx::string_object::{string_object_copy_construct, StringObject};
use crate::kernel::kobj::{mailbox_slot_create, Mailbox};

pub const TASK_BASE_VTABLE_ADDRESS: u32 = 0x089a_7160;
const NAME_OFFSET: usize = 0x08;
const SCHEDULER_OFFSET: usize = 0x10;
const PRIORITY_OFFSET: usize = 0x14;
const ACTIVE_OFFSET: usize = 0x18;
const TIMEOUT_OFFSET: usize = 0x1c;
const FLAGS_OFFSET: usize = 0x20;
const MAILBOX_OFFSET: usize = 0x24;

#[cfg(not(target_os = "none"))]
type StringCopyConstruct = unsafe extern "C" fn(*mut StringObject, *const StringObject) -> *mut StringObject;
#[cfg(not(target_os = "none"))]
type MailboxSlotCreate = unsafe extern "C" fn(*mut *mut Mailbox);

#[cfg(not(target_os = "none"))]
static mut STRING_COPY_CONSTRUCT: StringCopyConstruct = string_object_copy_construct;
#[cfg(not(target_os = "none"))]
static mut MAILBOX_SLOT_CREATE: MailboxSlotCreate = mailbox_slot_create;

#[inline(always)]
unsafe fn copy_name(destination: *mut StringObject, source: *const StringObject) {
    #[cfg(target_os = "none")]
    string_object_copy_construct(destination, source);
    #[cfg(not(target_os = "none"))]
    ptr::read_volatile(ptr::addr_of!(STRING_COPY_CONSTRUCT))(destination, source);
}

#[inline(always)]
unsafe fn create_mailbox(slot: *mut *mut Mailbox) {
    #[cfg(target_os = "none")]
    mailbox_slot_create(slot);
    #[cfg(not(target_os = "none"))]
    ptr::read_volatile(ptr::addr_of!(MAILBOX_SLOT_CREATE))(slot);
}

/// Constructs the shared base of several scheduled task classes.
///
/// `this` must cover target offsets +0x00 through +0x27. `name` must be a
/// valid StringObject for its copy constructor. The original has no NULL or
/// allocation-failure guard.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn task_base_construct(
    this: *mut u8,
    _unused: u32,
    name: *const StringObject,
    scheduler: u32,
    active: u8,
    timeout: u32,
) -> *mut u8 {
    this.cast::<u32>().write(TASK_BASE_VTABLE_ADDRESS);
    this.add(4).cast::<u32>().write(0);
    copy_name(this.add(NAME_OFFSET).cast(), name);
    this.add(SCHEDULER_OFFSET).cast::<u32>().write(scheduler);
    this.add(PRIORITY_OFFSET).cast::<u32>().write(_unused);
    this.add(ACTIVE_OFFSET).write(active);
    this.add(TIMEOUT_OFFSET).cast::<u32>().write(timeout);
    this.add(FLAGS_OFFSET).write(0);
    this.add(FLAGS_OFFSET + 1).write(0);
    create_mailbox(this.add(MAILBOX_OFFSET).cast());
    this
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex;

    static LOCK: Mutex<()> = Mutex::new(());
    static mut COPY_DESTINATION: *mut StringObject = ptr::null_mut();
    static mut COPY_SOURCE: *const StringObject = ptr::null();
    static mut MAILBOX_SLOT: *mut *mut Mailbox = ptr::null_mut();

    struct Seams {
        copy: StringCopyConstruct,
        mailbox: MailboxSlotCreate,
    }

    impl Seams {
        unsafe fn install() -> Self {
            let seams = Self {
                copy: ptr::read_volatile(ptr::addr_of!(STRING_COPY_CONSTRUCT)),
                mailbox: ptr::read_volatile(ptr::addr_of!(MAILBOX_SLOT_CREATE)),
            };
            ptr::addr_of_mut!(STRING_COPY_CONSTRUCT).write_volatile(record_copy);
            ptr::addr_of_mut!(MAILBOX_SLOT_CREATE).write_volatile(record_mailbox);
            seams
        }
    }

    impl Drop for Seams {
        fn drop(&mut self) {
            unsafe {
                ptr::addr_of_mut!(STRING_COPY_CONSTRUCT).write_volatile(self.copy);
                ptr::addr_of_mut!(MAILBOX_SLOT_CREATE).write_volatile(self.mailbox);
            }
        }
    }

    unsafe extern "C" fn record_copy(destination: *mut StringObject, source: *const StringObject) -> *mut StringObject {
        COPY_DESTINATION = destination;
        COPY_SOURCE = source;
        destination
    }

    unsafe extern "C" fn record_mailbox(slot: *mut *mut Mailbox) {
        MAILBOX_SLOT = slot;
    }

    #[repr(align(4))]
    struct AlignedStorage([u8; 0x30]);

    #[test]
    fn constructs_target_layout_and_forwards_all_arguments() {
        let _lock = LOCK.lock();
        unsafe {
            let _seams = Seams::install();
            COPY_DESTINATION = ptr::null_mut();
            COPY_SOURCE = ptr::null();
            MAILBOX_SLOT = ptr::null_mut();
            let mut storage = AlignedStorage([0xa5_u8; 0x30]);
            let source = StringObject { vtable: ptr::null(), payload: ptr::null_mut() };
            let result = task_base_construct(storage.0.as_mut_ptr(), 0xc000, &source, 0x20, 1, 10);

            assert_eq!(result, storage.0.as_mut_ptr());
            assert_eq!(storage.0.as_ptr().cast::<u32>().read(), TASK_BASE_VTABLE_ADDRESS);
            assert_eq!(storage.0.as_ptr().add(4).cast::<u32>().read(), 0);
            assert_eq!(COPY_DESTINATION, storage.0.as_mut_ptr().add(NAME_OFFSET).cast());
            assert!(COPY_SOURCE == &source);
            assert_eq!(storage.0.as_ptr().add(SCHEDULER_OFFSET).cast::<u32>().read(), 0x20);
            assert_eq!(storage.0.as_ptr().add(PRIORITY_OFFSET).cast::<u32>().read(), 0xc000);
            assert_eq!(storage.0[ACTIVE_OFFSET], 1);
            assert_eq!(storage.0.as_ptr().add(TIMEOUT_OFFSET).cast::<u32>().read(), 10);
            assert_eq!(&storage.0[FLAGS_OFFSET..FLAGS_OFFSET + 2], &[0, 0]);
            assert_eq!(MAILBOX_SLOT, storage.0.as_mut_ptr().add(MAILBOX_OFFSET).cast());
        }
    }
}
