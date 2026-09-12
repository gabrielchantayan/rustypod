//! `enqueue_command_kind_7` — original: `FUN_081df164` @ **0x081df164**
//! (**56 bytes**, `0x081df164..0x081df19c`; the next separately linked
//! function starts at `0x081df19c` with `push {r4,lr}`). A decoded scan of
//! every ARM B/BL word in `osos.dec` finds **8 direct BL callers**, all plain
//! unconditional `bl` (at `0x0817bc34`, `0x0817bc84`, `0x0817bcbc`,
//! `0x0817c914`, `0x0817d100`, `0x0817d1b4`, `0x0817d3ec`, and
//! `0x0817d4a0`); there are no predicated BL forms or direct tail branches.
//! No aligned data word contains this entry, so it is not virtually dispatched.
//!
//! Allocates a 12-byte command record, sets only its kind word to 7, appends
//! that record to the caller's leading pointer queue, runs its once-only
//! initialization guard, then tail-branches to post the mailbox slot at +0x20.
//! The command's remaining two words are deliberately left uninitialized, as
//! in the retailOS body. The input has no NULL guard; each of the eight callers
//! invokes it unconditionally.
//!
//! Deliberate deviation: Rust performs the final mailbox post as an ordinary
//! call rather than an ARM tail branch. The existing ports of `operator_new`,
//! `pointer_queue_enqueue`, `initialize_once`, and `mailbox_slot_post` supply
//! the retailOS operations directly.

use core::ffi::c_void;

use crate::app::once_initializer::{initialize_once, OnceInitializationState};
use crate::app::pointer_queue::{pointer_queue_enqueue, PointerQueue};
use crate::heap::veneers::operator_new;
use crate::kernel::kobj::{mailbox_slot_post, Mailbox};

const COMMAND_RECORD_TARGET_SIZE: usize = 12;
const COMMAND_KIND: u32 = 7;

/// Command-queue owner layout used by this command path.
///
/// On ARM, `queue` occupies +0x00..+0x20 and `notification_slot` is +0x20.
/// `initialize_once` reads the shared owner flag at +0x25; the two byte fields
/// below name that target-layout state without using literal byte offsets.
#[repr(C)]
pub struct CommandQueue {
    pub queue: PointerQueue,
    pub notification_slot: *mut Mailbox,
    reserved_24: u8,
    initialized: u8,
}

/// Queues a kind-7 command and posts the owner's mailbox notification slot.
///
/// Original: `FUN_081df164` @ 0x081df164 (56 bytes; 8 unconditional direct
/// `bl` callers, binary-verified — see the module header).
///
/// # Safety
///
/// `queue` must point to a live command-queue owner with a fully initialized
/// leading [`PointerQueue`] and a non-NULL mailbox in `notification_slot`.
/// Its allocator must return a writable 12-byte command record; the original
/// dereferences that result without an allocation-failure guard.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn enqueue_command_kind_7(queue: *mut CommandQueue) {
    let command = operator_new(COMMAND_RECORD_TARGET_SIZE).cast::<u32>();
    command.write(COMMAND_KIND);

    pointer_queue_enqueue(
        core::ptr::addr_of_mut!((*queue).queue),
        command.cast::<c_void>(),
    );
    initialize_once(queue.cast::<OnceInitializationState>());
    mailbox_slot_post(core::ptr::addr_of_mut!((*queue).notification_slot));
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::heap::types::HeapDescriptorDescriptor;
    use crate::heap::veneers::{HEAP_OPS, HeapVeneerOps};
    use crate::heap::veneers::tests::mock_heap;
    use core::ptr::{addr_of_mut, null_mut};

    static mut ALLOCATIONS: [*mut u8; 2] = [null_mut(); 2];
    static mut ALLOCATION_INDEX: usize = 0;
    static mut ALLOCATION_REQUESTS: [(usize, usize); 2] = [(0, 0); 2];

    unsafe extern "C" fn sequential_alloc(
        _heap: *mut HeapDescriptorDescriptor,
        size: usize,
        tag: usize,
    ) -> *mut u8 {
        let index = ALLOCATION_INDEX;
        ALLOCATION_INDEX += 1;
        ALLOCATION_REQUESTS[index] = (size, tag);
        ALLOCATIONS[index]
    }

    #[repr(C)]
    struct CommandRecord([u32; 3]);

    #[repr(C)]
    struct QueueNodeStorage([usize; 2]);

    #[test]
    fn enqueues_kind_7_initializes_once_and_posts_mailbox() {
        let _heap = mock_heap();
        let mut command = CommandRecord([0, 0x1111_2222, 0x3333_4444]);
        let mut node = QueueNodeStorage([0; 2]);
        let mut mailbox = Mailbox { state: 1, id: 0xfeed_0007 };
        let mut queue = CommandQueue {
            queue: unsafe { core::mem::zeroed() },
            notification_slot: &mut mailbox,
            reserved_24: 0,
            initialized: 0,
        };

        unsafe {
            ALLOCATIONS = [command.0.as_mut_ptr().cast(), node.0.as_mut_ptr().cast()];
            ALLOCATION_INDEX = 0;
            ALLOCATION_REQUESTS = [(0, 0); 2];
            let mut ops: HeapVeneerOps = core::ptr::read_volatile(addr_of_mut!(HEAP_OPS));
            ops.alloc = sequential_alloc;
            addr_of_mut!(HEAP_OPS).write(ops);

            enqueue_command_kind_7(&mut queue);

            assert_eq!(ALLOCATION_INDEX, 2, "command then queue node allocation");
            assert_eq!(ALLOCATION_REQUESTS, [(12, 2), (8, 2)]);
            assert_eq!(command.0[0], COMMAND_KIND, "only kind is written before enqueue");
            assert_eq!(command.0[1], 0x1111_2222, "second command word is untouched");
            assert_eq!(command.0[2], 0x3333_4444, "third command word is untouched");
            assert_eq!(queue.queue.pending.head, node.0.as_mut_ptr().cast());
            assert_eq!(queue.queue.pending.tail, node.0.as_mut_ptr().cast());
            assert_eq!(node.0[0], 0, "new queue node has no successor");
            assert_eq!(node.0[1], command.0.as_mut_ptr() as usize);
            assert_eq!(mailbox.state, 2, "mailbox post adds one token");
            assert_eq!(*((&mut queue as *mut CommandQueue).cast::<u8>().add(0x25)), 1,
                "initialize_once writes the shared owner byte at target +0x25");
        }
    }
}
