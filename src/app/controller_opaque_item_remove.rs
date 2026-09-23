//! `app_controller_opaque_item_remove` — original: `FUN_0817e9b8` @
//! **0x0817e9b8**.
//!
//! The true extent is **196 bytes**, `0x0817e9b8..0x0817ea7c`: 188 bytes of
//! instructions followed by the two literal-pool words at `0x0817ea74` and
//! `0x0817ea78`; the next separately entered function starts at `0x0817ea7c`.
//! Raw A32 decoding finds five outbound plain `bl` calls (`0x0817e9d8`,
//! `0x0817ea3c`, `0x0817ea4c`, `0x0817ea58`, and `0x0817ea70`) and one
//! predicated `blne` at `0x0817ea10`; there is no tail branch.
//!
//! # Algorithm
//!
//! If the controller's opaque word vector is nonempty, removes its first
//! element equal to `item_id` by shifting following words down and shortening
//! the end pointer. If that removal made the vector empty, allocates a
//! 12-byte queued-message envelope, constructs a word payload with code
//! `0x2503` and controller word `+0x70`, then posts it back to the controller.
//!
//! # Deliberate deviations
//!
//! The element type and message meaning are unrecovered, so both retain their
//! representation-level names. The stock `FUN_083e9eb8` word copy is expressed
//! directly with volatile word accesses; it has no Rust seam because this
//! caller is its only observed use in the relevant path.

use core::ptr::{addr_of, addr_of_mut, read_volatile, write_volatile};

use crate::app::controller_opaque_item_vector::{app_controller_opaque_item_vector_nonempty, AppControllerOpaqueItemVector};
use crate::app::message_arena::message_arena_alloc;
use crate::app::queued_message::{queued_message_construct_word, queued_message_post, MessageTarget, QueuedMessage};
use crate::cxx::templates::VectorBounds;

/// Controller view used by [`app_controller_opaque_item_remove`].
#[repr(C)]
pub struct AppControllerOpaqueItemRemoval {
    _prefix: [u8; 0x58],
    pub opaque_items: VectorBounds,
    _between_vector_and_notification: [u32; 4],
    /// Word passed to the queued-message payload constructor from `+0x70`.
    pub notification_word: u32,
}

#[cfg(target_pointer_width = "32")]
const _: [u8; 0x58] = [0; core::mem::offset_of!(AppControllerOpaqueItemRemoval, opaque_items)];
#[cfg(target_pointer_width = "32")]
const _: [u8; 0x70] = [0; core::mem::offset_of!(AppControllerOpaqueItemRemoval, notification_word)];

const EMPTY_NOTIFICATION_CODE: u32 = 0x2503;

unsafe fn remove_opaque_item_with<Nonempty, Allocate, Construct, Post>(
    controller: *mut AppControllerOpaqueItemRemoval,
    item_id: u32,
    nonempty: Nonempty,
    allocate: Allocate,
    construct: Construct,
    post: Post,
) where
    Nonempty: Fn(*const AppControllerOpaqueItemRemoval) -> u32,
    Allocate: Fn(usize) -> *mut u8,
    Construct: Fn(*mut QueuedMessage, u32, u32) -> *mut QueuedMessage,
    Post: Fn(*mut QueuedMessage, *mut MessageTarget, u32, usize, u32) -> u32,
{
    if nonempty(controller) == 0 {
        return;
    }

    let bounds = unsafe { addr_of_mut!((*controller).opaque_items) };
    let end = unsafe { read_volatile(addr_of!((*bounds).end)) }.cast::<u32>();
    let mut current = unsafe { read_volatile(addr_of!((*bounds).begin)) }.cast::<u32>();
    while current != end {
        if unsafe { read_volatile(current) } == item_id {
            let next = unsafe { current.add(1) };
            if next != end {
                let mut source = next;
                let mut destination = current;
                while source != end {
                    unsafe { write_volatile(destination, read_volatile(source)) };
                    source = unsafe { source.add(1) };
                    destination = unsafe { destination.add(1) };
                }
            }
            unsafe { write_volatile(addr_of_mut!((*bounds).end), end.sub(1).cast()) };
            break;
        }
        current = unsafe { current.add(1) };
    }

    if nonempty(controller) != 0 {
        return;
    }

    let storage = allocate(core::mem::size_of::<QueuedMessage>()).cast::<QueuedMessage>();
    let message = construct(storage, EMPTY_NOTIFICATION_CODE, unsafe { read_volatile(addr_of!((*controller).notification_word)) });
    post(message, controller.cast(), 1, 0, 0);
}

/// Removes one matching opaque word from the controller's item vector.
///
/// Original: `FUN_0817e9b8` @ `0x0817e9b8` (196 bytes including its literal
/// pool; five plain `bl` and one `blne` outbound calls -- see module header).
/// The controller and its vector bounds are dereferenced without NULL guards.
///
/// # Safety
///
/// `controller` must designate a valid retailOS controller with a readable
/// word vector at `+0x58` and a [`MessageTarget`] compatible prefix when the
/// removal empties that vector.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn app_controller_opaque_item_remove(
    controller: *mut AppControllerOpaqueItemRemoval,
    item_id: u32,
) {
    unsafe {
        remove_opaque_item_with(
            controller,
            item_id,
            |controller| app_controller_opaque_item_vector_nonempty(controller.cast::<AppControllerOpaqueItemVector>()),
            |size| message_arena_alloc(size),
            |storage, code, word| queued_message_construct_word(storage, code, word),
            |message, target, no_wait, reply_queue, flags| queued_message_post(message, target, no_wait, reply_queue, flags),
        )
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use parking_lot::Mutex;

    static LOCK: Mutex<()> = Mutex::new(());
    static mut ALLOCATIONS: usize = 0;
    static mut CONSTRUCTIONS: std::vec::Vec<(u32, u32)> = std::vec::Vec::new();
    static mut POSTS: usize = 0;

    fn nonempty(controller: *const AppControllerOpaqueItemRemoval) -> u32 {
        let bounds = unsafe { &(*controller).opaque_items };
        (bounds.begin != bounds.end) as u32
    }

    fn allocate(_: usize) -> *mut u8 {
        unsafe { ALLOCATIONS += 1 };
        0x1000usize as *mut u8
    }

    fn construct(storage: *mut QueuedMessage, code: u32, word: u32) -> *mut QueuedMessage {
        unsafe { CONSTRUCTIONS.push((code, word)) };
        storage
    }

    fn post(_: *mut QueuedMessage, _: *mut MessageTarget, _: u32, _: usize, _: u32) -> u32 {
        unsafe { POSTS += 1 };
        0
    }

    fn controller(words: &mut [u32], end: usize) -> AppControllerOpaqueItemRemoval {
        AppControllerOpaqueItemRemoval {
            _prefix: [0; 0x58],
            opaque_items: VectorBounds { begin: words.as_mut_ptr().cast(), end: unsafe { words.as_mut_ptr().add(end).cast() } },
            _between_vector_and_notification: [0; 4],
            notification_word: 0xa5a5_5a5a,
        }
    }

    fn reset() {
        unsafe {
            ALLOCATIONS = 0;
            CONSTRUCTIONS.clear();
            POSTS = 0;
        }
    }

    #[test]
    fn removes_middle_word_without_empty_notification() {
        let _guard = LOCK.lock();
        reset();
        let mut words = [10, 20, 30, 40];
        let mut controller = controller(&mut words, 4);

        unsafe { remove_opaque_item_with(&mut controller, 20, nonempty, allocate, construct, post) };

        assert_eq!(&words[..3], &[10, 30, 40]);
        assert_eq!(unsafe { controller.opaque_items.end.offset_from(controller.opaque_items.begin) }, 12);
        assert_eq!(unsafe { ALLOCATIONS }, 0);
        assert_eq!(unsafe { POSTS }, 0);
    }

    #[test]
    fn removing_final_word_posts_empty_notification() {
        let _guard = LOCK.lock();
        reset();
        let mut words = [0x42];
        let mut controller = controller(&mut words, 1);

        unsafe { remove_opaque_item_with(&mut controller, 0x42, nonempty, allocate, construct, post) };

        assert_eq!(controller.opaque_items.begin, controller.opaque_items.end);
        assert_eq!(unsafe { ALLOCATIONS }, 1);
        assert_eq!(unsafe { CONSTRUCTIONS.as_slice() }, &[(EMPTY_NOTIFICATION_CODE, 0xa5a5_5a5a)]);
        assert_eq!(unsafe { POSTS }, 1);
    }

    #[test]
    fn absent_word_keeps_vector_and_does_not_notify() {
        let _guard = LOCK.lock();
        reset();
        let mut words = [1, 2];
        let mut controller = controller(&mut words, 2);

        unsafe { remove_opaque_item_with(&mut controller, 3, nonempty, allocate, construct, post) };

        assert_eq!(words, [1, 2]);
        assert_eq!(unsafe { ALLOCATIONS }, 0);
        assert_eq!(unsafe { POSTS }, 0);
    }

    #[test]
    fn empty_vector_has_no_side_effects() {
        let _guard = LOCK.lock();
        reset();
        let mut words = [0u32];
        let mut controller = controller(&mut words, 0);

        unsafe { remove_opaque_item_with(&mut controller, 0, nonempty, allocate, construct, post) };

        assert_eq!(unsafe { ALLOCATIONS }, 0);
        assert!(unsafe { CONSTRUCTIONS.is_empty() });
        assert_eq!(unsafe { POSTS }, 0);
        assert_eq!(controller.opaque_items.begin, controller.opaque_items.end);
    }
}
