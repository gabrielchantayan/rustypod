//! Collection listener notification step — FUN_081b979c @ 0x081b979c.
//!
//! True extent: 220 bytes, 0x081b979c..0x081b9878 (216 code + 4 pool).
//! Raw ARM decoding: two inbound plain BLs, four outgoing plain BLs, three
//! indirect BLXs, zero predicated calls. The next function opens at 0x081b9878.
//! Snapshot the collection count, prepare and notify each entry's +0x98 listener,
//! accumulating into context +0x120. Event 3 suppresses stage-6 progress; other
//! events report (index+1)*500/count. Nonzero single_step returns 0 immediately
//! after one entry, even the last. A subsequent call completes by adding the
//! registered-listener result and returning 1. Indices and sums wrap as u32.
//! Deviations: host virtual dispatch uses typed operations (as in
//! registered_listener_notify); target reads the original global and vtables.
//! The scratch output is initialized to NULL rather than an irrelevant incoming
//! r3: collection slot +0x3c must write it before use. Existing direct Rust
//! callees retain their documented deviations, including singleton storage.

#[cfg(not(target_os = "none"))]
#[derive(Clone, Copy)]
pub struct CollectionListenerOps {
    pub collection_get: unsafe fn() -> *mut u8,
    pub listener_at: unsafe fn(*mut u8, u32) -> *mut u8,
    pub prepare: unsafe fn(*mut u8),
    pub notify: unsafe fn(*mut u8, u32, *mut u32),
    pub finish: unsafe fn(u32) -> u32,
    pub progress: unsafe fn(u32),
}

#[cfg(not(target_os = "none"))]
pub static mut COLLECTION_LISTENER_OPS: Option<CollectionListenerOps> = None;

/// # Safety
/// Context must contain writable u32 words at +0x11c and +0x120. The retail
/// collection global, entries and vtables must be valid; on host install ops.
#[cfg_attr(target_os = "none", no_mangle)]
#[inline(never)]
pub unsafe extern "C" fn collection_listener_notify_step(
    context: *mut u32, event: u32, single_step: u32,
) -> u32 {
    #[cfg(not(target_os = "none"))]
    let ops = core::ptr::addr_of!(COLLECTION_LISTENER_OPS).read().expect("install collection listener host operations");
    #[cfg(not(target_os = "none"))]
    let collection = (ops.collection_get)();
    #[cfg(target_os = "none")]
    let collection = (0x089c_c8dc as *const *mut u8).read_volatile();
    let count = collection.add(4).cast::<u32>().read();
    let index = context.add(0x11c / 4);
    let total = context.add(0x120 / 4);
    while index.read() < count {
        #[cfg(not(target_os = "none"))]
        let listener = (ops.listener_at)(collection, index.read());
        #[cfg(target_os = "none")]
        let listener = {
            type ItemAt = unsafe extern "C" fn(*mut u8, u32, *mut *mut u8);
            type Prepare = unsafe extern "C" fn(*mut u8);
            let table = collection.cast::<*const u8>().read_volatile();
            let item_at = table.add(0x3c).cast::<ItemAt>().read_volatile();
            let mut entry = core::ptr::null_mut();
            item_at(collection, index.read(), &mut entry);
            let listener = entry.add(0x98).cast::<*mut u8>().read();
            let table = listener.cast::<*const u8>().read_volatile();
            let prepare = table.add(0x2c).cast::<Prepare>().read_volatile();
            prepare(listener);
            listener
        };
        #[cfg(not(target_os = "none"))]
        { (ops.prepare)(listener); (ops.notify)(listener, event, total); }
        #[cfg(target_os = "none")]
        {
            type Notify = unsafe extern "C" fn(*mut u8, u32, *mut u32);
            let table = listener.cast::<*const u8>().read_volatile();
            let notify = table.add(0x1c).cast::<Notify>().read_volatile();
            notify(listener, event, total);
        }
        if event != 3 {
            let progress = crate::runtime::rt_div::__rt_udiv(index.read().wrapping_add(1).wrapping_mul(500), count);
            #[cfg(not(target_os = "none"))]
            (ops.progress)(progress);
            #[cfg(target_os = "none")]
            {
                let tracker = super::singletons::stage_progress_tracker_get();
                super::stage_progress::stage_progress_set(tracker.cast(), 6, progress);
            }
        }
        index.write(index.read().wrapping_add(1));
        if single_step != 0 { return 0; }
    }
    #[cfg(not(target_os = "none"))]
    let final_output = (ops.finish)(event);
    #[cfg(target_os = "none")]
    let final_output = super::registered_listener_notify::registered_listener_notify(event);
    total.write(total.read().wrapping_add(final_output));
    1
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use parking_lot::Mutex;
    static LOCK: Mutex<()> = Mutex::new(());
    static mut COLLECTION: [u32; 2] = [0; 2];
    static mut TRACE: std::vec::Vec<u32> = std::vec::Vec::new();
    unsafe fn get() -> *mut u8 { core::ptr::addr_of_mut!(COLLECTION).cast() }
    unsafe fn at(_: *mut u8, index: u32) -> *mut u8 { core::ptr::addr_of_mut!(TRACE).as_mut().unwrap().push(100 + index); (index as usize + 1) as *mut u8 }
    unsafe fn prepare(listener: *mut u8) { (*core::ptr::addr_of_mut!(TRACE)).push(200 + listener as usize as u32); }
    unsafe fn notify(listener: *mut u8, event: u32, total: *mut u32) {
        (*core::ptr::addr_of_mut!(TRACE)).push(300 + listener as usize as u32);
        total.write(total.read().wrapping_add((listener as usize as u32).wrapping_mul(event + 1)));
        // Count changes must not alter the initial traversal bound.
        COLLECTION[1] = 0;
    }
    unsafe fn finish(event: u32) -> u32 { (*core::ptr::addr_of_mut!(TRACE)).push(400 + event); 7 }
    unsafe fn progress(value: u32) { (*core::ptr::addr_of_mut!(TRACE)).push(1000 + value); }
    unsafe fn install(count: u32) {
        COLLECTION = [0, count];
        (*core::ptr::addr_of_mut!(TRACE)).clear();
        COLLECTION_LISTENER_OPS = Some(CollectionListenerOps { collection_get: get, listener_at: at, prepare, notify, finish, progress });
    }

    #[test]
    fn batch_snapshots_count_and_accumulates_wrapping_output_in_order() {
        let _guard = LOCK.lock();
        unsafe {
            install(2);
            let mut context = [0u32; 73]; context[72] = u32::MAX;
            assert_eq!(collection_listener_notify_step(context.as_mut_ptr(), 0, 0), 1);
            assert_eq!((context[71], context[72]), (2, 9));
            assert_eq!(&*core::ptr::addr_of!(TRACE), &[100, 201, 301, 1250, 101, 202, 302, 1500, 400]);
        }
    }

    #[test]
    fn single_last_entry_defers_completion_and_event_three_skips_progress() {
        let _guard = LOCK.lock();
        unsafe {
            install(1);
            let mut context = [0u32; 73];
            assert_eq!(collection_listener_notify_step(context.as_mut_ptr(), 3, 7), 0);
            assert_eq!((context[71], context[72]), (1, 4));
            assert_eq!(&*core::ptr::addr_of!(TRACE), &[100, 201, 301]);
            assert_eq!(collection_listener_notify_step(context.as_mut_ptr(), 3, 7), 1);
            assert_eq!((context[71], context[72]), (1, 11));
            assert_eq!(&*core::ptr::addr_of!(TRACE), &[100, 201, 301, 403]);
        }
    }

    #[test]
    fn empty_and_unsigned_past_end_complete_without_entry_or_division() {
        let _guard = LOCK.lock();
        unsafe {
            for (count, index) in [(0, 0), (2, u32::MAX), (2, 2)] {
                install(count);
                let mut context = [0u32; 73]; context[71] = index; context[72] = u32::MAX;
                assert_eq!(collection_listener_notify_step(context.as_mut_ptr(), 0, 1), 1);
                assert_eq!((context[71], context[72]), (index, 6));
                assert_eq!(&*core::ptr::addr_of!(TRACE), &[400]);
            }
        }
    }
}
