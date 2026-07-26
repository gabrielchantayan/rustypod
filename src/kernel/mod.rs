//! RAM-side kernel-service layer over the RTXC mask-ROM kernel.
pub mod condvar;
pub mod irq;
pub mod kobj;
pub mod mqueue;
pub mod os_heap;
pub mod sync_mutex;
pub mod sync_sem;
pub mod task;
pub mod task_lock;
pub mod thunks;
