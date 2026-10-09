// Timed PMU mode-1 status query.

#[derive(Clone, Copy)]
struct Ops {
    wait: unsafe fn(),
    prepare: unsafe fn(),
    sleep: unsafe fn(u32),
    elapsed: unsafe fn(u32, u32) -> bool,
    query: unsafe fn(u32, *mut u32) -> i32,
    signal: unsafe fn(),
}

#[cfg(target_os = "none")]
unsafe fn wait() { crate::kernel::task_lock::rom_sem_wait(18); }
#[cfg(target_os = "none")]
unsafe fn signal() { crate::kernel::task_lock::rom_sem_signal(18); }
#[cfg(target_os = "none")]
unsafe fn prepare() {
    // Raw 0x080bfbec starts mode 1 if inactive, then records the start tick
    // at 0x089cd928 and marks 0x089cd924 active. No registered Rust port.
    core::mem::transmute::<usize, unsafe extern "C" fn()>(0x080b_fbec)();
}
#[cfg(target_os = "none")]
unsafe fn sleep(ticks: u32) { crate::kernel::task::task_sleep_thunk(ticks); }
#[cfg(target_os = "none")]
unsafe fn elapsed(start: u32, interval: u32) -> bool {
    crate::drivers::timer::iram_usec_timer_elapsed_veneer(start, interval)
}
#[cfg(target_os = "none")]
unsafe fn query(mode: u32, response: *mut u32) -> i32 {
    crate::drivers::pmu::pmu_query_mode_response(mode, response)
}

/// pmu_timed_mode_status — original `FUN_080db71c` @ `0x080db71c`.
/// True size: 120 bytes (112 instruction bytes, 8 literal bytes); the next
/// real prologue is at 0x080db794. Independently decoded BL counts: 2 plain
/// inbound, 0 predicated inbound; 6 plain outgoing, 0 predicated outgoing.
///
/// Holds semaphore 18, prepares the mode-1 transaction, sleeps 80 ticks,
/// then polls the saved start tick until 80000 microseconds have elapsed.
/// Queries mode 1 with a response initialized to all ones. On success,
/// extracts signed bits 4..11 and maps 15 to 100; on failure returns -1.
/// Always clears the active word before releasing semaphore 18.
///
/// Deviations: existing Rust semaphore, sleep, timer and PMU ports replace
/// their retail edges. The unported preparation routine uses its verified
/// typed load address, not a guessed callee identity. Shared state accesses
/// are volatile; hosts replace hardware boundaries, not the algorithm.
#[inline(never)]
#[cfg_attr(target_os = "none", no_mangle)]
pub unsafe extern "C" fn pmu_timed_mode_status() -> i32 {
    #[cfg(target_os = "none")]
    {
        run(0x089c_d924 as *mut u32, Ops { wait, prepare, sleep, elapsed, query, signal })
    }
    #[cfg(not(target_os = "none"))]
    {
        let (state, ops) = core::ptr::read_volatile(core::ptr::addr_of!(HOST));
        let ops = ops.expect("install timed PMU status host operations");
        run(state, ops)
    }
}

#[cfg(not(target_os = "none"))]
static mut HOST: (*mut u32, Option<Ops>) = (core::ptr::null_mut(), None);

#[inline(always)]
unsafe fn run(state: *mut u32, ops: Ops) -> i32 {
    let mut response = u32::MAX;
    (ops.wait)();
    (ops.prepare)();
    (ops.sleep)(80);
    while !(ops.elapsed)(core::ptr::read_volatile(state.add(1)), 80000) {}
    let status = (ops.query)(1, &mut response);
    let result = if status == 0 {
        let value = ((response << 20) as i32) >> 24;
        if value == 15 { 100 } else { value }
    } else { -1 };
    core::ptr::write_volatile(state, 0);
    (ops.signal)();
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex;
    static LOCK: Mutex<()> = Mutex::new(());
    static mut STATE: [u32; 3] = [0; 3];
    static mut POLLS: u32 = 0;
    static mut RESPONSE: Option<u32> = None;
    static mut STATUS: i32 = 0;
    static mut PHASE: u32 = 0;

    unsafe fn wait() { assert_eq!(PHASE, 0); PHASE = 1; }
    unsafe fn prepare() {
        assert_eq!(PHASE, 1);
        STATE = [1, u32::MAX - 10, 0xdeadbeef];
        PHASE = 2;
    }
    unsafe fn sleep(ticks: u32) { assert_eq!(PHASE, 2); assert_eq!(ticks, 80); PHASE = 3; }
    unsafe fn elapsed(start: u32, interval: u32) -> bool {
        assert_eq!(PHASE, 3);
        assert_eq!(interval, 80000);
        assert_eq!(start, if POLLS == 0 { u32::MAX - 10 } else { 27 });
        POLLS += 1;
        // A concurrent update must be reloaded on the next iteration.
        STATE[1] = 27;
        POLLS == 2
    }
    unsafe fn query(mode: u32, out: *mut u32) -> i32 {
        assert_eq!(PHASE, 3); assert_eq!(POLLS, 2);
        assert_eq!(mode, 1); assert_eq!(*out, u32::MAX);
        if let Some(value) = RESPONSE { *out = value; }
        PHASE = 4;
        STATUS
    }
    unsafe fn signal() {
        assert_eq!(PHASE, 4); assert_eq!(STATE, [0, 27, 0xdeadbeef]);
        PHASE = 5;
    }
    unsafe fn invoke(response: Option<u32>, status: i32) -> i32 {
        RESPONSE = response; STATUS = status; PHASE = 0; POLLS = 0;
        HOST = (core::ptr::addr_of_mut!(STATE).cast(), Some(Ops { wait, prepare, sleep, elapsed, query, signal }));
        let result = pmu_timed_mode_status();
        assert_eq!(PHASE, 5);
        HOST = (core::ptr::null_mut(), None);
        result
    }

    #[test]
    fn extracts_every_signed_status_and_remaps_only_fifteen() {
        let _lock = LOCK.lock();
        unsafe {
            for byte in 0..=255_u32 {
                let response = 0xa5a5_f00f | (byte << 4);
                let expected = if byte == 15 { 100 } else { byte as u8 as i8 as i32 };
                assert_eq!(invoke(Some(response), 0), expected);
            }
            assert_eq!(invoke(None, 0), -1);
        }
    }

    #[test]
    fn errors_ignore_response_and_still_clear_and_release() {
        let _lock = LOCK.lock();
        unsafe {
            for status in [1, -1, i32::MIN, i32::MAX] {
                assert_eq!(invoke(Some(15 << 4), status), -1);
                assert_eq!(invoke(None, status), -1);
            }
        }
    }
}
