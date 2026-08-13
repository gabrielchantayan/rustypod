//! H.264 / MPEG-4 AVC video decoder — the bitstream side.
//!
//! The decoder's syntax parsers live in the 0x0836xxxx cluster and read
//! everything through one shared RBSP cursor whose primitives sit far
//! away, in 0x0809bxxx / 0x082bxxxx / 0x082cxxxx / 0x082dxxxx:
//!
//! - 0x082d0630 — read the next `n` bits as an unsigned value.
//! - 0x0809b040 — count leading zero bits (the Exp-Golomb prefix),
//!   ported in [`bitstream`].
//! - 0x082c319c — emulation-prevention probe: is the byte at `p` the
//!   `0x03` of a `00 00 03` sequence? Transcribed in [`bitstream`] as
//!   a local helper of the leading-zero count.
//! - 0x082c5df0 — `ue(v)`: leading-zero count `n`, then `n+1` bits,
//!   folded to `2^n - 1 + suffix`.
//! - 0x082c5dcc — `se(v)`: `ue(v)` mapped to `+k / -k`.
//! - 0x082b3258 — the cursor advance, ported in [`bitstream`].
//!
//! What pins the codec down as H.264 rather than any other bit-packed
//! format: emulation-prevention bytes are H.264/HEVC-specific, `ue(v)`
//! and `se(v)` are its universal syntax element codings, and the parser
//! at 0x08365640 is textbook `dec_ref_pic_marking()` — `nal_unit_type
//! == 5` reads `no_output_of_prior_pics_flag` and
//! `long_term_reference_flag`, everything else reads
//! `adaptive_ref_pic_marking_mode_flag` and then loops over
//! `memory_management_control_operation` values, pulling one extra
//! `ue(v)` for ops 1/3, 2 and 3/6 exactly as the standard prescribes.
//! It is ported in [`dec_ref_pic_marking`].
pub mod bitstream;
pub mod dec_ref_pic_marking;
pub mod stream_buffer_reset;
