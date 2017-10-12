use std::time;

/// ```rust
/// use xipolib::get_bit;
///
/// let b1 = get_bit(0, 0);
/// assert_eq!(b1, 0);
///
/// let b2 = get_bit(0xFF, 0);
/// assert_eq!(b2, 1);
///
/// let b3 = get_bit(0x80, 6);
/// assert_eq!(b3, 0);
///
/// let b4 = get_bit(0x80, 7);
/// assert_eq!(b4, 1);
/// ```
pub fn get_bit(byte: u8, bit: u8) -> u8 {
    (byte >> bit) & 1
}

/// ```rust
/// use xipolib::set_bit;
///
/// let mut b1 = 0u8;
/// set_bit(&mut b1, 0);
/// assert_eq!(b1, 1);
///
/// let mut b2 = 0u8;
/// set_bit(&mut b2, 7);
/// assert_eq!(b2, 128);
/// ```
pub fn set_bit(byte: &mut u8, bit: u8) {
    *byte |= 1 << bit;
}

/// Convert `Duration` into microseconds.
pub fn duration_to_micros(time: time::Duration) -> f64 {
    let secs = time.as_secs() as f64 * 1e6;
    let subsecs = time.subsec_nanos() as f64 * 1e-3;
    secs + subsecs
}
