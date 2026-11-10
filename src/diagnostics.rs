//! Compile-time optional process-lifetime histograms. No timer or per-frame log.
use std::sync::atomic::{AtomicU64, Ordering};
pub const LIMITS: [usize; 10] = [
    1024,
    4096,
    8192,
    16384,
    32768,
    65536,
    131072,
    262144,
    524288,
    usize::MAX,
];
pub const NAMES: [&str; 6] = [
    "rx_tcp_full_messages",
    "rx_tcp_pass_messages",
    "rx_control_messages",
    "rx_tls_chunks",
    "req_tcp_deliveries",
    "tx_tcp_messages",
];
static COUNTS: [[AtomicU64; 10]; 6] = [const { [const { AtomicU64::new(0) }; 10] }; 6];
static BYTES: [[AtomicU64; 10]; 6] = [const { [const { AtomicU64::new(0) }; 10] }; 6];
pub fn record(kind: usize, len: usize) {
    let bucket = bucket(len);
    COUNTS[kind][bucket].fetch_add(1, Ordering::Relaxed);
    BYTES[kind][bucket].fetch_add(len as u64, Ordering::Relaxed);
}
fn bucket(len: usize) -> usize {
    LIMITS.iter().position(|&max| len <= max).unwrap()
}
pub fn snapshot() -> [([u64; 10], [u64; 10]); 6] {
    std::array::from_fn(|k| {
        (
            std::array::from_fn(|b| COUNTS[k][b].load(Ordering::Relaxed)),
            std::array::from_fn(|b| BYTES[k][b].load(Ordering::Relaxed)),
        )
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn boundaries() {
        assert_eq!(bucket(0), 0);
        assert_eq!(bucket(1024), 0);
        assert_eq!(bucket(1025), 1);
        assert_eq!(bucket(16384), 3);
        assert_eq!(bucket(262144), 7);
        assert_eq!(bucket(usize::MAX), 9);
    }
}
