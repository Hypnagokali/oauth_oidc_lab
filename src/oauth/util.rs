use sha2::{Digest, Sha256};
use constant_time_eq::constant_time_eq;

pub fn is_equal_constant_time(a: &str, b: &str) -> bool {
    let first = Sha256::digest(a);
    let second = Sha256::digest(b);
    constant_time_eq(&first, &second)
}
