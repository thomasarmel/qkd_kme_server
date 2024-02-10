
/// Asserts that two strings are equal after normalizing whitespace.
pub fn assert_string_equal(left: &str, right: &str) {
    let left = left.replace("\r", "");
    let right = right.replace("\r", "");
    assert_eq!(left, right);
}