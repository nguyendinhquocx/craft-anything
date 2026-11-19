//! The partial shared-reader cutover preserves offsets and the app's definite-length contract.
use craft_anything_formats::der;

#[test]
fn shared_tlv_preserves_offsets_raw_bytes_and_length_notes() {
    for (encoding, non_minimal) in [
        (vec![4, 3, 1, 2, 3], false),
        (vec![4, 0x81, 3, 1, 2, 3], true),
        (vec![4, 0x82, 0, 3, 1, 2, 3], true),
        ([vec![4, 0x81, 128], vec![0; 128]].concat(), false),
    ] {
        let mut bytes = vec![0xaa, 0xbb];
        bytes.extend_from_slice(&encoding);
        bytes.push(0xcc);
        let value = der::read(&bytes, 2).expect("definite-length element");
        assert_eq!(value.start, 2);
        assert_eq!(value.end(), 2 + encoding.len());
        assert_eq!(value.whole(&bytes), Some(encoding.as_slice()));
        assert_eq!(value.non_minimal_length, non_minimal);
        assert_eq!(value.bytes(&bytes).unwrap().len(), value.len);
    }
}

#[test]
fn shared_tlv_keeps_definite_only_policy() {
    // A valid BER indefinite SEQUENCE is outside this application's DER reader contract.
    assert!(der::read(&[0x30, 0x80, 0x05, 0, 0, 0], 0).is_none());
    assert!(der::read(&[0x30, 2, 0x05, 0], 0).is_some());
}
