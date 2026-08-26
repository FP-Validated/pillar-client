use pillar_client::obfuscate_urls;

#[test]
fn obfuscate_urls_leaves_strings_with_no_urls_like_typescript_client() {
    assert_eq!(
        obfuscate_urls("some error without any URLs"),
        "some error without any URLs"
    );
}

#[test]
fn obfuscate_urls_leaves_empty_string_like_typescript_client() {
    assert_eq!(obfuscate_urls(""), "");
}
