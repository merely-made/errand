use super::*;

fn split(u: &str) -> (char, String) {
    split_path(&Url::parse(u).unwrap())
}

#[test]
fn root_path_is_a_menu() {
    assert_eq!(split("gopher://example.org/"), ('1', String::new()));
    assert_eq!(split("gopher://example.org"), ('1', String::new()));
}

#[test]
fn type_and_selector_split_at_the_first_char() {
    assert_eq!(
        split("gopher://example.org/0/about.txt"),
        ('0', "/about.txt".into())
    );
    assert_eq!(split("gopher://example.org/1/dir"), ('1', "/dir".into()));
}

#[test]
fn mime_inference() {
    assert_eq!(mime_for_item_type('0'), "text/plain");
    assert_eq!(mime_for_item_type('1'), "application/gopher-menu");
    assert_eq!(mime_for_item_type('9'), "application/octet-stream");
}

#[tokio::test]
async fn a_url_without_a_host_is_refused_before_connecting() {
    let error = fetch("gopher:///0/x").await.unwrap_err();
    assert!(matches!(error, ClientError::BadUrl(_)), "got {error:?}");
}

#[test]
fn plus_tokens_match_the_spec() {
    assert_eq!(PlusRequest::Item(None).token(), "+");
    assert_eq!(
        PlusRequest::Item(Some("text/plain".into())).token(),
        "+text/plain"
    );
    assert_eq!(PlusRequest::Attributes.token(), "!");
    assert_eq!(PlusRequest::DirectoryAttributes.token(), "$");
}

#[test]
fn the_period_terminator_goes_but_the_last_newline_stays() {
    assert_eq!(
        strip_period_terminator(b"one\r\ntwo\r\n.\r\n".to_vec()),
        b"one\r\ntwo\r\n".to_vec()
    );
    assert_eq!(
        strip_period_terminator(b"one\ntwo\n.\n".to_vec()),
        b"one\ntwo\n".to_vec()
    );
}

#[test]
fn a_body_that_merely_ends_in_a_period_is_left_alone() {
    assert_eq!(
        strip_period_terminator(b"see fig. 1.".to_vec()),
        b"see fig. 1.".to_vec()
    );
}
