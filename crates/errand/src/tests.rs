use super::*;

#[test]
fn scheme_round_trips_and_ports() {
    assert_eq!(Scheme::parse("gemini"), Some(Scheme::Gemini));
    assert_eq!(
        Scheme::parse("spartan").map(Scheme::default_port),
        Some(300)
    );
    assert_eq!(Scheme::parse("https"), None);
}

#[test]
fn new_schemes_round_trip() {
    assert_eq!(Scheme::parse("nex").map(Scheme::default_port), Some(1900));
    assert_eq!(Scheme::parse("guppy").map(Scheme::default_port), Some(6775));
    assert_eq!(Scheme::parse("titan").map(Scheme::default_port), Some(1965));
}

#[test]
fn trace_url_omits_query_and_fragment() {
    let url = Url::parse("gemini://capsule.example/search?secret%20answer#part").unwrap();
    assert_eq!(trace_url(&url).as_str(), "gemini://capsule.example/search");
}

#[test]
fn mime_strips_params_and_gates_on_success() {
    let mut r = Response {
        url: Url::parse("gemini://x/").unwrap(),
        status: Status::Success,
        raw_status: Some(20),
        meta: "text/gemini; charset=utf-8".into(),
        body: Vec::new(),
    };
    assert_eq!(r.mime(), Some("text/gemini"));
    r.status = Status::Failure;
    assert_eq!(r.mime(), None, "non-success has no mime");
}

#[tokio::test]
async fn http_is_not_routed() {
    let err = fetch("https://example.com/").await.unwrap_err();
    assert!(matches!(err, Error::UnsupportedScheme(s) if s == "https"));
}

#[tokio::test]
async fn identity_fetch_refuses_non_gemini_before_transport() {
    let url = Url::parse("gopher://example.test/").unwrap();
    let identity = GeminiClientIdentity {
        certificate_der: b"certificate",
        private_key_pkcs8_der: b"private-key",
    };
    assert!(matches!(
        fetch_url_with_identity(&url, identity).await,
        Err(Error::UnsupportedScheme(scheme)) if scheme == "gopher"
    ));
}

#[test]
fn every_smolweb_scheme_is_recognized() {
    for s in [
        "gemini", "gopher", "finger", "spartan", "nex", "guppy", "titan",
    ] {
        assert!(Scheme::parse(s).is_some(), "{s} should route");
    }
}

#[test]
fn timeout_error_displays() {
    assert_eq!(Error::Timeout.to_string(), "fetch timed out");
}
