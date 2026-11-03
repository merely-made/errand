use super::*;

const RSS: &str = r#"<?xml version="1.0"?>
<rss version="2.0"><channel>
  <title>Capsule Log</title>
  <link>https://example.test/</link>
  <description>News &amp; notes</description>
  <language>en</language>
  <item>
    <title>First post</title>
    <link>https://example.test/1</link>
    <pubDate>Mon, 01 Jan 2026 00:00:00 GMT</pubDate>
    <description>A &lt;b&gt;bold&lt;/b&gt; summary.</description>
  </item>
  <item>
    <title>Second post</title>
    <link>https://example.test/2</link>
  </item>
</channel></rss>"#;

const ATOM: &str = r#"<?xml version="1.0"?>
<feed xmlns="http://www.w3.org/2005/Atom">
  <title>Atom Capsule</title>
  <link href="https://atom.test/" rel="alternate"/>
  <subtitle>An atom feed</subtitle>
  <entry>
    <title>Atom one</title>
    <link href="https://atom.test/a" rel="alternate"/>
    <updated>2026-01-01T00:00:00Z</updated>
    <summary>Plain summary.</summary>
  </entry>
</feed>"#;

const PODCAST_RSS: &str = r#"<?xml version="1.0"?>
<rss version="2.0"
  xmlns:itunes="http://www.itunes.com/dtds/podcast-1.0.dtd"
  xmlns:podcast="https://podcastindex.org/namespace/1.0"
  xmlns:mystery="https://example.test/mystery">
  <channel>
    <title>Field Notes</title>
    <itunes:image href="/art/feed.jpg"/>
    <item>
      <guid isPermaLink="false">episode-42</guid>
      <title>Wetland</title>
      <link>/episodes/42</link>
      <enclosure url="/audio/42.mp3" type="audio/mpeg" length="123456"/>
      <itunes:duration>01:02:03</itunes:duration>
      <itunes:image href="/art/42.jpg"/>
      <podcast:chapters url="/chapters/42.json" type="application/json+chapters"/>
      <podcast:transcript url="/transcripts/42.vtt" type="text/vtt" language="en" rel="captions"/>
      <mystery:waveform bins="32"/>
    </item>
  </channel>
</rss>"#;

#[test]
fn rss_parses_channel_and_items() {
    let feed = parse(RSS).expect("rss");
    assert_eq!(feed.title.as_deref(), Some("Capsule Log"));
    assert_eq!(feed.link.as_deref(), Some("https://example.test/"));
    assert_eq!(feed.subtitle.as_deref(), Some("News & notes"));
    assert_eq!(feed.lang.as_deref(), Some("en"));
    assert_eq!(feed.entries.len(), 2);
    assert_eq!(feed.entries[0].title.as_deref(), Some("First post"));
    assert_eq!(
        feed.entries[0].link.as_deref(),
        Some("https://example.test/1")
    );
    assert_eq!(feed.entries[0].summary.as_deref(), Some("A bold summary."));
    assert_eq!(
        feed.html_stripped, 1,
        "the first item's HTML summary was stripped"
    );
}

#[test]
fn atom_uses_link_href_attributes() {
    let feed = parse(ATOM).expect("atom");
    assert_eq!(feed.title.as_deref(), Some("Atom Capsule"));
    assert_eq!(feed.link.as_deref(), Some("https://atom.test/"));
    assert_eq!(feed.subtitle.as_deref(), Some("An atom feed"));
    assert_eq!(feed.entries.len(), 1);
    assert_eq!(feed.entries[0].link.as_deref(), Some("https://atom.test/a"));
    assert_eq!(
        feed.entries[0].date.as_deref(),
        Some("2026-01-01T00:00:00Z")
    );
}

#[test]
fn podcast_extensions_retain_raw_resources_and_diagnose_unknown_namespaces() {
    let feed = parse(PODCAST_RSS).expect("podcast rss");
    assert_eq!(feed.artwork.as_deref(), Some("/art/feed.jpg"));
    let entry = &feed.entries[0];
    assert_eq!(entry.guid.as_deref(), Some("episode-42"));
    assert_eq!(entry.duration.as_deref(), Some("01:02:03"));
    assert_eq!(entry.artwork.as_deref(), Some("/art/42.jpg"));
    assert_eq!(
        entry.enclosures,
        [FeedEnclosure {
            url: "/audio/42.mp3".into(),
            media_type: Some("audio/mpeg".into()),
            byte_length: Some(123_456),
        }]
    );
    assert_eq!(entry.chapters[0].url, "/chapters/42.json");
    assert_eq!(entry.transcripts[0].url, "/transcripts/42.vtt");
    assert_eq!(entry.transcripts[0].language.as_deref(), Some("en"));
    assert!(
        feed.diagnostics
            .iter()
            .any(|diagnostic| diagnostic.contains("mystery:waveform"))
    );
}

#[test]
fn atom_enclosure_and_id_use_the_same_entry_facts() {
    let feed = parse(
        r#"<feed xmlns="http://www.w3.org/2005/Atom">
              <title>Audio</title>
              <entry>
                <id>tag:example.test,2026:7</id>
                <title>Seven</title>
                <link rel="alternate" href="/seven"/>
                <link rel="enclosure" href="/seven.ogg" type="audio/ogg" length="77"/>
              </entry>
            </feed>"#,
    )
    .unwrap();
    let entry = &feed.entries[0];
    assert_eq!(entry.guid.as_deref(), Some("tag:example.test,2026:7"));
    assert_eq!(entry.link.as_deref(), Some("/seven"));
    assert_eq!(entry.enclosures[0].url, "/seven.ogg");
    assert_eq!(entry.enclosures[0].byte_length, Some(77));
}

#[test]
fn dates_and_bodies_stay_apart() {
    let rss = r#"<?xml version="1.0"?>
<rss version="2.0" xmlns:content="http://purl.org/rss/1.0/modules/content/">
  <channel><title>Log</title>
    <item>
      <title>Post</title>
      <guid>post-1</guid>
      <pubDate>Mon, 01 Jan 2026 00:00:00 GMT</pubDate>
      <description>Short &lt;i&gt;teaser&lt;/i&gt;.</description>
      <content:encoded><![CDATA[<p>The <b>whole</b> post.</p>]]></content:encoded>
    </item>
  </channel>
</rss>"#;
    let entry = &parse(rss).unwrap().entries[0];
    assert_eq!(
        entry.published.as_deref(),
        Some("Mon, 01 Jan 2026 00:00:00 GMT")
    );
    assert_eq!(entry.updated, None);
    assert_eq!(entry.summary.as_deref(), Some("Short teaser."));
    assert_eq!(
        entry.content.as_deref(),
        Some("<p>The <b>whole</b> post.</p>")
    );

    let atom = r#"<?xml version="1.0"?>
<feed xmlns="http://www.w3.org/2005/Atom">
  <title>Log</title>
  <entry>
    <title>Post</title>
    <id>urn:post:2</id>
    <published>2026-01-01T00:00:00Z</published>
    <updated>2026-02-01T00:00:00Z</updated>
    <content type="html">&lt;p&gt;Only a body.&lt;/p&gt;</content>
  </entry>
</feed>"#;
    let entry = &parse(atom).unwrap().entries[0];
    assert_eq!(entry.date.as_deref(), Some("2026-01-01T00:00:00Z"));
    assert_eq!(entry.published.as_deref(), Some("2026-01-01T00:00:00Z"));
    assert_eq!(entry.updated.as_deref(), Some("2026-02-01T00:00:00Z"));
    assert_eq!(entry.content.as_deref(), Some("<p>Only a body.</p>"));
    assert_eq!(
        entry.summary.as_deref(),
        Some("Only a body."),
        "an entry with no summary shows its stripped body"
    );
}

#[test]
fn truncated_feed_errors() {
    assert!(parse("<rss><channel><title>X").is_err());
}

#[test]
fn strip_html_tags_collapses_whitespace() {
    assert_eq!(strip_html_tags("<p>a   <b>b</b></p>"), "a b");
}
