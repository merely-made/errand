// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

//! Feed parser — RSS 2.0 and Atom 1.0 into a portable [`Feed`].
//!
//! The two XML flavours share one event-driven walker: they differ in element
//! names but share the same logical shape — a feed-level title plus a sequence of
//! entries, each with ordinary document facts plus raw podcast enclosure and
//! extension resources. RSS expresses links as element text; Atom uses
//! `<link href=…>` attributes.
//!
//! Summary handling is deliberately lossy: HTML in `<description>` / `<content>`
//! is stripped to plain text (see [`strip_html_tags`]), and the count of stripped
//! entries is reported in [`Feed::html_stripped`] so a consumer can surface a
//! "degraded" hint. JSON Feed is *not* handled here (it needs a JSON dependency a
//! transport crate should not carry); a consumer parses it and builds a [`Feed`]
//! itself — the public fields make that straightforward.

use quick_xml::Reader;
use quick_xml::escape::unescape;
use quick_xml::events::Event;

/// A parsed feed: channel-level metadata plus entries, flavour-neutral.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Feed {
    pub title: Option<String>,
    pub subtitle: Option<String>,
    pub link: Option<String>,
    pub lang: Option<String>,
    pub artwork: Option<String>,
    pub entries: Vec<FeedEntry>,
    /// How many entry summaries had HTML stripped (for a degraded-rendering hint).
    pub html_stripped: usize,
    /// Namespaced elements that were not understood and therefore could not be
    /// projected losslessly.
    pub diagnostics: Vec<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FeedEnclosure {
    pub url: String,
    pub media_type: Option<String>,
    pub byte_length: Option<u64>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PodcastResource {
    pub url: String,
    pub media_type: Option<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PodcastTranscript {
    pub url: String,
    pub media_type: Option<String>,
    pub language: Option<String>,
    pub rel: Option<String>,
}

/// One feed entry.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FeedEntry {
    pub guid: Option<String>,
    pub title: Option<String>,
    pub link: Option<String>,
    pub date: Option<String>,
    pub summary: Option<String>,
    pub enclosures: Vec<FeedEnclosure>,
    pub duration: Option<String>,
    pub artwork: Option<String>,
    pub chapters: Vec<PodcastResource>,
    pub transcripts: Vec<PodcastTranscript>,
}

/// A feed parse error (malformed or truncated XML).
#[derive(Clone, Debug)]
pub struct FeedError(pub String);

impl std::fmt::Display for FeedError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "feed parse error: {}", self.0)
    }
}

impl std::error::Error for FeedError {}

/// Parse an RSS 2.0 or Atom 1.0 document into a [`Feed`].
pub fn parse(body: &str) -> Result<Feed, FeedError> {
    let mut reader = Reader::from_str(body);
    // Don't enable trim_text: quick-xml splits text events around entity
    // references (`&lt;`, etc.), and trimming each chunk eats the spaces between
    // them. Element-level trimming happens at commit.
    let mut buf = Vec::new();
    let mut state = State::default();

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e)) => {
                let qualified = qualified_name(e.name().as_ref());
                let local = local_name(e.name().as_ref());
                state.start_element(local.clone());
                state.inspect_element(&qualified, &local, element_attributes(&e));
            }
            Ok(Event::Empty(e)) => {
                let qualified = qualified_name(e.name().as_ref());
                let local = local_name(e.name().as_ref());
                state.inspect_element(&qualified, &local, element_attributes(&e));
            }
            Ok(Event::Text(t)) => {
                let raw = std::str::from_utf8(t.as_ref()).map_err(err)?;
                let unescaped = unescape(raw).map_err(err)?.into_owned();
                state.append_text(&unescaped);
            }
            Ok(Event::GeneralRef(r)) => {
                // quick-xml 0.39 emits entity references as their own event,
                // split out of surrounding Text. Resolve and append.
                let name = std::str::from_utf8(r.as_ref()).map_err(err)?;
                let unescaped = unescape(&format!("&{name};")).map_err(err)?.into_owned();
                state.append_text(&unescaped);
            }
            Ok(Event::CData(c)) => {
                let raw = std::str::from_utf8(c.as_ref()).map_err(err)?;
                state.append_text(raw);
            }
            Ok(Event::End(e)) => {
                let qualified = qualified_name(e.name().as_ref());
                let local = local_name(e.name().as_ref());
                state.end_element(&qualified, &local);
            }
            Ok(Event::Eof) => {
                if !state.path.is_empty() {
                    return Err(FeedError(format!(
                        "feed truncated; unclosed element <{}>",
                        state.path.last().map(String::as_str).unwrap_or("?")
                    )));
                }
                break;
            }
            Err(e) => return Err(err(e)),
            _ => {}
        }
        buf.clear();
    }

    Ok(state.feed)
}

/// Naively strip HTML tags from a fragment, preserving text content and
/// collapsing the whitespace that stripping introduces. Shared with consumers
/// (e.g. a JSON Feed path) so summary handling matches across flavours.
pub fn strip_html_tags(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut in_tag = false;
    for ch in input.chars() {
        match ch {
            '<' => in_tag = true,
            '>' => in_tag = false,
            _ if !in_tag => out.push(ch),
            _ => {}
        }
    }
    let mut collapsed = String::with_capacity(out.len());
    let mut prev_ws = false;
    for ch in out.chars() {
        if ch.is_whitespace() {
            if !prev_ws {
                collapsed.push(' ');
            }
            prev_ws = true;
        } else {
            collapsed.push(ch);
            prev_ws = false;
        }
    }
    collapsed.trim().to_string()
}

#[derive(Default)]
struct State {
    path: Vec<String>,
    pending_text: String,
    current_entry: Option<FeedEntry>,
    feed: Feed,
}

impl State {
    fn in_entry(&self) -> bool {
        self.path.iter().any(|p| p == "item" || p == "entry")
    }

    fn start_element(&mut self, name: String) {
        self.pending_text.clear();
        if name == "item" || name == "entry" {
            self.current_entry = Some(FeedEntry::default());
        }
        self.path.push(name);
    }

    /// Apply an ordinary link to the entry or the feed, first-wins.
    fn set_link(&mut self, href: String) {
        if self.in_entry() {
            if let Some(entry) = &mut self.current_entry {
                if entry.link.is_none() {
                    entry.link = Some(href);
                }
            }
        } else if self.feed.link.is_none() {
            self.feed.link = Some(href);
        }
    }

    fn inspect_element(&mut self, qualified: &str, local: &str, attributes: Vec<(String, String)>) {
        if let Some(prefix) = qualified.split_once(':').map(|(prefix, _)| prefix)
            && !matches!(prefix, "atom" | "rss" | "itunes" | "podcast")
        {
            let scope = if self.in_entry() { "entry" } else { "feed" };
            self.feed.diagnostics.push(format!(
                "unsupported extension element <{qualified}> in {scope}"
            ));
        }

        let attribute = |name: &str| {
            attributes
                .iter()
                .find(|(key, _)| key == name)
                .map(|(_, value)| value.clone())
        };
        match (qualified, local) {
            (_, "link") => {
                let Some(href) = attribute("href") else {
                    return;
                };
                if attribute("rel").as_deref() == Some("enclosure") {
                    let byte_length =
                        parsed_length(attribute("length"), &mut self.feed.diagnostics);
                    self.push_enclosure(href, attribute("type"), byte_length);
                } else if attribute("rel")
                    .as_deref()
                    .is_none_or(|rel| rel == "alternate")
                {
                    self.set_link(href);
                }
            }
            (_, "enclosure") => {
                if let Some(url) = attribute("url") {
                    let byte_length =
                        parsed_length(attribute("length"), &mut self.feed.diagnostics);
                    self.push_enclosure(url, attribute("type"), byte_length);
                }
            }
            ("itunes:image", _) => {
                if let Some(href) = attribute("href") {
                    if let Some(entry) = &mut self.current_entry {
                        entry.artwork.get_or_insert(href);
                    } else {
                        self.feed.artwork.get_or_insert(href);
                    }
                }
            }
            ("podcast:chapters", _) => {
                if let (Some(entry), Some(url)) = (&mut self.current_entry, attribute("url")) {
                    entry.chapters.push(PodcastResource {
                        url,
                        media_type: attribute("type"),
                    });
                }
            }
            ("podcast:transcript", _) => {
                if let (Some(entry), Some(url)) = (&mut self.current_entry, attribute("url")) {
                    entry.transcripts.push(PodcastTranscript {
                        url,
                        media_type: attribute("type"),
                        language: attribute("language"),
                        rel: attribute("rel"),
                    });
                }
            }
            _ => {}
        }
    }

    fn push_enclosure(
        &mut self,
        url: String,
        media_type: Option<String>,
        byte_length: Option<u64>,
    ) {
        if let Some(entry) = &mut self.current_entry {
            entry.enclosures.push(FeedEnclosure {
                url,
                media_type,
                byte_length,
            });
        }
    }

    fn end_element(&mut self, qualified: &str, name: &str) {
        let text = std::mem::take(&mut self.pending_text);
        let trimmed = text.trim();
        let parent = self.path.iter().rev().nth(1).map(String::as_str);

        if !trimmed.is_empty() {
            if let Some(entry) = &mut self.current_entry {
                match name {
                    "guid" | "id" => {
                        if entry.guid.is_none() {
                            entry.guid = Some(trimmed.to_string());
                        }
                    }
                    "title" => {
                        if entry.title.is_none() {
                            entry.title = Some(trimmed.to_string());
                        }
                    }
                    "link" => {
                        // Atom emits an empty <link/> with href; only RSS-style
                        // text content reaches here.
                        if entry.link.is_none() {
                            entry.link = Some(trimmed.to_string());
                        }
                    }
                    "pubDate" | "published" | "updated" => {
                        if entry.date.is_none() {
                            entry.date = Some(trimmed.to_string());
                        }
                    }
                    "description" | "summary" | "content" => {
                        if entry.summary.is_none() {
                            let had_tags = trimmed.contains('<');
                            entry.summary = Some(strip_html_tags(trimmed));
                            if had_tags {
                                self.feed.html_stripped += 1;
                            }
                        }
                    }
                    "duration" if qualified == "itunes:duration" => {
                        if entry.duration.is_none() {
                            entry.duration = Some(trimmed.to_string());
                        }
                    }
                    _ => {}
                }
            } else {
                match name {
                    "title" => {
                        if matches!(parent, Some("channel") | Some("feed"))
                            && self.feed.title.is_none()
                        {
                            self.feed.title = Some(trimmed.to_string());
                        }
                    }
                    "subtitle" | "description" => {
                        if matches!(parent, Some("channel") | Some("feed"))
                            && self.feed.subtitle.is_none()
                        {
                            self.feed.subtitle = Some(strip_html_tags(trimmed));
                        }
                    }
                    "link" => {
                        if matches!(parent, Some("channel")) && self.feed.link.is_none() {
                            self.feed.link = Some(trimmed.to_string());
                        }
                    }
                    "language" => {
                        if matches!(parent, Some("channel")) && self.feed.lang.is_none() {
                            self.feed.lang = Some(trimmed.to_string());
                        }
                    }
                    _ => {}
                }
            }
        }

        let popped = self.path.pop();
        if popped.as_deref() == Some("item") || popped.as_deref() == Some("entry") {
            if let Some(entry) = self.current_entry.take() {
                if entry.title.is_some()
                    || entry.link.is_some()
                    || entry.guid.is_some()
                    || !entry.enclosures.is_empty()
                    || entry.summary.is_some()
                {
                    self.feed.entries.push(entry);
                }
            }
        }
    }

    fn append_text(&mut self, text: &str) {
        self.pending_text.push_str(text);
    }
}

fn local_name(qualified: &[u8]) -> String {
    let s = std::str::from_utf8(qualified).unwrap_or("");
    s.rsplit(':').next().unwrap_or(s).to_string()
}

fn qualified_name(qualified: &[u8]) -> String {
    std::str::from_utf8(qualified).unwrap_or("").to_string()
}

fn element_attributes(element: &quick_xml::events::BytesStart<'_>) -> Vec<(String, String)> {
    element
        .attributes()
        .flatten()
        .filter_map(|attribute| {
            let key = std::str::from_utf8(attribute.key.local_name().as_ref())
                .ok()?
                .to_string();
            let value = attribute.unescape_value().ok()?.into_owned();
            (!value.is_empty()).then_some((key, value))
        })
        .collect()
}

fn parsed_length(raw: Option<String>, diagnostics: &mut Vec<String>) -> Option<u64> {
    let raw = raw?;
    match raw.parse() {
        Ok(length) => Some(length),
        Err(_) => {
            diagnostics.push(format!("invalid enclosure length {raw:?}"));
            None
        }
    }
}

fn err<E: std::fmt::Display>(e: E) -> FeedError {
    FeedError(e.to_string())
}

#[cfg(test)]
mod tests {
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
    fn truncated_feed_errors() {
        assert!(parse("<rss><channel><title>X").is_err());
    }

    #[test]
    fn strip_html_tags_collapses_whitespace() {
        assert_eq!(strip_html_tags("<p>a   <b>b</b></p>"), "a b");
    }
}
