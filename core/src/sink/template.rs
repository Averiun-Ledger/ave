//! Shared placeholder template for sink transports.
//!
//! Replaces the `{{subject-id}}` and `{{schema-id}}` placeholders in
//! transport addresses (HTTP URLs, Kafka topic names).

use percent_encoding::{AsciiSet, CONTROLS, utf8_percent_encode};

/// Compiled template that replaces `{{subject-id}}` and `{{schema-id}}`.
#[derive(Debug, Clone)]
pub struct CompiledTemplate {
    template: String,
    /// Whether the template contains the `{{event-type}}` placeholder.
    has_event_type: bool,
}

/// RFC 3986 path segment encode set: unreserved + sub-delimiters allowed,
/// everything else percent-encoded.
const PATH_SEGMENT_ENCODE_SET: &AsciiSet = &CONTROLS
    .add(b' ')
    .add(b'"')
    .add(b'#')
    .add(b'<')
    .add(b'>')
    .add(b'`')
    .add(b'?')
    .add(b'[')
    .add(b']')
    .add(b'{')
    .add(b'}')
    .add(b'/')
    .add(b'%');

impl CompiledTemplate {
    pub fn new(template: &str) -> Self {
        Self {
            has_event_type: template.contains("{{event-type}}"),
            template: template.to_owned(),
        }
    }

    /// Whether the template routes by event type (`{{event-type}}`).
    pub const fn has_event_type(&self) -> bool {
        self.has_event_type
    }

    /// Replace the placeholders with the raw values (e.g. Kafka topic names).
    pub fn render(&self, subject_id: &str, schema_id: &str) -> String {
        self.template
            .replace("{{subject-id}}", subject_id)
            .replace("{{schema-id}}", schema_id)
    }

    /// Replace the placeholders with the raw values, including `{{event-type}}`.
    pub fn render_with_event_type(
        &self,
        subject_id: &str,
        schema_id: &str,
        event_type: &str,
    ) -> String {
        self.template
            .replace("{{subject-id}}", subject_id)
            .replace("{{schema-id}}", schema_id)
            .replace("{{event-type}}", event_type)
    }

    /// Replace the placeholders with percent-encoded values, safe to embed
    /// in a URL path segment.
    pub fn render_url_encoded(
        &self,
        subject_id: &str,
        schema_id: &str,
    ) -> String {
        let encoded_subject =
            utf8_percent_encode(subject_id, PATH_SEGMENT_ENCODE_SET);
        let encoded_schema =
            utf8_percent_encode(schema_id, PATH_SEGMENT_ENCODE_SET);
        self.render(&encoded_subject.to_string(), &encoded_schema.to_string())
    }

    /// Replace all placeholders, including `{{event-type}}`, with
    /// percent-encoded values, safe to embed in a URL path segment.
    pub fn render_url_encoded_with_event_type(
        &self,
        subject_id: &str,
        schema_id: &str,
        event_type: &str,
    ) -> String {
        let encoded_subject =
            utf8_percent_encode(subject_id, PATH_SEGMENT_ENCODE_SET);
        let encoded_schema =
            utf8_percent_encode(schema_id, PATH_SEGMENT_ENCODE_SET);
        let encoded_event_type =
            utf8_percent_encode(event_type, PATH_SEGMENT_ENCODE_SET);
        self.render_with_event_type(
            &encoded_subject.to_string(),
            &encoded_schema.to_string(),
            &encoded_event_type.to_string(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_url_encoded_with_event_type_encodes_all_values() {
        let template = CompiledTemplate::new(
            "https://sink.example/{{schema-id}}/{{subject-id}}/{{event-type}}",
        );
        assert!(template.has_event_type());
        assert_eq!(
            template.render_url_encoded_with_event_type(
                "subject/with slash",
                "schema#1",
                "fact",
            ),
            "https://sink.example/schema%231/subject%2Fwith%20slash/fact"
        );
    }

    #[test]
    fn render_url_encoded_with_event_type_without_placeholder() {
        let template =
            CompiledTemplate::new("https://sink.example/{{subject-id}}");
        assert!(!template.has_event_type());
        // A template without the placeholder renders identically through
        // both variants.
        assert_eq!(
            template.render_url_encoded_with_event_type("s", "x", "fact"),
            template.render_url_encoded("s", "x")
        );
    }
}
