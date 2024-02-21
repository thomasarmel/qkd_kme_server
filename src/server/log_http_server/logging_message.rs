use chrono;
use chrono::{DateTime, Utc};
use serde::{Serialize, Serializer};

#[derive(Debug, Clone, Serialize)]
pub(super) struct LoggingMessage {
    message: String,
    #[serde(serialize_with = "LoggingMessage::serialize_datetime_json")]
    datetime: DateTime<Utc>,
}

impl LoggingMessage {
    pub(super) fn new(message: &str) -> Self {
        Self {
            message: message.to_string(),
            datetime: Utc::now(),
        }
    }

    fn serialize_datetime_json<S: Serializer>(dt: &DateTime<Utc>, serializer: S) -> Result<S::Ok, S::Error> {
        format!("{:?}", dt).serialize(serializer)
    }
}

#[cfg(test)]
mod tests {
    use regex::Regex;
    use super::*;
    use serde_json;

    #[test]
    fn test_logging_message() {
        const MESSAGE: &'static str = "Test message";
        let log_message = LoggingMessage::new(MESSAGE);
        let json = serde_json::to_string(&log_message).unwrap();
        assert!(json.contains(MESSAGE));
        let check_json_regex = Regex::new(r#"\{"message":"Test message","datetime":"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+Z"}"#).unwrap();
        assert!(check_json_regex.is_match(&json));
    }
}