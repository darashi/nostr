// Copyright (c) 2021 Paul Miller
// Copyright (c) 2022-2023 Yuki Kishimoto
// Distributed under the MIT software license

//! Relay messages

use alloc::boxed::Box;
use alloc::string::{String, ToString};
use core::fmt;

use serde::{Deserialize, Deserializer};
use serde::{Serialize, Serializer};
use serde_json::{json, Value};

mod raw;

pub use self::raw::RawRelayMessage;
use super::MessageHandleError;
use crate::{Event, EventId, JsonUtil, SubscriptionId};

/// Negentropy error code
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum NegentropyErrorCode {
    /// Results too big
    ResultsTooBig,
    /// Because the NEG-OPEN queries are stateful, relays may choose to time-out inactive queries to recover memory resources
    Closed,
    /// If an event ID is used as the filter, this error will be returned if the relay does not have this event.
    /// The client should retry with the full filter, or upload the event to the relay.
    FilterNotFound,
    /// The event's content was not valid JSON, or the filter was invalid for some other reason.
    FilterInvalid,
    /// Other
    Other(String),
}

impl fmt::Display for NegentropyErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ResultsTooBig => write!(f, "RESULTS_TOO_BIG"),
            Self::Closed => write!(f, "CLOSED"),
            Self::FilterNotFound => write!(f, "FILTER_NOT_FOUND"),
            Self::FilterInvalid => write!(f, "FILTER_INVALID"),
            Self::Other(e) => write!(f, "{e}"),
        }
    }
}

impl<S> From<S> for NegentropyErrorCode
where
    S: Into<String>,
{
    fn from(code: S) -> Self {
        let code: String = code.into();
        match code.as_str() {
            "RESULTS_TOO_BIG" => Self::ResultsTooBig,
            "CLOSED" => Self::Closed,
            "FILTER_NOT_FOUND" => Self::FilterNotFound,
            "FILTER_INVALID" => Self::FilterInvalid,
            _ => Self::Other(code),
        }
    }
}

impl Serialize for NegentropyErrorCode {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for NegentropyErrorCode {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = Value::deserialize(deserializer)?;
        let alphaber: String = serde_json::from_value(value).map_err(serde::de::Error::custom)?;
        Ok(Self::from(alphaber))
    }
}

/// Messages sent by relays, received by clients
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RelayMessage {
    /// `["EVENT", <subscription_id>, <event JSON>]` (NIP01)
    Event {
        /// Subscription ID
        subscription_id: SubscriptionId,
        /// Event
        event: Box<Event>,
    },
    /// `["OK", <event_id>, <true|false>, <message>]` (NIP01)
    Ok {
        /// Event ID
        event_id: EventId,
        /// Status
        status: bool,
        /// Message
        message: String,
    },
    /// `["EOSE", <subscription_id>]` (NIP01)
    EndOfStoredEvents(SubscriptionId),
    /// ["NOTICE", \<message\>] (NIP01)
    Notice {
        /// Message
        message: String,
    },
    /// `["AUTH", <challenge-string>]` (NIP42)
    Auth {
        /// Challenge
        challenge: String,
    },
    /// `["COUNT", <subscription_id>, {"count": <integer>}]` (NIP45)
    Count {
        /// Subscription ID
        subscription_id: SubscriptionId,
        /// Events count
        count: usize,
    },
    /// Negentropy Message
    NegMsg {
        /// Subscription ID
        subscription_id: SubscriptionId,
        /// Message
        message: String,
    },
    /// Negentropy Error
    NegErr {
        /// Subscription ID
        subscription_id: SubscriptionId,
        /// Error code
        code: NegentropyErrorCode,
    },
}

impl Serialize for RelayMessage {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let json_value: Value = self.as_value();
        json_value.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for RelayMessage {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let json_value = Value::deserialize(deserializer)?;
        RelayMessage::from_value(json_value).map_err(serde::de::Error::custom)
    }
}

impl RelayMessage {
    /// Create new `EVENT` message
    pub fn new_event(subscription_id: SubscriptionId, event: Event) -> Self {
        Self::Event {
            subscription_id,
            event: Box::new(event),
        }
    }

    /// Create new `NOTICE` message
    pub fn new_notice<S>(message: S) -> Self
    where
        S: Into<String>,
    {
        Self::Notice {
            message: message.into(),
        }
    }

    /// Create new `EOSE` message
    pub fn new_eose(subscription_id: SubscriptionId) -> Self {
        Self::EndOfStoredEvents(subscription_id)
    }

    /// Create new `OK` message
    pub fn new_ok<S>(event_id: EventId, status: bool, message: S) -> Self
    where
        S: Into<String>,
    {
        Self::Ok {
            event_id,
            status,
            message: message.into(),
        }
    }

    /// Create new `AUTH` message
    pub fn new_auth<S>(challenge: S) -> Self
    where
        S: Into<String>,
    {
        Self::Auth {
            challenge: challenge.into(),
        }
    }

    /// Create new `EVENT` message
    pub fn new_count(subscription_id: SubscriptionId, count: usize) -> Self {
        Self::Count {
            subscription_id,
            count,
        }
    }

    fn as_value(&self) -> Value {
        match self {
            Self::Event {
                event,
                subscription_id,
            } => json!(["EVENT", subscription_id, event]),
            Self::Notice { message } => json!(["NOTICE", message]),
            Self::EndOfStoredEvents(subscription_id) => {
                json!(["EOSE", subscription_id])
            }
            Self::Ok {
                event_id,
                status,
                message,
            } => json!(["OK", event_id, status, message]),
            Self::Auth { challenge } => json!(["AUTH", challenge]),
            Self::Count {
                subscription_id,
                count,
            } => json!(["COUNT", subscription_id, { "count": count }]),
            Self::NegMsg {
                subscription_id,
                message,
            } => json!(["NEG-MSG", subscription_id, message]),
            Self::NegErr {
                subscription_id,
                code,
            } => json!(["NEG-ERR", subscription_id, code]),
        }
    }

    /// Deserialize [`RelayMessage`] from [`Value`]
    pub fn from_value(msg: Value) -> Result<Self, MessageHandleError> {
        let raw = RawRelayMessage::from_value(msg)?;
        RelayMessage::try_from(raw)
    }
}

impl JsonUtil for RelayMessage {
    type Err = MessageHandleError;

    /// Deserialize [`RelayMessage`] from JSON string
    ///
    /// **This method NOT verify the event signature!**
    fn from_json<T>(json: T) -> Result<Self, Self::Err>
    where
        T: AsRef<[u8]>,
    {
        let msg: &[u8] = json.as_ref();

        if msg.is_empty() {
            return Err(MessageHandleError::EmptyMsg);
        }

        let value: Value = serde_json::from_slice(msg)?;
        Self::from_value(value)
    }
}

impl TryFrom<RawRelayMessage> for RelayMessage {
    type Error = MessageHandleError;

    fn try_from(raw: RawRelayMessage) -> Result<Self, Self::Error> {
        match raw {
            RawRelayMessage::Event {
                subscription_id,
                event,
            } => Ok(Self::Event {
                subscription_id: SubscriptionId::new(subscription_id),
                event: Box::new(Event::from_value(event)?),
            }),
            RawRelayMessage::Ok {
                event_id,
                status,
                message,
            } => Ok(Self::Ok {
                event_id: EventId::from_hex(event_id)?,
                status,
                message,
            }),
            RawRelayMessage::EndOfStoredEvents(subscription_id) => Ok(Self::EndOfStoredEvents(
                SubscriptionId::new(subscription_id),
            )),
            RawRelayMessage::Notice { message } => Ok(Self::Notice { message }),
            RawRelayMessage::Auth { challenge } => Ok(Self::Auth { challenge }),
            RawRelayMessage::Count {
                subscription_id,
                count,
            } => Ok(Self::Count {
                subscription_id: SubscriptionId::new(subscription_id),
                count,
            }),
            RawRelayMessage::NegMsg {
                subscription_id,
                message,
            } => Ok(Self::NegMsg {
                subscription_id: SubscriptionId::new(subscription_id),
                message,
            }),
            RawRelayMessage::NegErr {
                subscription_id,
                code,
            } => Ok(Self::NegErr {
                subscription_id: SubscriptionId::new(subscription_id),
                code: NegentropyErrorCode::from(code),
            }),
        }
    }
}

#[cfg(feature = "std")]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::Timestamp;

    #[test]
    fn test_handle_valid_notice() {
        let valid_notice_msg = r#"["NOTICE","Invalid event format!"]"#;
        let handled_valid_notice_msg =
            RelayMessage::new_notice(String::from("Invalid event format!"));

        assert_eq!(
            RelayMessage::from_json(valid_notice_msg).unwrap(),
            handled_valid_notice_msg
        );
    }
    #[test]
    fn test_handle_invalid_notice() {
        //Missing content
        let invalid_notice_msg = r#"["NOTICE"]"#;
        //The content is not string
        let invalid_notice_msg_content = r#"["NOTICE": 404]"#;

        assert!(RelayMessage::from_json(invalid_notice_msg).is_err(),);
        assert!(RelayMessage::from_json(invalid_notice_msg_content).is_err(),);
    }

    #[test]
    fn test_handle_valid_event() {
        let valid_event_msg = r#"["EVENT", "random_string", {"id":"70b10f70c1318967eddf12527799411b1a9780ad9c43858f5e5fcd45486a13a5","pubkey":"379e863e8357163b5bce5d2688dc4f1dcc2d505222fb8d74db600f30535dfdfe","created_at":1612809991,"kind":1,"tags":[],"content":"test","sig":"273a9cd5d11455590f4359500bccb7a89428262b96b3ea87a756b770964472f8c3e87f5d5e64d8d2e859a71462a3f477b554565c4f2f326cb01dd7620db71502"}]"#;

        let id = "70b10f70c1318967eddf12527799411b1a9780ad9c43858f5e5fcd45486a13a5";
        let pubkey = "379e863e8357163b5bce5d2688dc4f1dcc2d505222fb8d74db600f30535dfdfe";
        let created_at = Timestamp::from(1612809991);
        let kind = 1;
        let tags = vec![];
        let content = "test";
        let sig = "273a9cd5d11455590f4359500bccb7a89428262b96b3ea87a756b770964472f8c3e87f5d5e64d8d2e859a71462a3f477b554565c4f2f326cb01dd7620db71502";

        let handled_event = Event::new_dummy(id, pubkey, created_at, kind, tags, content, sig);

        assert_eq!(
            RelayMessage::from_json(valid_event_msg).unwrap(),
            RelayMessage::new_event(SubscriptionId::new("random_string"), handled_event)
        );
    }

    #[test]
    fn test_handle_invalid_event() {
        // Missing Event field
        let invalid_event_msg = r#"["EVENT", "random_string"]"#;
        //Event JSON with incomplete content
        let invalid_event_msg_content = r#"["EVENT", "random_string", {"id":"70b10f70c1318967eddf12527799411b1a9780ad9c43858f5e5fcd45486a13a5","pubkey":"379e863e8357163b5bce5d2688dc4f1dcc2d505222fb8d74db600f30535dfdfe"}]"#;

        assert!(RelayMessage::from_json(invalid_event_msg).is_err(),);

        assert!(RelayMessage::from_json(invalid_event_msg_content).is_err(),);
    }

    #[test]
    fn test_handle_valid_eose() {
        let valid_eose_msg = r#"["EOSE","random-subscription-id"]"#;
        let handled_valid_eose_msg =
            RelayMessage::new_eose(SubscriptionId::new("random-subscription-id"));

        assert_eq!(
            RelayMessage::from_json(valid_eose_msg).unwrap(),
            handled_valid_eose_msg
        );
    }
    #[test]
    fn test_handle_invalid_eose() {
        // Missing subscription ID
        assert!(RelayMessage::from_json(r#"["EOSE"]"#).is_err(),);

        // The subscription ID is not string
        assert!(RelayMessage::from_json(r#"["EOSE", 404]"#).is_err(),);
    }

    #[test]
    fn test_handle_valid_ok() {
        let valid_ok_msg = r#"["OK", "b1a649ebe8b435ec71d3784793f3bbf4b93e64e17568a741aecd4c7ddeafce30", true, "pow: difficulty 25>=24"]"#;
        let handled_valid_ok_msg = RelayMessage::new_ok(
            EventId::from_hex("b1a649ebe8b435ec71d3784793f3bbf4b93e64e17568a741aecd4c7ddeafce30")
                .unwrap(),
            true,
            "pow: difficulty 25>=24",
        );

        assert_eq!(
            RelayMessage::from_json(valid_ok_msg).unwrap(),
            handled_valid_ok_msg
        );
    }
    #[test]
    fn test_handle_invalid_ok() {
        // Missing params
        assert!(RelayMessage::from_json(
            r#"["OK", "b1a649ebe8b435ec71d3784793f3bbf4b93e64e17568a741aecd4c7ddeafce30"]"#
        )
        .is_err(),);

        // Invalid event_id
        assert!(RelayMessage::from_json(
            r#"["OK", "b1a649ebe8b435ec71d3784793f3bbf4b93e64e17568a741aecd4c7dde", true, ""]"#
        )
        .is_err(),);

        // Invalid status
        assert!(
            RelayMessage::from_json(r#"["OK", "b1a649ebe8b435ec71d3784793f3bbf4b93e64e17568a741aecd4c7ddeafce30", hello, ""]"#).is_err(),
        );

        // Invalid message
        assert!(
            RelayMessage::from_json(r#"["OK", "b1a649ebe8b435ec71d3784793f3bbf4b93e64e17568a741aecd4c7ddeafce30", hello, 404]"#).is_err()
        );
    }

    #[test]
    fn parse_message() {
        // Got this fresh off the wire
        pub const SAMPLE_EVENT: &'static str = r#"["EVENT", "random_string", {"id":"70b10f70c1318967eddf12527799411b1a9780ad9c43858f5e5fcd45486a13a5","pubkey":"379e863e8357163b5bce5d2688dc4f1dcc2d505222fb8d74db600f30535dfdfe","created_at":1612809991,"kind":1,"tags":[],"content":"test","sig":"273a9cd5d11455590f4359500bccb7a89428262b96b3ea87a756b770964472f8c3e87f5d5e64d8d2e859a71462a3f477b554565c4f2f326cb01dd7620db71502"}]"#;

        // Hand parsed version as a sanity check
        let id = "70b10f70c1318967eddf12527799411b1a9780ad9c43858f5e5fcd45486a13a5";
        let pubkey = "379e863e8357163b5bce5d2688dc4f1dcc2d505222fb8d74db600f30535dfdfe";
        let created_at = Timestamp::from(1612809991);
        let kind = 1;
        let tags = Vec::new();
        let content = "test";
        let sig = "273a9cd5d11455590f4359500bccb7a89428262b96b3ea87a756b770964472f8c3e87f5d5e64d8d2e859a71462a3f477b554565c4f2f326cb01dd7620db71502";

        let event = Event::new_dummy(id, pubkey, created_at, kind, tags, content, sig);

        let parsed_event = RelayMessage::from_json(SAMPLE_EVENT).expect("Failed to parse event");

        assert_eq!(
            parsed_event,
            RelayMessage::new_event(SubscriptionId::new("random_string"), event)
        );
    }

    #[test]
    fn test_raw_relay_message() {
        pub const SAMPLE_EVENT: &'static str = r#"["EVENT", "random_string", {"id":"70b10f70c1318967eddf12527799411b1a9780ad9c43858f5e5fcd45486a13a5","pubkey":"379e863e8357163b5bce5d2688dc4f1dcc2d505222fb8d74db600f30535dfdfe","created_at":1612809991,"kind":1,"tags":[],"content":"test","sig":"273a9cd5d11455590f4359500bccb7a89428262b96b3ea87a756b770964472f8c3e87f5d5e64d8d2e859a71462a3f477b554565c4f2f326cb01dd7620db71502"}]"#;

        let raw = RawRelayMessage::from_json(SAMPLE_EVENT).unwrap();
        let msg = RelayMessage::try_from(raw).unwrap();

        assert_eq!(msg, RelayMessage::from_json(SAMPLE_EVENT).unwrap());
    }
}
