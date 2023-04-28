// Copyright (c) 2022-2023 Yuki Kishimoto
// Distributed under the MIT software license

//! Tag

use std::fmt;
use std::num::ParseIntError;
use std::str::FromStr;

use secp256k1::schnorr::Signature;
use secp256k1::XOnlyPublicKey;
use serde::de::Error as DeserializerError;
use serde::ser::SerializeSeq;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use url::Url;

use super::id::{self, EventId};
use crate::nips::nip26::Conditions;
use crate::{Kind, Timestamp};

/// [`Tag`] error
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Impossible to parse [`Marker`]
    #[error("impossible to parse marker")]
    MarkerParseError,
    /// Unknown [`Report`]
    #[error("unknown report type")]
    UnknownReportType,
    /// Impossible to find tag kind
    #[error("impossible to find tag kind")]
    KindNotFound,
    /// Invalid length
    #[error("invalid length")]
    InvalidLength,
    /// Impossible to parse integer
    #[error(transparent)]
    ParseIntError(#[from] ParseIntError),
    /// Secp256k1
    #[error(transparent)]
    Secp256k1(#[from] secp256k1::Error),
    /// Hex decoding error
    #[error(transparent)]
    Hex(#[from] bitcoin_hashes::hex::Error),
    /// Url parse error
    #[error("invalid url")]
    Url(#[from] url::ParseError),
    /// EventId error
    #[error(transparent)]
    EventId(#[from] id::Error),
    /// NIP26 error
    #[error(transparent)]
    Nip26(#[from] crate::nips::nip26::Error),
    /// Event Error
    #[error(transparent)]
    Event(#[from] crate::event::Error),
    /// Invalid Zap Request
    #[error("Invalid Zap request")]
    InvalidZapRequest,
}

/// Marker
#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd)]
pub enum Marker {
    /// Root
    Root,
    /// Reply
    Reply,
    /// Custom
    Custom(String),
}

impl fmt::Display for Marker {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Root => write!(f, "root"),
            Self::Reply => write!(f, "reply"),
            Self::Custom(m) => write!(f, "{m}"),
        }
    }
}

impl<S> From<S> for Marker
where
    S: Into<String>,
{
    fn from(s: S) -> Self {
        let s: String = s.into();
        match s.as_str() {
            "root" => Self::Root,
            "reply" => Self::Reply,
            m => Self::Custom(m.to_string()),
        }
    }
}

/// Report
#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd)]
pub enum Report {
    /// Depictions of nudity, porn, etc
    Nudity,
    /// Profanity, hateful speech, etc.
    Profanity,
    /// Something which may be illegal in some jurisdiction
    ///
    /// Remenber: there is what is right and there is the law.
    Illegal,
    /// Spam
    Spam,
    /// Someone pretending to be someone else
    Impersonation,
}

impl fmt::Display for Report {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Nudity => write!(f, "nudity"),
            Self::Profanity => write!(f, "profanity"),
            Self::Illegal => write!(f, "illegal"),
            Self::Spam => write!(f, "spam"),
            Self::Impersonation => write!(f, "impersonation"),
        }
    }
}

impl TryFrom<&str> for Report {
    type Error = Error;
    fn try_from(s: &str) -> Result<Self, Self::Error> {
        match s {
            "nudity" => Ok(Self::Nudity),
            "profanity" => Ok(Self::Profanity),
            "illegal" => Ok(Self::Illegal),
            "spam" => Ok(Self::Spam),
            "impersonation" => Ok(Self::Impersonation),
            _ => Err(Error::UnknownReportType),
        }
    }
}

/// Tag kind
#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd)]
pub enum TagKind {
    /// Public key
    P,
    /// Event id
    E,
    /// Reference (URL, etc.)
    R,
    /// Hashtag
    T,
    /// Geohash
    G,
    /// Identifier
    D,
    /// Referencing and tagging
    A,
    /// Relay
    Relay,
    /// Nonce
    Nonce,
    /// Delegation
    Delegation,
    /// Content warning
    ContentWarning,
    /// Expiration
    Expiration,
    /// Subject
    Subject,
    /// Auth challenge
    Challenge,
    /// Title (NIP23)
    Title,
    /// Image (NIP23)
    Image,
    /// Summary (NIP23)
    Summary,
    /// PublishedAt (NIP23)
    PublishedAt,
    /// Description (NIP57)
    Description,
    /// Bolt11 Invoice (NIP57)
    Bolt11,
    /// Preimage (NIP57)
    Preimage,
    /// Relays (NIP57)
    Relays,
    /// Amount (NIP57)
    Amount,
    /// Lnurl (NIP57)
    Lnurl,
    /// Custom tag kind
    Custom(String),
}

impl fmt::Display for TagKind {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::P => write!(f, "p"),
            Self::E => write!(f, "e"),
            Self::R => write!(f, "r"),
            Self::T => write!(f, "t"),
            Self::G => write!(f, "g"),
            Self::D => write!(f, "d"),
            Self::A => write!(f, "a"),
            Self::Relay => write!(f, "relay"),
            Self::Nonce => write!(f, "nonce"),
            Self::Delegation => write!(f, "delegation"),
            Self::ContentWarning => write!(f, "content-warning"),
            Self::Expiration => write!(f, "expiration"),
            Self::Subject => write!(f, "subject"),
            Self::Challenge => write!(f, "challenge"),
            Self::Title => write!(f, "title"),
            Self::Image => write!(f, "image"),
            Self::Summary => write!(f, "summary"),
            Self::PublishedAt => write!(f, "published_at"),
            Self::Description => write!(f, "description"),
            Self::Bolt11 => write!(f, "bolt11"),
            Self::Preimage => write!(f, "preimage"),
            Self::Relays => write!(f, "relays"),
            Self::Amount => write!(f, "amount"),
            Self::Lnurl => write!(f, "lnurl"),
            Self::Custom(tag) => write!(f, "{tag}"),
        }
    }
}

impl<S> From<S> for TagKind
where
    S: Into<String>,
{
    fn from(s: S) -> Self {
        let s: String = s.into();
        match s.as_str() {
            "p" => Self::P,
            "e" => Self::E,
            "r" => Self::R,
            "t" => Self::T,
            "g" => Self::G,
            "d" => Self::D,
            "a" => Self::A,
            "relay" => Self::Relay,
            "nonce" => Self::Nonce,
            "delegation" => Self::Delegation,
            "content-warning" => Self::ContentWarning,
            "expiration" => Self::Expiration,
            "subject" => Self::Subject,
            "challenge" => Self::Challenge,
            "title" => Self::Title,
            "image" => Self::Image,
            "summary" => Self::Summary,
            "published_at" => Self::PublishedAt,
            "description" => Self::Description,
            "bolt11" => Self::Bolt11,
            "preimage" => Self::Preimage,
            "relays" => Self::Relays,
            "amount" => Self::Amount,
            "lnurl" => Self::Lnurl,
            tag => Self::Custom(tag.to_string()),
        }
    }
}

/// Unchecked Relay Url
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq, PartialOrd, Ord, Default)]
pub struct UncheckedUrl(String);

impl FromStr for UncheckedUrl {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self(s.to_owned()))
    }
}

impl From<Url> for UncheckedUrl {
    fn from(url: Url) -> Self {
        let url_string = url.to_string();
        Self(url_string)
    }
}

impl TryFrom<UncheckedUrl> for Url {
    type Error = Error;

    fn try_from(unchecked_url: UncheckedUrl) -> Result<Url, Self::Error> {
        Ok(Self::parse(&unchecked_url.0)?)
    }
}

impl fmt::Display for UncheckedUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[allow(missing_docs)]
#[derive(Debug, Clone, Eq, PartialEq, PartialOrd, Ord)]
pub enum Tag {
    Generic(TagKind, Vec<String>),
    Event(EventId, Option<UncheckedUrl>, Option<Marker>),
    PubKey(XOnlyPublicKey, Option<UncheckedUrl>),
    EventReport(EventId, Report),
    PubKeyReport(XOnlyPublicKey, Report),
    Reference(String),
    RelayMetadata(String, Option<String>),
    Hashtag(String),
    Geohash(String),
    Identifier(String),
    A {
        kind: Kind,
        public_key: XOnlyPublicKey,
        identifier: String,
        relay_url: UncheckedUrl,
    },
    Relay(Url),
    ContactList {
        pk: XOnlyPublicKey,
        relay_url: Option<UncheckedUrl>,
        alias: Option<String>,
    },
    POW {
        nonce: u128,
        difficulty: u8,
    },
    Delegation {
        delegator_pk: XOnlyPublicKey,
        conditions: Conditions,
        sig: Signature,
    },
    ContentWarning {
        reason: Option<String>,
    },
    Expiration(Timestamp),
    Subject(String),
    Challenge(String),
    Title(String),
    Image(String),
    Summary(String),
    Description(String),
    Bolt11(String),
    Preimage(String),
    Relays(Vec<UncheckedUrl>),
    Amount(u64),
    Lnurl(String),
    PublishedAt(Timestamp),
}

impl Tag {
    /// Parse [`Tag`] from string vector
    pub fn parse<S>(data: Vec<S>) -> Result<Self, Error>
    where
        S: Into<String>,
    {
        Tag::try_from(data)
    }

    /// Get [`Tag`] as string vector
    pub fn as_vec(&self) -> Vec<String> {
        self.clone().into()
    }

    /// Get [`TagKind`]
    pub fn kind(&self) -> TagKind {
        match self {
            Tag::Generic(kind, ..) => kind.clone(),
            Tag::Event(..) => TagKind::E,
            Tag::PubKey(..) => TagKind::P,
            Tag::EventReport(..) => TagKind::E,
            Tag::PubKeyReport(..) => TagKind::P,
            Tag::Reference(..) => TagKind::R,
            Tag::RelayMetadata(..) => TagKind::R,
            Tag::Hashtag(..) => TagKind::T,
            Tag::Geohash(..) => TagKind::G,
            Tag::Identifier(..) => TagKind::D,
            Tag::A { .. } => TagKind::A,
            Tag::Relay(..) => TagKind::Relay,
            Tag::ContactList { .. } => TagKind::P,
            Tag::POW { .. } => TagKind::Nonce,
            Tag::Delegation { .. } => TagKind::Delegation,
            Tag::ContentWarning { .. } => TagKind::ContentWarning,
            Tag::Expiration(..) => TagKind::Expiration,
            Tag::Subject(..) => TagKind::Subject,
            Tag::Challenge(..) => TagKind::Challenge,
            Tag::Title(..) => TagKind::Title,
            Tag::Image(..) => TagKind::Image,
            Tag::Summary(..) => TagKind::Summary,
            Tag::PublishedAt(..) => TagKind::PublishedAt,
            Tag::Description(..) => TagKind::Description,
            Tag::Bolt11(..) => TagKind::Bolt11,
            Tag::Preimage(..) => TagKind::Preimage,
            Tag::Relays(..) => TagKind::Relays,
            Tag::Amount(..) => TagKind::Amount,
            Tag::Lnurl(..) => TagKind::Lnurl,
        }
    }
}

impl<S> TryFrom<Vec<S>> for Tag
where
    S: Into<String>,
{
    type Error = Error;

    fn try_from(tag: Vec<S>) -> Result<Self, Self::Error> {
        let tag: Vec<String> = tag.into_iter().map(|v| v.into()).collect();
        let tag_len: usize = tag.len();
        let tag_kind: TagKind = match tag.first() {
            Some(kind) => TagKind::from(kind),
            None => return Err(Error::KindNotFound),
        };

        if tag_kind.eq(&TagKind::Relays) {
            // Relays vec is of unknown length so checked here based on kind

            let urls = tag
                .iter()
                .skip(1)
                .filter_map(|tag_str| UncheckedUrl::from_str(tag_str).ok())
                .collect::<Vec<UncheckedUrl>>();

            Ok(Self::Relays(urls))
        } else if tag_len == 1 {
            match tag_kind {
                TagKind::ContentWarning => Ok(Self::ContentWarning { reason: None }),
                _ => Ok(Self::Generic(tag_kind, Vec::new())),
            }
        } else if tag_len == 2 {
            let content: &str = &tag[1];
            match tag_kind {
                TagKind::P => Ok(Self::PubKey(XOnlyPublicKey::from_str(content)?, None)),
                TagKind::E => Ok(Self::Event(EventId::from_hex(content)?, None, None)),
                TagKind::R => Ok(Self::Reference(content.to_string())),
                TagKind::T => Ok(Self::Hashtag(content.to_string())),
                TagKind::G => Ok(Self::Geohash(content.to_string())),
                TagKind::D => Ok(Self::Identifier(content.to_string())),
                TagKind::Relay => Ok(Self::Relay(Url::parse(content)?)),
                TagKind::ContentWarning => Ok(Self::ContentWarning {
                    reason: Some(content.to_string()),
                }),
                TagKind::Expiration => Ok(Self::Expiration(Timestamp::from_str(content)?)),
                TagKind::Subject => Ok(Self::Subject(content.to_string())),
                TagKind::Challenge => Ok(Self::Challenge(content.to_string())),
                TagKind::Title => Ok(Self::Title(content.to_string())),
                TagKind::Image => Ok(Self::Image(content.to_string())),
                TagKind::Summary => Ok(Self::Summary(content.to_string())),
                TagKind::PublishedAt => Ok(Self::PublishedAt(Timestamp::from_str(content)?)),
                TagKind::Description => Ok(Self::Description(content.to_string())),
                TagKind::Bolt11 => Ok(Self::Bolt11(content.to_string())),
                TagKind::Preimage => Ok(Self::Preimage(content.to_string())),
                TagKind::Amount => Ok(Self::Amount(content.parse()?)),
                TagKind::Lnurl => Ok(Self::Lnurl(content.to_string())),
                _ => Ok(Self::Generic(tag_kind, vec![content.to_string()])),
            }
        } else if tag_len == 3 {
            match tag_kind {
                TagKind::P => {
                    let pubkey = XOnlyPublicKey::from_str(&tag[1])?;
                    if tag[2].is_empty() {
                        Ok(Self::PubKey(pubkey, Some(UncheckedUrl::default())))
                    } else {
                        match Report::try_from(tag[2].as_str()) {
                            Ok(report) => Ok(Self::PubKeyReport(pubkey, report)),
                            Err(_) => Ok(Self::PubKey(pubkey, Some(UncheckedUrl(tag[2].clone())))),
                        }
                    }
                }
                TagKind::E => {
                    let event_id = EventId::from_hex(&tag[1])?;
                    if tag[2].is_empty() {
                        Ok(Self::Event(event_id, Some(UncheckedUrl::default()), None))
                    } else {
                        match Report::try_from(tag[2].as_str()) {
                            Ok(report) => Ok(Self::EventReport(event_id, report)),
                            Err(_) => Ok(Self::Event(
                                event_id,
                                Some(UncheckedUrl(tag[2].clone())),
                                None,
                            )),
                        }
                    }
                }
                TagKind::Nonce => Ok(Self::POW {
                    nonce: tag[1].parse()?,
                    difficulty: tag[2].parse()?,
                }),
                TagKind::A => {
                    let kpi: Vec<&str> = tag[1].split(':').collect();
                    if kpi.len() == 3 {
                        Ok(Self::A {
                            kind: Kind::from_str(kpi[0])?,
                            public_key: XOnlyPublicKey::from_str(kpi[1])?,
                            identifier: kpi[2].to_string(),
                            relay_url: UncheckedUrl(tag[2].clone()),
                        })
                    } else {
                        Err(Error::InvalidLength)
                    }
                }
                _ => Ok(Self::Generic(tag_kind, tag[1..].to_vec())),
            }
        } else if tag_len == 4 {
            match tag_kind {
                TagKind::P => Ok(Self::ContactList {
                    pk: XOnlyPublicKey::from_str(&tag[1])?,
                    relay_url: Some(UncheckedUrl(tag[2].clone())),
                    alias: (!tag[3].is_empty()).then_some(tag[3].clone()),
                }),
                TagKind::E => Ok(Self::Event(
                    EventId::from_hex(&tag[1])?,
                    (!tag[2].is_empty()).then_some(UncheckedUrl(tag[2].clone())),
                    (!tag[3].is_empty()).then_some(Marker::from(&tag[3])),
                )),
                TagKind::Delegation => Ok(Self::Delegation {
                    delegator_pk: XOnlyPublicKey::from_str(&tag[1])?,
                    conditions: Conditions::from_str(&tag[2])?,
                    sig: Signature::from_str(&tag[3])?,
                }),
                _ => Ok(Self::Generic(tag_kind, tag[1..].to_vec())),
            }
        } else {
            Ok(Self::Generic(tag_kind, tag[1..].to_vec()))
        }
    }
}

impl From<Tag> for Vec<String> {
    fn from(data: Tag) -> Self {
        match data {
            Tag::Generic(kind, data) => vec![vec![kind.to_string()], data].concat(),
            Tag::Event(id, relay_url, marker) => {
                let mut tag = vec![TagKind::E.to_string(), id.to_hex()];
                if let Some(relay_url) = relay_url {
                    tag.push(relay_url.to_string());
                }
                if let Some(marker) = marker {
                    if tag.len() == 2 {
                        tag.push(String::new());
                    }
                    tag.push(marker.to_string());
                }
                tag
            }
            Tag::PubKey(pk, relay_url) => {
                let mut tag = vec![TagKind::P.to_string(), pk.to_string()];
                if let Some(relay_url) = relay_url {
                    tag.push(relay_url.to_string());
                }
                tag
            }
            Tag::EventReport(id, report) => {
                vec![TagKind::E.to_string(), id.to_hex(), report.to_string()]
            }
            Tag::PubKeyReport(pk, report) => {
                vec![TagKind::P.to_string(), pk.to_string(), report.to_string()]
            }
            Tag::Reference(r) => vec![TagKind::R.to_string(), r],
            Tag::RelayMetadata(url, rw) => {
                let mut tag = vec![TagKind::R.to_string(), url];
                if let Some(rw) = rw {
                    tag.push(rw);
                }
                tag
            }
            Tag::Hashtag(t) => vec![TagKind::T.to_string(), t],
            Tag::Geohash(g) => vec![TagKind::G.to_string(), g],
            Tag::Identifier(d) => vec![TagKind::D.to_string(), d],
            Tag::A {
                kind,
                public_key,
                identifier,
                relay_url,
            } => vec![
                TagKind::A.to_string(),
                format!("{}:{public_key}:{identifier}", kind.as_u64()),
                relay_url.to_string(),
            ],
            Tag::Relay(url) => vec![TagKind::Relay.to_string(), url.to_string()],
            Tag::ContactList {
                pk,
                relay_url,
                alias,
            } => vec![
                TagKind::P.to_string(),
                pk.to_string(),
                relay_url.unwrap_or_default().to_string(),
                alias.unwrap_or_default(),
            ],
            Tag::POW { nonce, difficulty } => vec![
                TagKind::Nonce.to_string(),
                nonce.to_string(),
                difficulty.to_string(),
            ],
            Tag::Delegation {
                delegator_pk,
                conditions,
                sig,
            } => vec![
                TagKind::Delegation.to_string(),
                delegator_pk.to_string(),
                conditions.to_string(),
                sig.to_string(),
            ],
            Tag::ContentWarning { reason } => {
                let mut tag = vec![TagKind::ContentWarning.to_string()];
                if let Some(reason) = reason {
                    tag.push(reason);
                }
                tag
            }
            Tag::Expiration(timestamp) => {
                vec![TagKind::Expiration.to_string(), timestamp.to_string()]
            }
            Tag::Subject(sub) => vec![TagKind::Subject.to_string(), sub],
            Tag::Challenge(challenge) => vec![TagKind::Challenge.to_string(), challenge],
            Tag::Title(title) => vec![TagKind::Title.to_string(), title],
            Tag::Image(image) => vec![TagKind::Image.to_string(), image],
            Tag::Summary(summary) => vec![TagKind::Summary.to_string(), summary],
            Tag::PublishedAt(timestamp) => {
                vec![TagKind::PublishedAt.to_string(), timestamp.to_string()]
            }
            Tag::Description(description) => {
                vec![TagKind::Description.to_string(), description]
            }
            Tag::Bolt11(bolt11) => {
                vec![TagKind::Bolt11.to_string(), bolt11]
            }
            Tag::Preimage(preimage) => {
                vec![TagKind::Preimage.to_string(), preimage]
            }
            Tag::Relays(relays) => vec![TagKind::Relays.to_string()]
                .into_iter()
                .chain(relays.iter().map(|relay| relay.to_string()))
                .collect::<Vec<_>>(),
            Tag::Amount(amount) => {
                vec![TagKind::Amount.to_string(), amount.to_string()]
            }
            Tag::Lnurl(lnurl) => {
                vec![TagKind::Lnurl.to_string(), lnurl]
            }
        }
    }
}

impl Serialize for Tag {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let data: Vec<String> = self.as_vec();
        let mut seq = serializer.serialize_seq(Some(data.len()))?;
        for element in data.into_iter() {
            seq.serialize_element(&element)?;
        }
        seq.end()
    }
}

impl<'de> Deserialize<'de> for Tag {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        type Data = Vec<String>;
        let vec: Vec<String> = Data::deserialize(deserializer)?;
        Self::try_from(vec).map_err(DeserializerError::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Event, Result, Timestamp};

    #[test]
    fn test_deserialize_tag_from_event() -> Result<()> {
        // Got this fresh off the wire
        let event: &str = r#"{"id":"2be17aa3031bdcb006f0fce80c146dea9c1c0268b0af2398bb673365c6444d45","pubkey":"f86c44a2de95d9149b51c6a29afeabba264c18e2fa7c49de93424a0c56947785","created_at":1640839235,"kind":4,"tags":[["p","13adc511de7e1cfcf1c6b7f6365fb5a03442d7bcacf565ea57fa7770912c023d"]],"content":"uRuvYr585B80L6rSJiHocw==?iv=oh6LVqdsYYol3JfFnXTbPA==","sig":"a5d9290ef9659083c490b303eb7ee41356d8778ff19f2f91776c8dc4443388a64ffcf336e61af4c25c05ac3ae952d1ced889ed655b67790891222aaa15b99fdd"}"#;
        let event = Event::from_json(event)?;
        let tag = event.tags.first().unwrap();

        assert_eq!(
            tag,
            &Tag::PubKey(
                XOnlyPublicKey::from_str(
                    "13adc511de7e1cfcf1c6b7f6365fb5a03442d7bcacf565ea57fa7770912c023d"
                )?,
                None
            )
        );

        Ok(())
    }

    #[test]
    fn test_serialize_tag_to_event() -> Result<()> {
        let pubkey = XOnlyPublicKey::from_str(
            "68d81165918100b7da43fc28f7d1fc12554466e1115886b9e7bb326f65ec4272",
        )?;
        let event = Event::new_dummy(
            "378f145897eea948952674269945e88612420db35791784abf0616b4fed56ef7",
            "79dff8f82963424e0bb02708a22e44b4980893e3a4be0fa3cb60a43b946764e3",
            Timestamp::from(1671739153),
            4,
            vec![Tag::PubKey(pubkey, None)],
            "8y4MRYrb4ztvXO2NmsHvUA==?iv=MplZo7oSdPfH/vdMC8Hmwg==",
            "fd0954de564cae9923c2d8ee9ab2bf35bc19757f8e328a978958a2fcc950eaba0754148a203adec29b7b64080d0cf5a32bebedd768ea6eb421a6b751bb4584a8"
        )?;

        let event_json: &str = r#"{"content":"8y4MRYrb4ztvXO2NmsHvUA==?iv=MplZo7oSdPfH/vdMC8Hmwg==","created_at":1671739153,"id":"378f145897eea948952674269945e88612420db35791784abf0616b4fed56ef7","kind":4,"pubkey":"79dff8f82963424e0bb02708a22e44b4980893e3a4be0fa3cb60a43b946764e3","sig":"fd0954de564cae9923c2d8ee9ab2bf35bc19757f8e328a978958a2fcc950eaba0754148a203adec29b7b64080d0cf5a32bebedd768ea6eb421a6b751bb4584a8","tags":[["p","68d81165918100b7da43fc28f7d1fc12554466e1115886b9e7bb326f65ec4272"]]}"#;

        assert_eq!(&event.as_json(), event_json);

        Ok(())
    }

    #[test]
    fn test_tag_as_vec() -> Result<()> {
        assert_eq!(
            vec!["content-warning"],
            Tag::ContentWarning { reason: None }.as_vec()
        );

        assert_eq!(
            vec![
                "p",
                "13adc511de7e1cfcf1c6b7f6365fb5a03442d7bcacf565ea57fa7770912c023d"
            ],
            Tag::PubKey(
                XOnlyPublicKey::from_str(
                    "13adc511de7e1cfcf1c6b7f6365fb5a03442d7bcacf565ea57fa7770912c023d"
                )?,
                None
            )
            .as_vec()
        );

        assert_eq!(
            vec![
                "e",
                "378f145897eea948952674269945e88612420db35791784abf0616b4fed56ef7"
            ],
            Tag::Event(
                EventId::from_hex(
                    "378f145897eea948952674269945e88612420db35791784abf0616b4fed56ef7"
                )?,
                None,
                None
            )
            .as_vec()
        );

        assert_eq!(
            vec!["expiration", "1600000000"],
            Tag::Expiration(Timestamp::from(1600000000)).as_vec()
        );

        assert_eq!(
            vec!["content-warning", "reason"],
            Tag::ContentWarning {
                reason: Some(String::from("reason"))
            }
            .as_vec()
        );

        assert_eq!(
            vec!["subject", "textnote with subject"],
            Tag::Subject(String::from("textnote with subject")).as_vec()
        );

        assert_eq!(
            vec!["client", "nostr-sdk"],
            Tag::Generic(
                TagKind::Custom("client".to_string()),
                vec!["nostr-sdk".to_string()]
            )
            .as_vec()
        );

        assert_eq!(
            vec!["d", "test"],
            Tag::Identifier("test".to_string()).as_vec()
        );

        assert_eq!(
            vec![
                "p",
                "13adc511de7e1cfcf1c6b7f6365fb5a03442d7bcacf565ea57fa7770912c023d",
                "wss://relay.damus.io"
            ],
            Tag::PubKey(
                XOnlyPublicKey::from_str(
                    "13adc511de7e1cfcf1c6b7f6365fb5a03442d7bcacf565ea57fa7770912c023d"
                )?,
                Some(UncheckedUrl::from_str("wss://relay.damus.io")?)
            )
            .as_vec()
        );

        assert_eq!(
            vec![
                "e",
                "378f145897eea948952674269945e88612420db35791784abf0616b4fed56ef7",
                ""
            ],
            Tag::Event(
                EventId::from_hex(
                    "378f145897eea948952674269945e88612420db35791784abf0616b4fed56ef7"
                )?,
                Some(UncheckedUrl::default()),
                None
            )
            .as_vec()
        );

        assert_eq!(
            vec![
                "e",
                "378f145897eea948952674269945e88612420db35791784abf0616b4fed56ef7",
                "wss://relay.damus.io"
            ],
            Tag::Event(
                EventId::from_hex(
                    "378f145897eea948952674269945e88612420db35791784abf0616b4fed56ef7"
                )?,
                Some(UncheckedUrl::from_str("wss://relay.damus.io")?),
                None
            )
            .as_vec()
        );

        assert_eq!(
            vec![
                "p",
                "13adc511de7e1cfcf1c6b7f6365fb5a03442d7bcacf565ea57fa7770912c023d",
                "spam"
            ],
            Tag::PubKeyReport(
                XOnlyPublicKey::from_str(
                    "13adc511de7e1cfcf1c6b7f6365fb5a03442d7bcacf565ea57fa7770912c023d"
                )?,
                Report::Spam
            )
            .as_vec()
        );

        assert_eq!(
            vec![
                "e",
                "378f145897eea948952674269945e88612420db35791784abf0616b4fed56ef7",
                "nudity"
            ],
            Tag::EventReport(
                EventId::from_hex(
                    "378f145897eea948952674269945e88612420db35791784abf0616b4fed56ef7"
                )?,
                Report::Nudity,
            )
            .as_vec()
        );

        assert_eq!(
            vec!["nonce", "1", "20"],
            Tag::POW {
                nonce: 1,
                difficulty: 20
            }
            .as_vec()
        );

        assert_eq!(
            vec![
                "a",
                "30023:a695f6b60119d9521934a691347d9f78e8770b56da16bb255ee286ddf9fda919:ipsum",
                "wss://relay.nostr.org"
            ],
            Tag::A {
                kind: Kind::LongFormTextNote,
                public_key: XOnlyPublicKey::from_str(
                    "a695f6b60119d9521934a691347d9f78e8770b56da16bb255ee286ddf9fda919"
                )?,
                identifier: String::from("ipsum"),
                relay_url: UncheckedUrl::from_str("wss://relay.nostr.org")?
            }
            .as_vec()
        );

        assert_eq!(
            vec![
                "p",
                "13adc511de7e1cfcf1c6b7f6365fb5a03442d7bcacf565ea57fa7770912c023d",
                "wss://relay.damus.io",
                "alias",
            ],
            Tag::ContactList {
                pk: XOnlyPublicKey::from_str(
                    "13adc511de7e1cfcf1c6b7f6365fb5a03442d7bcacf565ea57fa7770912c023d"
                )?,
                relay_url: Some(UncheckedUrl::from_str("wss://relay.damus.io")?),
                alias: Some(String::from("alias"))
            }
            .as_vec()
        );

        assert_eq!(
            vec![
                "e",
                "378f145897eea948952674269945e88612420db35791784abf0616b4fed56ef7",
                "",
                "reply"
            ],
            Tag::Event(
                EventId::from_hex(
                    "378f145897eea948952674269945e88612420db35791784abf0616b4fed56ef7"
                )?,
                None,
                Some(Marker::Reply)
            )
            .as_vec()
        );

        assert_eq!(
            vec![
                "delegation",
                "13adc511de7e1cfcf1c6b7f6365fb5a03442d7bcacf565ea57fa7770912c023d",
                "kind=1",
                "fd0954de564cae9923c2d8ee9ab2bf35bc19757f8e328a978958a2fcc950eaba0754148a203adec29b7b64080d0cf5a32bebedd768ea6eb421a6b751bb4584a8",
            ],
            Tag::Delegation { delegator_pk: XOnlyPublicKey::from_str(
                "13adc511de7e1cfcf1c6b7f6365fb5a03442d7bcacf565ea57fa7770912c023d"
            )?, conditions: Conditions::from_str("kind=1")?, sig: Signature::from_str("fd0954de564cae9923c2d8ee9ab2bf35bc19757f8e328a978958a2fcc950eaba0754148a203adec29b7b64080d0cf5a32bebedd768ea6eb421a6b751bb4584a8")? }
            .as_vec()
        );

        assert_eq!(
            vec!["lnurl", "lnurl1dp68gurn8ghj7um5v93kketj9ehx2amn9uh8wetvdskkkmn0wahz7mrww4excup0dajx2mrv92x9xp"],
            Tag::Lnurl(String::from("lnurl1dp68gurn8ghj7um5v93kketj9ehx2amn9uh8wetvdskkkmn0wahz7mrww4excup0dajx2mrv92x9xp")).as_vec(),
        );

        Ok(())
    }

    #[test]
    fn test_tag_parser() -> Result<()> {
        match Tag::parse::<String>(vec![]) {
            Err(Error::KindNotFound) => (),
            _ => panic!(),
        }

        assert_eq!(
            Tag::parse(vec!["content-warning"])?,
            Tag::ContentWarning { reason: None }
        );

        assert_eq!(
            Tag::parse(vec![
                "p",
                "13adc511de7e1cfcf1c6b7f6365fb5a03442d7bcacf565ea57fa7770912c023d"
            ])?,
            Tag::PubKey(
                XOnlyPublicKey::from_str(
                    "13adc511de7e1cfcf1c6b7f6365fb5a03442d7bcacf565ea57fa7770912c023d"
                )?,
                None
            )
        );

        assert_eq!(
            Tag::parse(vec![
                "e",
                "378f145897eea948952674269945e88612420db35791784abf0616b4fed56ef7"
            ])?,
            Tag::Event(
                EventId::from_hex(
                    "378f145897eea948952674269945e88612420db35791784abf0616b4fed56ef7"
                )?,
                None,
                None
            )
        );

        assert_eq!(
            Tag::parse(vec!["expiration", "1600000000"])?,
            Tag::Expiration(Timestamp::from(1600000000))
        );

        assert_eq!(
            Tag::parse(vec!["content-warning", "reason"])?,
            Tag::ContentWarning {
                reason: Some(String::from("reason"))
            }
        );

        assert_eq!(
            Tag::parse(vec!["subject", "textnote with subject"])?,
            Tag::Subject(String::from("textnote with subject"))
        );

        assert_eq!(
            Tag::parse(vec!["client", "nostr-sdk"])?,
            Tag::Generic(
                TagKind::Custom("client".to_string()),
                vec!["nostr-sdk".to_string()]
            )
        );

        assert_eq!(
            Tag::parse(vec!["d", "test"])?,
            Tag::Identifier("test".to_string())
        );

        assert_eq!(
            Tag::parse(vec![
                "p",
                "13adc511de7e1cfcf1c6b7f6365fb5a03442d7bcacf565ea57fa7770912c023d",
                "wss://relay.damus.io"
            ])?,
            Tag::PubKey(
                XOnlyPublicKey::from_str(
                    "13adc511de7e1cfcf1c6b7f6365fb5a03442d7bcacf565ea57fa7770912c023d"
                )?,
                Some(UncheckedUrl::from_str("wss://relay.damus.io")?)
            )
        );

        assert_eq!(
            Tag::parse(vec![
                "e",
                "378f145897eea948952674269945e88612420db35791784abf0616b4fed56ef7",
                ""
            ])?,
            Tag::Event(
                EventId::from_hex(
                    "378f145897eea948952674269945e88612420db35791784abf0616b4fed56ef7"
                )?,
                Some(UncheckedUrl::default()),
                None
            )
        );

        assert_eq!(
            Tag::parse(vec![
                "e",
                "378f145897eea948952674269945e88612420db35791784abf0616b4fed56ef7",
                "wss://relay.damus.io"
            ])?,
            Tag::Event(
                EventId::from_hex(
                    "378f145897eea948952674269945e88612420db35791784abf0616b4fed56ef7"
                )?,
                Some(UncheckedUrl::from_str("wss://relay.damus.io")?),
                None
            )
        );

        assert_eq!(
            Tag::parse(vec![
                "p",
                "13adc511de7e1cfcf1c6b7f6365fb5a03442d7bcacf565ea57fa7770912c023d",
                "impersonation"
            ])?,
            Tag::PubKeyReport(
                XOnlyPublicKey::from_str(
                    "13adc511de7e1cfcf1c6b7f6365fb5a03442d7bcacf565ea57fa7770912c023d"
                )?,
                Report::Impersonation
            )
        );

        assert_eq!(
            Tag::parse(vec![
                "e",
                "378f145897eea948952674269945e88612420db35791784abf0616b4fed56ef7",
                "profanity"
            ])?,
            Tag::EventReport(
                EventId::from_hex(
                    "378f145897eea948952674269945e88612420db35791784abf0616b4fed56ef7"
                )?,
                Report::Profanity
            )
        );

        assert_eq!(
            Tag::parse(vec!["nonce", "1", "20"])?,
            Tag::POW {
                nonce: 1,
                difficulty: 20
            }
        );

        assert_eq!(
            Tag::parse(vec![
                "a",
                "30023:a695f6b60119d9521934a691347d9f78e8770b56da16bb255ee286ddf9fda919:ipsum",
                "wss://relay.nostr.org"
            ])?,
            Tag::A {
                kind: Kind::LongFormTextNote,
                public_key: XOnlyPublicKey::from_str(
                    "a695f6b60119d9521934a691347d9f78e8770b56da16bb255ee286ddf9fda919"
                )?,
                identifier: String::from("ipsum"),
                relay_url: UncheckedUrl::from_str("wss://relay.nostr.org")?
            }
        );

        assert_eq!(
            Tag::parse(vec![
                "p",
                "13adc511de7e1cfcf1c6b7f6365fb5a03442d7bcacf565ea57fa7770912c023d",
                "wss://relay.damus.io",
                "alias",
            ])?,
            Tag::ContactList {
                pk: XOnlyPublicKey::from_str(
                    "13adc511de7e1cfcf1c6b7f6365fb5a03442d7bcacf565ea57fa7770912c023d"
                )?,
                relay_url: Some(UncheckedUrl::from_str("wss://relay.damus.io")?),
                alias: Some(String::from("alias"))
            }
        );

        assert_eq!(
            Tag::parse(vec![
                "e",
                "378f145897eea948952674269945e88612420db35791784abf0616b4fed56ef7",
                "",
                "reply"
            ])?,
            Tag::Event(
                EventId::from_hex(
                    "378f145897eea948952674269945e88612420db35791784abf0616b4fed56ef7"
                )?,
                None,
                Some(Marker::Reply)
            )
        );

        assert_eq!(
            Tag::parse(vec![
                "delegation",
                "13adc511de7e1cfcf1c6b7f6365fb5a03442d7bcacf565ea57fa7770912c023d",
                "kind=1",
                "fd0954de564cae9923c2d8ee9ab2bf35bc19757f8e328a978958a2fcc950eaba0754148a203adec29b7b64080d0cf5a32bebedd768ea6eb421a6b751bb4584a8",
            ])?,
            Tag::Delegation { delegator_pk: XOnlyPublicKey::from_str(
                "13adc511de7e1cfcf1c6b7f6365fb5a03442d7bcacf565ea57fa7770912c023d"
            )?, conditions: Conditions::from_str("kind=1")?, sig: Signature::from_str("fd0954de564cae9923c2d8ee9ab2bf35bc19757f8e328a978958a2fcc950eaba0754148a203adec29b7b64080d0cf5a32bebedd768ea6eb421a6b751bb4584a8")? }
        );

        assert_eq!(
            Tag::parse(vec![
                "relays",
                "wss://relay.damus.io/",
                "wss://nostr-relay.wlvs.space/",
                "wss://nostr.fmt.wiz.biz",
                "wss//nostr.fmt.wiz.biz"
            ])?,
            Tag::Relays(vec![
                UncheckedUrl::from_str("wss://relay.damus.io/")?,
                UncheckedUrl::from_str("wss://nostr-relay.wlvs.space/")?,
                UncheckedUrl::from_str("wss://nostr.fmt.wiz.biz")?,
                UncheckedUrl::from_str("wss//nostr.fmt.wiz.biz")?
            ])
        );

        assert_eq!(
            Tag::parse(vec![
                "bolt11", 
                "lnbc10u1p3unwfusp5t9r3yymhpfqculx78u027lxspgxcr2n2987mx2j55nnfs95nxnzqpp5jmrh92pfld78spqs78v9euf2385t83uvpwk9ldrlvf6ch7tpascqhp5zvkrmemgth3tufcvflmzjzfvjt023nazlhljz2n9hattj4f8jq8qxqyjw5qcqpjrzjqtc4fc44feggv7065fqe5m4ytjarg3repr5j9el35xhmtfexc42yczarjuqqfzqqqqqqqqlgqqqqqqgq9q9qxpqysgq079nkq507a5tw7xgttmj4u990j7wfggtrasah5gd4ywfr2pjcn29383tphp4t48gquelz9z78p4cq7ml3nrrphw5w6eckhjwmhezhnqpy6gyf0"])?, 
                Tag::Bolt11("lnbc10u1p3unwfusp5t9r3yymhpfqculx78u027lxspgxcr2n2987mx2j55nnfs95nxnzqpp5jmrh92pfld78spqs78v9euf2385t83uvpwk9ldrlvf6ch7tpascqhp5zvkrmemgth3tufcvflmzjzfvjt023nazlhljz2n9hattj4f8jq8qxqyjw5qcqpjrzjqtc4fc44feggv7065fqe5m4ytjarg3repr5j9el35xhmtfexc42yczarjuqqfzqqqqqqqqlgqqqqqqgq9q9qxpqysgq079nkq507a5tw7xgttmj4u990j7wfggtrasah5gd4ywfr2pjcn29383tphp4t48gquelz9z78p4cq7ml3nrrphw5w6eckhjwmhezhnqpy6gyf0".to_string())
        );

        assert_eq!(
            Tag::parse(vec![
                "preimage",
                "5d006d2cf1e73c7148e7519a4c68adc81642ce0e25a432b2434c99f97344c15f"
            ])?,
            Tag::Preimage(
                "5d006d2cf1e73c7148e7519a4c68adc81642ce0e25a432b2434c99f97344c15f".to_string()
            )
        );

        assert_eq!(
            Tag::parse(vec![
                "description",
                "{\"pubkey\":\"32e1827635450ebb3c5a7d12c1f8e7b2b514439ac10a67eef3d9fd9c5c68e245\",\"content\":\"\",\"id\":\"d9cc14d50fcb8c27539aacf776882942c1a11ea4472f8cdec1dea82fab66279d\",\"created_at\":1674164539,\"sig\":\"77127f636577e9029276be060332ea565deaf89ff215a494ccff16ae3f757065e2bc59b2e8c113dd407917a010b3abd36c8d7ad84c0e3ab7dab3a0b0caa9835d\",\"kind\":9734,\"tags\":[[\"e\",\"3624762a1274dd9636e0c552b53086d70bc88c165bc4dc0f9e836a1eaf86c3b8\"],[\"p\",\"32e1827635450ebb3c5a7d12c1f8e7b2b514439ac10a67eef3d9fd9c5c68e245\"],[\"relays\",\"wss://relay.damus.io\",\"wss://nostr-relay.wlvs.space\",\"wss://nostr.fmt.wiz.biz\",\"wss://relay.nostr.bg\",\"wss://nostr.oxtr.dev\",\"wss://nostr.v0l.io\",\"wss://brb.io\",\"wss://nostr.bitcoiner.social\",\"ws://monad.jb55.com:8080\",\"wss://relay.snort.social\"]]}"
            ])?,
            Tag::Description("{\"pubkey\":\"32e1827635450ebb3c5a7d12c1f8e7b2b514439ac10a67eef3d9fd9c5c68e245\",\"content\":\"\",\"id\":\"d9cc14d50fcb8c27539aacf776882942c1a11ea4472f8cdec1dea82fab66279d\",\"created_at\":1674164539,\"sig\":\"77127f636577e9029276be060332ea565deaf89ff215a494ccff16ae3f757065e2bc59b2e8c113dd407917a010b3abd36c8d7ad84c0e3ab7dab3a0b0caa9835d\",\"kind\":9734,\"tags\":[[\"e\",\"3624762a1274dd9636e0c552b53086d70bc88c165bc4dc0f9e836a1eaf86c3b8\"],[\"p\",\"32e1827635450ebb3c5a7d12c1f8e7b2b514439ac10a67eef3d9fd9c5c68e245\"],[\"relays\",\"wss://relay.damus.io\",\"wss://nostr-relay.wlvs.space\",\"wss://nostr.fmt.wiz.biz\",\"wss://relay.nostr.bg\",\"wss://nostr.oxtr.dev\",\"wss://nostr.v0l.io\",\"wss://brb.io\",\"wss://nostr.bitcoiner.social\",\"ws://monad.jb55.com:8080\",\"wss://relay.snort.social\"]]}".to_string())
        );

        assert_eq!(Tag::parse(vec!["amount", "10000"])?, Tag::Amount(10000));

        Ok(())
    }

    #[test]
    fn test_unchecked_relay_url() -> Result<()> {
        let relay = "wss://relay.damus.io/";
        let relay_url = Url::from_str(relay)?;

        println!("{}", relay_url.to_string());

        let unchecked_relay_url = UncheckedUrl::from(relay_url.clone());

        assert_eq!(unchecked_relay_url, UncheckedUrl::from_str(relay)?);

        assert_eq!(Url::try_from(unchecked_relay_url.clone())?, relay_url);

        assert_eq!(relay, unchecked_relay_url.to_string());

        Ok(())
    }

    #[test]
    fn test_unchecked_relay_url_without_trailing_slash() -> Result<()> {
        let relay = "wss://relay.damus.io";
        let relay_url = Url::from_str(relay)?;

        println!("{}", relay_url.to_string());

        let unchecked_relay_url = UncheckedUrl::from(relay_url.clone());

        assert_eq!(unchecked_relay_url, UncheckedUrl::from_str(relay)?);

        assert_eq!(Url::try_from(unchecked_relay_url.clone())?, relay_url);

        assert_eq!(relay, unchecked_relay_url.to_string());

        Ok(())
    }
}
