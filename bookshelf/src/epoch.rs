use std::str::FromStr;
use std::{collections::BTreeMap, fmt};

use camino::{Utf8Path, Utf8PathBuf};
use chrono::Datelike;
use thiserror::Error;

type Date = chrono::NaiveDate;
const DATE_FORMAT: &str = "%Y%m%d";

/// An error indicating that a string could not be parsed as an epoch
#[derive(Debug, Error)]
#[error("Invalid epoch: {value:?}")]
pub struct InvalidEpoch {
    value: String,
}

impl InvalidEpoch {
    /// Create a new error indicating that a string could not be parsed as an epoch
    pub(crate) fn new(value: String) -> Self {
        Self { value }
    }
}

// Names are restricted to a single path component.

/// A point in time used to organize the contents of a library
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Epoch(Date);

impl Epoch {
    /// Create a new epoch from the current date
    pub fn today() -> Self {
        Epoch(chrono::Utc::now().date_naive())
    }

    /// Convert the epoch to a path
    pub fn to_path(&self) -> Utf8PathBuf {
        (*self).into()
    }

    /// Get the month of the epoch
    pub fn month(&self) -> u32 {
        self.0.month()
    }

    /// Get the year of the epoch
    pub fn year(&self) -> i32 {
        self.0.year()
    }
}

impl FromStr for Epoch {
    type Err = InvalidEpoch;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        chrono::NaiveDate::parse_from_str(s, DATE_FORMAT)
            .map_err(|_| InvalidEpoch::new(s.into()))
            .map(Epoch)
    }
}

impl TryFrom<&Utf8Path> for Epoch {
    type Error = InvalidEpoch;
    fn try_from(path: &Utf8Path) -> Result<Self, Self::Error> {
        Epoch::from_str(path.as_str())
    }
}

impl From<chrono::NaiveDate> for Epoch {
    fn from(value: chrono::NaiveDate) -> Self {
        Epoch(value)
    }
}

impl From<Epoch> for chrono::NaiveDate {
    fn from(epoch: Epoch) -> Self {
        epoch.0
    }
}

impl From<Epoch> for Utf8PathBuf {
    fn from(epoch: Epoch) -> Self {
        Utf8PathBuf::from(epoch.0.format(DATE_FORMAT).to_string())
    }
}

impl fmt::Display for Epoch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.format("%b %d, %Y").fmt(f)
    }
}

/// A selector for an epoch in a range
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EpochSelector {
    /// The earliest epoch in the range
    Earliest,

    /// The latest epoch in the range
    Latest,

    /// An exact epoch in the range
    Exact(Epoch),

    /// The Nth latest epoch in the range
    Nth(usize),
}

impl FromStr for EpochSelector {
    type Err = InvalidEpoch;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "earliest" => Ok(Self::Earliest),
            "latest" => Ok(Self::Latest),
            nth if nth.parse::<usize>().map(|v| v < 1000).unwrap_or(false) => {
                Ok(Self::Nth(nth.parse().unwrap()))
            }
            _ => Ok(Self::Exact(s.parse()?)),
        }
    }
}

impl From<Epoch> for EpochSelector {
    fn from(epoch: Epoch) -> Self {
        Self::Exact(epoch)
    }
}

impl From<Option<Epoch>> for EpochSelector {
    fn from(epoch: Option<Epoch>) -> Self {
        epoch.map_or(Self::Latest, Self::from)
    }
}

impl fmt::Display for EpochSelector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Earliest => write!(f, "earliest"),
            Self::Latest => write!(f, "latest"),
            Self::Exact(epoch) => write!(f, "{}", epoch),
            Self::Nth(n) => write!(f, "{}th", n),
        }
    }
}

impl EpochSelector {
    /// Given a tree of epochs, find the epoch that matches the selector
    pub fn find<V>(&self, epochs: &BTreeMap<Epoch, V>) -> Option<Epoch> {
        match self {
            Self::Earliest => epochs.keys().next().cloned(),
            Self::Latest => epochs.keys().last().cloned(),
            Self::Exact(epoch) => epochs.get(epoch).map(|_| *epoch),
            Self::Nth(n) => epochs.keys().rev().nth(*n).cloned(),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn epoch() {
        let epoch = Epoch::from_str("20200101").unwrap();
        assert_eq!(epoch.year(), 2020);
        assert_eq!(epoch.month(), 1);
        assert_eq!(epoch.to_path().as_str(), "20200101");
    }

    #[test]
    fn selector_parse() {
        let selector = EpochSelector::from_str("earliest").unwrap();
        assert_eq!(selector, EpochSelector::Earliest);
        let selector = EpochSelector::from_str("latest").unwrap();
        assert_eq!(selector, EpochSelector::Latest);
        let selector = EpochSelector::from_str("20200101").unwrap();
        assert_eq!(
            selector,
            EpochSelector::Exact(Epoch::from_str("20200101").unwrap())
        );
        let selector = EpochSelector::from_str("3").unwrap();
        assert_eq!(selector, EpochSelector::Nth(3));
    }

    #[test]
    fn epoch_selector() {
        let epoch_items = vec![
            Epoch::from_str("20200101").unwrap(),
            Epoch::from_str("20200201").unwrap(),
            Epoch::from_str("20200301").unwrap(),
        ];

        let mut epochs = BTreeMap::new();
        for epoch in &epoch_items {
            epochs.insert(*epoch, ());
        }

        let selector = EpochSelector::Earliest;
        assert_eq!(
            selector.find(&epochs),
            Some(epoch_items[0]),
            "{:?}",
            selector
        );

        let selector = EpochSelector::Latest;
        assert_eq!(
            selector.find(&epochs),
            Some(epoch_items[2]),
            "{:?}",
            selector
        );
        let selector = EpochSelector::Exact(epoch_items[1]);
        assert_eq!(
            selector.find(&epochs),
            Some(epoch_items[1]),
            "{:?}",
            selector
        );
        let selector = EpochSelector::Nth(1);
        assert_eq!(
            selector.find(&epochs),
            Some(epoch_items[1]),
            "{:?}",
            selector
        );

        let selector = EpochSelector::Nth(2);
        assert_eq!(
            selector.find(&epochs),
            Some(epoch_items[0]),
            "{:?}",
            selector
        );
    }
}
