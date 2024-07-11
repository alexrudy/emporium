use std::any::type_name;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Debug;
use std::hash::Hash;
use std::{cmp, fmt};

use chrono::{Datelike, Duration, Months, NaiveDate};
use serde::Deserialize;

use crate::Epoch;

trait Bucket {
    fn insert(&mut self, epoch: Epoch);
    fn values(&self) -> BTreeSet<Epoch>;

    #[allow(dead_code)]
    fn len(&self) -> usize {
        self.values().len()
    }

    #[allow(dead_code)]
    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn name(&self) -> &str {
        type_name::<Self>()
    }
}

/// Collect all backups which belong to a single bucket
struct ExpirationBucket<D> {
    extract: Box<dyn Fn(Epoch) -> D>,
    horizon: D,
    backups: BTreeMap<D, Epoch>,
}

impl<D> fmt::Debug for ExpirationBucket<D>
where
    D: Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ExpirationBucket")
            .field("horizon", &self.horizon)
            .field("backups", &self.backups)
            .finish()
    }
}

fn weeks_since_year_start(date: Epoch) -> i64 {
    let year_start = NaiveDate::from_ymd_opt(date.year(), 1, 1).unwrap();
    (std::convert::Into::<chrono::NaiveDate>::into(date) - year_start).num_weeks()
}

impl ExpirationBucket<()> {
    fn daily(origin: NaiveDate, days: u32) -> ExpirationBucket<Epoch> {
        let extract = { |epoch: Epoch| epoch };

        ExpirationBucket {
            extract: Box::new(extract),
            horizon: (origin - Duration::days(days as i64)).into(),
            backups: Default::default(),
        }
    }

    fn weekly(origin: NaiveDate, weeks: u32) -> ExpirationBucket<(i32, i64)> {
        let extract = { |epoch: Epoch| (epoch.year(), weeks_since_year_start(epoch)) };

        let horizon = (extract)((origin - Duration::weeks(weeks as i64)).into());

        ExpirationBucket {
            extract: Box::new(extract),
            horizon,
            backups: Default::default(),
        }
    }

    fn monthly(origin: NaiveDate, months: u32) -> ExpirationBucket<(i32, u32)> {
        let extract = {
            |epoch: Epoch| {
                let month = epoch.month();
                let year = epoch.year();
                (year, month)
            }
        };

        let horizon = origin.checked_sub_months(Months::new(months)).unwrap();

        ExpirationBucket {
            extract: Box::new(extract),
            horizon: (horizon.year(), horizon.month()),
            backups: Default::default(),
        }
    }

    fn yearly(origin: NaiveDate, years: u32) -> ExpirationBucket<i32> {
        let extract = { |epoch: Epoch| epoch.year() };

        let horizon = origin
            .year()
            .checked_sub_unsigned(years)
            .expect("Valid year limit");

        ExpirationBucket {
            extract: Box::new(extract),
            horizon,
            backups: Default::default(),
        }
    }
}

impl<D> Bucket for ExpirationBucket<D>
where
    D: Ord + Eq + Hash,
{
    fn insert(&mut self, epoch: Epoch) {
        let bucket = (self.extract)(epoch);

        if bucket >= self.horizon {
            let current = self.backups.entry(bucket).or_insert(epoch);
            *current = cmp::min(epoch, *current);
        }
    }

    fn values(&self) -> BTreeSet<Epoch> {
        self.backups.values().copied().collect()
    }

    fn len(&self) -> usize {
        self.backups.len()
    }

    fn is_empty(&self) -> bool {
        self.backups.is_empty()
    }
}

#[derive(Default)]
struct Policy {
    policies: Vec<Box<dyn Bucket>>,
    epochs: BTreeSet<Epoch>,
}

impl fmt::Debug for Policy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Policy {{")?;
        for policy in &self.policies {
            writeln!(f, "  {}", policy.name())?;

            let mut epochs = policy.values().into_iter().collect::<Vec<_>>();
            epochs.sort();
            for epoch in epochs {
                writeln!(f, "    {epoch:?}")?;
            }
        }
        writeln!(f, "}}")?;
        Ok(())
    }
}

impl Policy {
    fn new(policies: Vec<Box<dyn Bucket>>) -> Self {
        Policy {
            policies,
            epochs: Default::default(),
        }
    }

    fn insert(&mut self, epoch: Epoch) {
        self.epochs.insert(epoch);
        for policy in &mut self.policies {
            policy.insert(epoch)
        }
    }

    fn expired(&self) -> BTreeSet<Epoch> {
        let mut expired = self.epochs.clone();
        for policy in &self.policies {
            for retained in &policy.values() {
                expired.remove(retained);
            }
        }

        expired
    }
}

#[derive(Debug, Clone, Copy, Deserialize)]
pub struct ExpirationPolicy {
    pub days: u32,
    pub weeks: u32,
    pub months: u32,
    pub years: u32,
}

impl Default for ExpirationPolicy {
    fn default() -> Self {
        ExpirationPolicy {
            days: 7,
            weeks: 8,
            months: 12,
            years: 10,
        }
    }
}

impl ExpirationPolicy {
    fn policies(&self, origin: NaiveDate) -> Policy {
        let policies: Vec<Box<dyn Bucket>> = vec![
            Box::new(ExpirationBucket::daily(origin, self.days)),
            Box::new(ExpirationBucket::weekly(origin, self.weeks)),
            Box::new(ExpirationBucket::monthly(origin, self.months)),
            Box::new(ExpirationBucket::yearly(origin, self.years)),
        ];

        Policy::new(policies)
    }

    pub fn expired<I>(&self, origin: Epoch, iterator: I) -> BTreeSet<Epoch>
    where
        I: Iterator<Item = Epoch>,
    {
        let mut policy = self.policies(origin.into());
        for epoch in iterator {
            policy.insert(epoch);
        }

        policy.expired()
    }
}

#[cfg(test)]
mod test {
    use chrono::NaiveDate;

    use super::*;

    macro_rules! date {
        ($year:tt / $month:tt / $day:tt) => {
            NaiveDate::from_ymd_opt($year, $month, $day).unwrap()
        };
    }

    fn year(n: i32) -> Vec<Epoch> {
        let start = date!(2010 / 1 / 1);

        (0..)
            .map(|d| start + Duration::days(d))
            .take_while(|date| date.year() < 2010 + n)
            .map(|date| date.into())
            .collect()
    }

    #[test]
    fn default_policy() {
        let policy_config = ExpirationPolicy::default();
        let origin = date!(2010 / 12 / 31);

        let mut policy = policy_config.policies(origin);

        for epoch in year(1) {
            policy.insert(epoch);
        }
        eprintln!("{policy:?}");
        assert_eq!(policy.policies[0].len(), 8, "daily");
        assert_eq!(policy.policies[1].len(), 9, "weekly");
        assert_eq!(policy.policies[2].len(), 12, "monthly");
        assert_eq!(policy.policies[3].len(), 1, "yearly");

        let expired = policy_config.expired(origin.into(), year(1).into_iter());
        assert!(expired.contains(&date!(2010 / 1 / 2).into()));
        assert!(expired.contains(&date!(2010 / 12 / 20).into()));
    }

    #[test]
    fn default_policy_multiyear() {
        let policy_config = ExpirationPolicy::default();
        let origin = date!(2015 / 12 / 31);

        let mut policy = policy_config.policies(origin);

        for epoch in year(6) {
            policy.insert(epoch);
        }

        assert_eq!(policy.policies[0].len(), 8, "daily");
        assert_eq!(policy.policies[1].len(), 9, "weekly");
        assert_eq!(policy.policies[2].len(), 13, "monthly");
        assert_eq!(policy.policies[3].len(), 6, "yearly");

        let expired = policy_config.expired(origin.into(), year(6).into_iter());
        assert!(expired.contains(&date!(2015 / 1 / 2).into()));
        assert!(expired.contains(&date!(2015 / 12 / 20).into()));
    }

    #[test]
    fn apply_sequentially() {
        let policy_config = ExpirationPolicy::default();
        let origin = date!(2015 / 12 / 31);

        let mut storage: BTreeSet<Epoch> = year(6).into_iter().collect();

        for i in 1..90 {
            let today = origin + Duration::days(i);
            storage.insert(today.into());

            let mut policy = policy_config.policies(today);
            for epoch in &storage {
                policy.insert(*epoch);
            }

            assert_eq!(policy.policies[0].len(), 8, "daily");
            assert!(policy.policies[1].len() >= 9, "weekly");
            assert_eq!(policy.policies[2].len(), 13, "monthly");
            assert_eq!(policy.policies[3].len(), 7, "yearly");

            let expired = policy.expired();
            for epoch in expired {
                storage.remove(&epoch);
            }
        }

        assert!(storage.contains(&date!(2015 / 1 / 1).into()));
        assert!(!storage.contains(&date!(2015 / 2 / 1).into()));
        assert!(storage.contains(&date!(2015 / 4 / 1).into()));
    }
}
