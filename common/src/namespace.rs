//! Hierarchical namespace type used by subjects and governance roles.

use borsh::{BorshDeserialize, BorshSerialize};

use serde::{Deserialize, Serialize};

use std::cmp::Ordering;
use std::fmt::{Error, Formatter};

#[cfg(feature = "openapi")]
use utoipa::ToSchema;

#[cfg(feature = "typescript")]
use ts_rs::TS;

/// Dot-separated namespace.
#[derive(
    Clone,
    Hash,
    Eq,
    PartialEq,
    PartialOrd,
    Ord,
    Serialize,
    Deserialize,
    BorshDeserialize,
    BorshSerialize,
)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[cfg_attr(feature = "typescript", derive(TS))]
#[cfg_attr(feature = "typescript", ts(export))]
pub struct Namespace(Vec<String>);

impl Namespace {
    /// Creates an empty namespace.
    pub const fn new() -> Self {
        Self(Vec::new())
    }

    /// Returns `true` when all namespace tokens are non-empty, trimmed and short enough.
    pub fn check(&self) -> bool {
        !self
            .0
            .iter()
            .any(|x| x.trim().is_empty() || x.len() > 100 || x != x.trim())
    }

    /// Appends a non-empty token to the namespace.
    pub fn add(&mut self, name: &str) {
        let name = name.trim();

        if !name.is_empty() {
            self.0.push(name.to_owned())
        }
    }

    /// Returns the top-level namespace segment.
    pub fn root(&self) -> Self {
        if self.0.len() == 1 {
            self.clone()
        } else if !self.0.is_empty() {
            Self(self.0.iter().take(1).cloned().collect())
        } else {
            Self(Vec::new())
        }
    }

    /// Returns the direct parent namespace.
    pub fn parent(&self) -> Self {
        if self.0.len() > 1 {
            let mut tokens = self.0.clone();
            tokens.truncate(tokens.len() - 1);
            Self(tokens)
        } else {
            Self(Vec::new())
        }
    }

    /// Returns the last namespace segment.
    pub fn key(&self) -> String {
        self.0.last().cloned().unwrap_or_else(|| "".to_string())
    }

    /// Returns the number of namespace segments.
    pub const fn level(&self) -> usize {
        self.0.len()
    }

    /// Returns the namespace truncated to `level` segments.
    pub fn at_level(&self, level: usize) -> Self {
        if level == 0 || level > self.level() {
            self.clone()
        } else {
            let mut tokens = self.0.clone();
            tokens.truncate(level);
            Self(tokens)
        }
    }

    /// Returns `true` when the namespace has no segments.
    pub const fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Returns `true` when `self` is a strict ancestor of `other`.
    pub fn is_ancestor_of(&self, other: &Self) -> bool {
        let me = format!("{}.", self);
        other.to_string().as_str().starts_with(me.as_str()) || self.is_empty()
    }

    /// Returns `true` when `self` is an ancestor of `other` or both are equal.
    pub fn is_ancestor_or_equal_of(&self, other: &Self) -> bool {
        let me = format!("{}.", self);
        other.to_string().as_str().starts_with(me.as_str())
            || self.is_empty()
            || self == other
    }

    /// Returns `true` when `self` is a strict descendant of `other`.
    pub fn is_descendant_of(&self, other: &Self) -> bool {
        let me = self.to_string();
        me.as_str().starts_with(format!("{}.", other).as_str())
    }

    /// Returns `true` when `self` is the direct parent of `other`.
    pub fn is_parent_of(&self, other: &Self) -> bool {
        *self == other.parent()
    }

    /// Returns `true` when `self` is the direct child of `other`.
    pub fn is_child_of(&self, other: &Self) -> bool {
        self.parent() == *other
    }

    /// Returns `true` when the namespace has a single segment.
    pub const fn is_top_level(&self) -> bool {
        self.0.len() == 1
    }
}

impl std::fmt::Display for Namespace {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self.level().cmp(&1) {
            Ordering::Less => write!(f, ""),
            Ordering::Equal => write!(f, "{}", self.0[0]),
            Ordering::Greater => write!(f, "{}", self.0.join(".")),
        }
    }
}

impl std::fmt::Debug for Namespace {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), Error> {
        match self.level().cmp(&1) {
            Ordering::Less => {
                write!(f, "")
            }
            Ordering::Equal => write!(f, "{}", self.0[0]),
            Ordering::Greater => write!(f, "{}", self.0.join(".")),
        }
    }
}

impl Default for Namespace {
    fn default() -> Self {
        Self::new()
    }
}

impl From<&str> for Namespace {
    fn from(str: &str) -> Self {
        let tokens: Vec<String> = str
            .split('.')
            .filter(|x| !x.trim().is_empty())
            .map(|s| s.trim().to_string())
            .collect();

        Self(tokens)
    }
}

impl From<String> for Namespace {
    fn from(str: String) -> Self {
        Self::from(str.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_namespace() {
        let ns = Namespace::from("a.b.c");
        assert_eq!(ns.level(), 3);
        assert_eq!(ns.key(), "c");
        assert_eq!(ns.root().to_string(), "a");
        assert_eq!(ns.parent().to_string(), "a.b");
        assert_eq!(ns.at_level(1).to_string(), "a");
        assert_eq!(ns.at_level(2).to_string(), "a.b");
        assert_eq!(ns.at_level(3).to_string(), "a.b.c");
        assert!(!ns.is_empty());
        assert!(ns.is_ancestor_of(&Namespace::from("a.b.c.d")));
        assert!(ns.is_descendant_of(&Namespace::from("a.b")));
        assert!(ns.is_parent_of(&Namespace::from("a.b.c.d")));
        assert!(ns.is_child_of(&Namespace::from("a.b")));
        assert!(!ns.is_top_level());
        assert!(Namespace::new().is_ancestor_of(&Namespace::from("a.b.c.d")));
    }

    #[test]
    fn test_namespace_check() {
        assert!(Namespace::from("valid.token").check());
        assert!(Namespace::from("").check());
        // From<&str> trims tokens, so spaced inputs become valid
        assert!(Namespace::from(" spaced ").check());
        assert!(Namespace::from("a. b").check());

        // Direct construction with empty token fails check
        let mut bad = Namespace::new();
        bad.0.push("".to_string());
        assert!(!bad.check());

        // Direct construction with leading/trailing spaces fails check
        let mut bad2 = Namespace::new();
        bad2.0.push(" spaced ".to_string());
        assert!(!bad2.check());

        // Very long token fails check
        let mut bad3 = Namespace::new();
        bad3.0.push("x".repeat(101));
        assert!(!bad3.check());
    }

    #[test]
    fn test_namespace_add() {
        let mut ns = Namespace::new();
        ns.add("a");
        assert_eq!(ns.to_string(), "a");
        ns.add("  b  ");
        assert_eq!(ns.to_string(), "a.b");
        ns.add("");
        assert_eq!(ns.to_string(), "a.b");
    }

    #[test]
    fn test_namespace_edge_cases() {
        let empty = Namespace::new();
        assert_eq!(empty.level(), 0);
        assert_eq!(empty.key(), "");
        assert!(empty.is_empty());
        assert!(empty.is_top_level() == false);
        assert!(empty.is_ancestor_or_equal_of(&Namespace::from("a")));
        assert!(empty.is_ancestor_or_equal_of(&Namespace::new()));

        let top = Namespace::from("a");
        assert!(top.is_top_level());
        assert_eq!(top.parent().to_string(), "");
        assert_eq!(top.root().to_string(), "a");
        assert!(top.is_ancestor_or_equal_of(&Namespace::from("a")));
        assert!(top.is_ancestor_or_equal_of(&Namespace::from("a.b")));
        assert!(!top.is_descendant_of(&Namespace::from("a")));
        assert!(!top.is_descendant_of(&Namespace::from("")));

        let ns = Namespace::from("a.b.c");
        assert_eq!(ns.at_level(0).to_string(), "a.b.c");
        assert_eq!(ns.at_level(10).to_string(), "a.b.c");
    }

    #[test]
    fn test_namespace_from_str_filters_empty() {
        let ns = Namespace::from("a..b...c");
        assert_eq!(ns.to_string(), "a.b.c");
    }

    #[test]
    fn test_namespace_relationships_deep_hierarchy() {
        let root = Namespace::from("a");
        let mid = Namespace::from("a.b");
        let leaf = Namespace::from("a.b.c");

        assert!(root.is_ancestor_of(&leaf));
        assert!(mid.is_ancestor_of(&leaf));
        assert!(leaf.is_descendant_of(&root));
        assert!(leaf.is_descendant_of(&mid));
        assert!(mid.is_parent_of(&leaf));
        assert!(leaf.is_child_of(&mid));
        assert!(!root.is_parent_of(&leaf)); // not direct
    }
}
