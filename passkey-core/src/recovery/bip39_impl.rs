//! BIP39 implementation details
//!
//! Provides additional BIP39 utilities for recovery code validation.

use bip39::Language;

/// Get the BIP39 English word list
pub fn get_word_list() -> &'static [&'static str] {
    Language::English.word_list()
}

/// Check if a word is valid in the BIP39 English wordlist
pub fn is_valid_word(word: &str) -> bool {
    let normalized = word.to_lowercase();
    get_word_list().iter().any(|w| *w == normalized)
}

/// Get word suggestions for partial input (autocomplete)
///
/// Returns up to `max_results` words that start with the given prefix.
pub fn get_word_suggestions(prefix: &str, max_results: usize) -> Vec<&'static str> {
    let prefix_lower = prefix.to_lowercase();
    get_word_list()
        .iter()
        .filter(|w| w.starts_with(&prefix_lower))
        .take(max_results)
        .copied()
        .collect()
}

/// Find the closest matching word for a typo
///
/// Uses simple Levenshtein distance to find similar words.
/// Returns None if no word is within the threshold.
pub fn find_closest_word(word: &str, max_distance: usize) -> Option<&'static str> {
    let word_lower = word.to_lowercase();

    get_word_list()
        .iter()
        .map(|w| (*w, levenshtein_distance(&word_lower, w)))
        .filter(|(_, d)| *d <= max_distance)
        .min_by_key(|(_, d)| *d)
        .map(|(w, _)| w)
}

/// Simple Levenshtein distance implementation
fn levenshtein_distance(a: &str, b: &str) -> usize {
    let a_chars: Vec<char> = a.chars().collect();
    let b_chars: Vec<char> = b.chars().collect();

    let m = a_chars.len();
    let n = b_chars.len();

    if m == 0 { return n; }
    if n == 0 { return m; }

    let mut prev = vec![0usize; n + 1];
    let mut curr = vec![0usize; n + 1];

    for j in 0..=n {
        prev[j] = j;
    }

    for i in 1..=m {
        curr[0] = i;

        for j in 1..=n {
            let cost = if a_chars[i - 1] == b_chars[j - 1] { 0 } else { 1 };

            curr[j] = std::cmp::min(
                std::cmp::min(prev[j] + 1, curr[j - 1] + 1),
                prev[j - 1] + cost,
            );
        }

        std::mem::swap(&mut prev, &mut curr);
    }

    prev[n]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_valid_word() {
        assert!(is_valid_word("abandon"));
        assert!(is_valid_word("ABANDON")); // Case insensitive
        assert!(is_valid_word("zoo"));
        assert!(!is_valid_word("xyz123"));
        assert!(!is_valid_word("notaword"));
    }

    #[test]
    fn test_get_word_suggestions() {
        let suggestions = get_word_suggestions("aban", 5);
        assert!(!suggestions.is_empty());
        assert!(suggestions.contains(&"abandon"));
    }

    #[test]
    fn test_get_word_suggestions_empty() {
        let suggestions = get_word_suggestions("xyz", 5);
        assert!(suggestions.is_empty());
    }

    #[test]
    fn test_find_closest_word() {
        // Close typo
        let closest = find_closest_word("abandn", 2);
        assert_eq!(closest, Some("abandon"));

        // Too different
        let closest = find_closest_word("xyzabc", 2);
        assert_eq!(closest, None);
    }

    #[test]
    fn test_levenshtein_distance() {
        assert_eq!(levenshtein_distance("", ""), 0);
        assert_eq!(levenshtein_distance("abc", "abc"), 0);
        assert_eq!(levenshtein_distance("abc", "ab"), 1);
        assert_eq!(levenshtein_distance("abc", "abd"), 1);
        assert_eq!(levenshtein_distance("kitten", "sitting"), 3);
    }
}
