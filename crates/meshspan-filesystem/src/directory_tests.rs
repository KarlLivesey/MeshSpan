// SPDX-License-Identifier: GPL-2.0-only

use meshspan_domain::{ObjectId, ObjectRevisionId};

use super::{DirectoryEntry, DirectoryEntryKind, DirectoryTrie, DirectoryTrieError, node_digest};
use crate::{NamespaceComponent, NamespaceLimits};

#[test]
fn create_update_and_historical_lookup_path_copy_only_selected_nodes()
-> Result<(), Box<dyn std::error::Error>> {
    let mut trie = DirectoryTrie::empty();
    let empty_root = trie.root();
    let first = entry("Report", 1, 2)?;
    let created = trie.upsert(first.clone(), None)?;
    assert_eq!(created.previous_root, empty_root);
    assert_eq!(created.created_node_count, 65);
    assert_eq!(created.created_nodes.len(), created.created_node_count);
    for digest in &created.created_nodes {
        assert_eq!(trie.record(*digest)?.digest(), *digest);
    }
    assert_eq!(trie.lookup(first.name())?, Some(first.clone()));
    assert_eq!(trie.lookup_at(empty_root, first.name())?, None);

    let updated = entry("REPORT", 1, 3)?;
    let update = trie.upsert(updated.clone(), Some(first.object_revision_id()))?;
    assert_eq!(update.previous_entry, Some(first));
    assert_eq!(update.created_node_count, 65);
    assert_eq!(trie.lookup(updated.name())?, Some(updated));
    trie.verify()?;
    Ok(())
}

#[test]
fn stale_revision_and_different_object_cannot_replace_name()
-> Result<(), Box<dyn std::error::Error>> {
    let mut trie = DirectoryTrie::empty();
    let first = entry("same", 4, 5)?;
    trie.upsert(first.clone(), None)?;
    assert_eq!(
        trie.upsert(entry("SAME", 4, 6)?, None),
        Err(DirectoryTrieError::StaleEntry)
    );
    assert_eq!(
        trie.upsert(entry("SAME", 7, 8)?, Some(first.object_revision_id())),
        Err(DirectoryTrieError::NameConflict)
    );
    assert_eq!(trie.lookup(first.name())?, Some(first));
    Ok(())
}

#[test]
fn separate_keys_share_unchanged_nodes_and_rebuild_exactly()
-> Result<(), Box<dyn std::error::Error>> {
    let mut trie = DirectoryTrie::empty();
    let first = entry("alpha", 10, 11)?;
    let second = entry("beta", 12, 13)?;
    trie.upsert(first.clone(), None)?;
    let retained_after_first = trie.retained_node_count();
    let old_root = trie.root();
    let mutation = trie.upsert(second.clone(), None)?;
    assert!(mutation.created_node_count <= 65);
    assert!(trie.retained_node_count() > retained_after_first);
    assert_eq!(trie.lookup_at(old_root, first.name())?, Some(first.clone()));
    assert_eq!(trie.lookup_at(old_root, second.name())?, None);
    assert_eq!(trie.lookup(first.name())?, Some(first));
    assert_eq!(trie.lookup(second.name())?, Some(second));

    let records: Vec<_> = trie.records().collect();
    let rebuilt = DirectoryTrie::from_records(trie.root(), records)?;
    rebuilt.verify()?;
    assert_eq!(rebuilt.root(), trie.root());
    Ok(())
}

#[test]
fn digest_mismatch_in_untrusted_records_fails_closed() -> Result<(), Box<dyn std::error::Error>> {
    let trie = DirectoryTrie::empty();
    let mut records: Vec<_> = trie.records().collect();
    records[0].digest = super::DirectoryNodeDigest::from_bytes([9; 32]);
    assert!(matches!(
        DirectoryTrie::from_records(trie.root(), records),
        Err(DirectoryTrieError::Corrupt)
    ));
    let record = trie.records().next().ok_or("missing root")?;
    assert_eq!(record.digest, node_digest(&record.node));
    Ok(())
}

#[test]
fn canonical_node_codec_round_trips_and_rejects_corruption()
-> Result<(), Box<dyn std::error::Error>> {
    let mut trie = DirectoryTrie::empty();
    trie.upsert(entry("codec", 20, 21)?, None)?;
    for record in trie.records() {
        let mut encoded = record.encode();
        assert_eq!(
            super::DirectoryNodeRecord::decode(record.digest(), &encoded)?,
            record
        );
        let last = encoded.last_mut().ok_or("empty encoding")?;
        *last ^= 1;
        assert!(matches!(
            super::DirectoryNodeRecord::decode(record.digest(), &encoded),
            Err(DirectoryTrieError::Corrupt)
        ));
    }
    Ok(())
}

#[test]
fn mutation_work_stays_bounded_as_directory_grows() -> Result<(), Box<dyn std::error::Error>> {
    let mut trie = DirectoryTrie::empty();
    for index in 0_u64..512 {
        let mutation = trie.upsert(numbered_entry(index)?, None)?;
        assert!(mutation.created_node_count <= 65);
    }
    for index in [0_u64, 255, 511] {
        let expected = numbered_entry(index)?;
        assert_eq!(trie.lookup(expected.name())?, Some(expected));
    }
    trie.verify()?;
    Ok(())
}

fn entry(
    display: &str,
    object: u8,
    revision: u8,
) -> Result<DirectoryEntry, Box<dyn std::error::Error>> {
    Ok(DirectoryEntry::new(
        NamespaceComponent::new(display, NamespaceLimits::PORTABLE)?,
        ObjectId::from_bytes([object; 16])?,
        ObjectRevisionId::from_bytes([revision; 16])?,
        DirectoryEntryKind::File,
        1,
    )?)
}

fn numbered_entry(index: u64) -> Result<DirectoryEntry, Box<dyn std::error::Error>> {
    let mut object = [0_u8; 16];
    object[..8].copy_from_slice(&index.saturating_add(1).to_be_bytes());
    object[15] = 1;
    let mut revision = object;
    revision[15] = 2;
    Ok(DirectoryEntry::new(
        NamespaceComponent::new(&format!("entry-{index}"), NamespaceLimits::PORTABLE)?,
        ObjectId::from_bytes(object)?,
        ObjectRevisionId::from_bytes(revision)?,
        DirectoryEntryKind::File,
        1,
    )?)
}
