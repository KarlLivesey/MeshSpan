// SPDX-License-Identifier: GPL-2.0-only

//! Bounded content-addressed radix trie for immutable directory entry blocks.

use std::collections::BTreeMap;

use meshspan_domain::{ObjectId, ObjectRevisionId};
use thiserror::Error;

use crate::NamespaceComponent;

const HASH_NIBBLES: usize = 64;
const MAXIMUM_HASH_COLLISION_ENTRIES: usize = 8;
const MAXIMUM_ENCODED_NODE_BYTES: usize = 300 * 1_024;

/// BLAKE3 identity of one immutable directory trie node.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct DirectoryNodeDigest([u8; 32]);

impl DirectoryNodeDigest {
    /// Constructs a node digest from its exact canonical bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns the exact digest bytes.
    #[must_use]
    pub const fn as_bytes(self) -> [u8; 32] {
        self.0
    }
}

/// Protocol-neutral namespace object kind stored in a directory entry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DirectoryEntryKind {
    /// Child directory.
    Directory,
    /// Regular file.
    File,
}

/// One immutable case-preserving entry selected by its canonical comparison key.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DirectoryEntry {
    name: NamespaceComponent,
    object_id: ObjectId,
    object_revision_id: ObjectRevisionId,
    kind: DirectoryEntryKind,
    generation: u64,
}

impl DirectoryEntry {
    /// Constructs one entry with a positive name-reuse generation.
    ///
    /// # Errors
    ///
    /// Rejects generation zero.
    pub fn new(
        name: NamespaceComponent,
        object_id: ObjectId,
        object_revision_id: ObjectRevisionId,
        kind: DirectoryEntryKind,
        generation: u64,
    ) -> Result<Self, DirectoryTrieError> {
        if generation == 0 {
            return Err(DirectoryTrieError::InvalidEntry);
        }
        Ok(Self {
            name,
            object_id,
            object_revision_id,
            kind,
            generation,
        })
    }

    /// Case-preserved display and canonical lookup name.
    #[must_use]
    pub const fn name(&self) -> &NamespaceComponent {
        &self.name
    }

    /// Stable child object identity.
    #[must_use]
    pub const fn object_id(&self) -> ObjectId {
        self.object_id
    }

    /// Exact immutable child revision selected by this directory version.
    #[must_use]
    pub const fn object_revision_id(&self) -> ObjectRevisionId {
        self.object_revision_id
    }

    /// Child object kind.
    #[must_use]
    pub const fn kind(&self) -> DirectoryEntryKind {
        self.kind
    }

    /// Monotonic identity generation for reuse of this canonical name.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }
}

/// Exact path-copy outcome for one directory entry mutation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DirectoryMutation {
    /// Root selected before the mutation.
    pub previous_root: DirectoryNodeDigest,
    /// New root selecting the changed entry and every unchanged subtree.
    pub new_root: DirectoryNodeDigest,
    /// Prior entry when an existing object's revision was replaced.
    pub previous_entry: Option<DirectoryEntry>,
    /// Number of newly materialised immutable nodes.
    pub created_node_count: usize,
    /// Exact content identities requiring durable insertion for this root transition.
    pub created_nodes: Vec<DirectoryNodeDigest>,
}

/// In-memory semantic kernel for a persistent immutable directory-node repository.
///
/// Mutations append content-addressed nodes and move only this view's root. Older roots remain
/// readable and can be pinned by namespace commits or snapshots. The durable branch store persists
/// the same node records and root transition transactionally.
pub struct DirectoryTrie {
    root: DirectoryNodeDigest,
    nodes: BTreeMap<DirectoryNodeDigest, DirectoryNode>,
    complete: bool,
}

impl DirectoryTrie {
    /// Creates one empty directory with a verified immutable root node.
    #[must_use]
    pub fn empty() -> Self {
        let node = DirectoryNode::Internal(InternalNode {
            depth: 0,
            children: BTreeMap::new(),
        });
        let root = node_digest(&node);
        let mut nodes = BTreeMap::new();
        nodes.insert(root, node);
        Self {
            root,
            nodes,
            complete: true,
        }
    }

    /// Reconstructs a trie from untrusted immutable node records and verifies the selected root.
    ///
    /// # Errors
    ///
    /// Rejects duplicate-digest conflicts, malformed nodes, missing children, cycles, unreachable
    /// depth transitions and any content/digest mismatch.
    pub fn from_records(
        root: DirectoryNodeDigest,
        records: impl IntoIterator<Item = DirectoryNodeRecord>,
    ) -> Result<Self, DirectoryTrieError> {
        let mut nodes = BTreeMap::new();
        for record in records {
            validate_node(&record.node)?;
            if record.digest != node_digest(&record.node)
                || nodes
                    .insert(record.digest, record.node.clone())
                    .is_some_and(|existing| existing != record.node)
            {
                return Err(DirectoryTrieError::Corrupt);
            }
        }
        let trie = Self {
            root,
            nodes,
            complete: true,
        };
        trie.verify()?;
        Ok(trie)
    }

    pub(crate) fn from_selected_records(
        root: DirectoryNodeDigest,
        records: impl IntoIterator<Item = DirectoryNodeRecord>,
        name: &NamespaceComponent,
    ) -> Result<Self, DirectoryTrieError> {
        let mut nodes = BTreeMap::new();
        for record in records {
            validate_node(&record.node)?;
            if record.digest != node_digest(&record.node)
                || nodes
                    .insert(record.digest, record.node.clone())
                    .is_some_and(|existing| existing != record.node)
            {
                return Err(DirectoryTrieError::Corrupt);
            }
        }
        let trie = Self {
            root,
            nodes,
            complete: false,
        };
        trie.lookup(name)?;
        Ok(trie)
    }

    /// Current immutable directory root.
    #[must_use]
    pub const fn root(&self) -> DirectoryNodeDigest {
        self.root
    }

    /// Number of immutable nodes retained across current and historical roots.
    #[must_use]
    pub fn retained_node_count(&self) -> usize {
        self.nodes.len()
    }

    /// Looks up a canonical component beneath the current root.
    ///
    /// # Errors
    ///
    /// Fails closed if any selected node, edge, depth or digest is invalid.
    pub fn lookup(
        &self,
        name: &NamespaceComponent,
    ) -> Result<Option<DirectoryEntry>, DirectoryTrieError> {
        self.lookup_at(self.root, name)
    }

    /// Looks up a component beneath an explicitly retained historical root.
    ///
    /// # Errors
    ///
    /// Fails closed if the root or any selected node is absent or corrupt.
    pub fn lookup_at(
        &self,
        root: DirectoryNodeDigest,
        name: &NamespaceComponent,
    ) -> Result<Option<DirectoryEntry>, DirectoryTrieError> {
        let key_hash = name_hash(name.canonical());
        let mut selected = root;
        for depth in 0..HASH_NIBBLES {
            let node = self.load_verified(selected)?;
            let DirectoryNode::Internal(internal) = node else {
                return Err(DirectoryTrieError::Corrupt);
            };
            if usize::from(internal.depth) != depth {
                return Err(DirectoryTrieError::Corrupt);
            }
            let Some(child) = internal.children.get(&nibble(&key_hash, depth)) else {
                return Ok(None);
            };
            selected = *child;
        }
        let node = self.load_verified(selected)?;
        let DirectoryNode::Leaf(leaf) = node else {
            return Err(DirectoryTrieError::Corrupt);
        };
        if leaf.key_hash != key_hash {
            return Err(DirectoryTrieError::Corrupt);
        }
        Ok(leaf
            .entries
            .iter()
            .find(|entry| entry.name.canonical() == name.canonical())
            .cloned())
    }

    /// Appends only the nodes on one canonical-key path and advances the current root.
    ///
    /// `expected_revision` is `None` for create and the exact selected child revision for update.
    /// Existing canonical names cannot be silently replaced by a different stable object.
    ///
    /// # Errors
    ///
    /// Rejects stale expectations, identity/generation conflicts, collision-bucket exhaustion and
    /// any corrupt selected immutable node.
    pub fn upsert(
        &mut self,
        entry: DirectoryEntry,
        expected_revision: Option<ObjectRevisionId>,
    ) -> Result<DirectoryMutation, DirectoryTrieError> {
        let previous = self.lookup(&entry.name)?;
        validate_replacement(previous.as_ref(), &entry, expected_revision)?;
        let previous_root = self.root;
        let key_hash = name_hash(entry.name.canonical());
        let mut created = Vec::new();
        let new_root = self.upsert_node(self.root, 0, key_hash, entry, &mut created)?;
        self.root = new_root;
        Ok(DirectoryMutation {
            previous_root,
            new_root,
            previous_entry: previous,
            created_node_count: created.len(),
            created_nodes: created,
        })
    }

    /// Removes one exact canonical-name incarnation and path-copies only its hash path.
    ///
    /// # Errors
    ///
    /// Rejects an absent/stale entry and every malformed selected immutable node.
    pub fn remove(
        &mut self,
        name: &NamespaceComponent,
        expected_revision: ObjectRevisionId,
    ) -> Result<DirectoryMutation, DirectoryTrieError> {
        let previous = self.lookup(name)?.ok_or(DirectoryTrieError::StaleEntry)?;
        if previous.object_revision_id() != expected_revision {
            return Err(DirectoryTrieError::StaleEntry);
        }
        let previous_root = self.root;
        let key_hash = name_hash(name.canonical());
        let mut created = Vec::new();
        let new_root = self
            .remove_node(self.root, 0, key_hash, name, &mut created)?
            .ok_or(DirectoryTrieError::Corrupt)?;
        self.root = new_root;
        Ok(DirectoryMutation {
            previous_root,
            new_root,
            previous_entry: Some(previous),
            created_node_count: created.len(),
            created_nodes: created,
        })
    }

    /// Verifies the complete graph reachable from the current root.
    ///
    /// # Errors
    ///
    /// Rejects cycles, missing nodes, wrong depths, malformed fanout/leaves and digest mismatch.
    pub fn verify(&self) -> Result<(), DirectoryTrieError> {
        if !self.complete {
            return Err(DirectoryTrieError::Corrupt);
        }
        self.verify_node(self.root, 0, &mut Vec::new(), &mut BTreeMap::new())
    }

    /// Returns immutable node records suitable for a bounded durable repository.
    pub fn records(&self) -> impl Iterator<Item = DirectoryNodeRecord> + '_ {
        self.nodes.iter().map(|(digest, node)| DirectoryNodeRecord {
            digest: *digest,
            node: node.clone(),
        })
    }

    /// Loads and revalidates one retained immutable node record by content identity.
    ///
    /// # Errors
    ///
    /// Rejects an absent or corrupt record.
    pub fn record(
        &self,
        digest: DirectoryNodeDigest,
    ) -> Result<DirectoryNodeRecord, DirectoryTrieError> {
        Ok(DirectoryNodeRecord {
            digest,
            node: self.load_verified(digest)?.clone(),
        })
    }

    fn upsert_node(
        &mut self,
        selected: DirectoryNodeDigest,
        depth: usize,
        key_hash: [u8; 32],
        entry: DirectoryEntry,
        created: &mut Vec<DirectoryNodeDigest>,
    ) -> Result<DirectoryNodeDigest, DirectoryTrieError> {
        if depth == HASH_NIBBLES {
            return self.upsert_leaf(selected, key_hash, entry, created);
        }
        let DirectoryNode::Internal(mut internal) = self.load_verified(selected)?.clone() else {
            return Err(DirectoryTrieError::Corrupt);
        };
        if usize::from(internal.depth) != depth {
            return Err(DirectoryTrieError::Corrupt);
        }
        let slot = nibble(&key_hash, depth);
        let child = if let Some(child) = internal.children.get(&slot) {
            self.upsert_node(*child, depth + 1, key_hash, entry, created)?
        } else {
            self.build_path(depth + 1, key_hash, entry, created)?
        };
        internal.children.insert(slot, child);
        self.store_node(DirectoryNode::Internal(internal), created)
    }

    fn remove_node(
        &mut self,
        selected: DirectoryNodeDigest,
        depth: usize,
        key_hash: [u8; 32],
        name: &NamespaceComponent,
        created: &mut Vec<DirectoryNodeDigest>,
    ) -> Result<Option<DirectoryNodeDigest>, DirectoryTrieError> {
        if depth == HASH_NIBBLES {
            let DirectoryNode::Leaf(mut leaf) = self.load_verified(selected)?.clone() else {
                return Err(DirectoryTrieError::Corrupt);
            };
            if leaf.key_hash != key_hash {
                return Err(DirectoryTrieError::Corrupt);
            }
            let index = leaf
                .entries
                .binary_search_by(|entry| entry.name.canonical().cmp(name.canonical()))
                .map_err(|_| DirectoryTrieError::StaleEntry)?;
            leaf.entries.remove(index);
            return if leaf.entries.is_empty() {
                Ok(None)
            } else {
                self.store_node(DirectoryNode::Leaf(leaf), created)
                    .map(Some)
            };
        }
        let DirectoryNode::Internal(mut internal) = self.load_verified(selected)?.clone() else {
            return Err(DirectoryTrieError::Corrupt);
        };
        if usize::from(internal.depth) != depth {
            return Err(DirectoryTrieError::Corrupt);
        }
        let slot = nibble(&key_hash, depth);
        let child = internal
            .children
            .get(&slot)
            .copied()
            .ok_or(DirectoryTrieError::StaleEntry)?;
        match self.remove_node(child, depth + 1, key_hash, name, created)? {
            Some(next) => {
                internal.children.insert(slot, next);
            }
            None => {
                internal.children.remove(&slot);
            }
        }
        if depth != 0 && internal.children.is_empty() {
            Ok(None)
        } else {
            self.store_node(DirectoryNode::Internal(internal), created)
                .map(Some)
        }
    }

    fn build_path(
        &mut self,
        depth: usize,
        key_hash: [u8; 32],
        entry: DirectoryEntry,
        created: &mut Vec<DirectoryNodeDigest>,
    ) -> Result<DirectoryNodeDigest, DirectoryTrieError> {
        if depth == HASH_NIBBLES {
            let leaf = LeafNode {
                key_hash,
                entries: vec![entry],
            };
            return self.store_node(DirectoryNode::Leaf(leaf), created);
        }
        let child = self.build_path(depth + 1, key_hash, entry, created)?;
        let mut children = BTreeMap::new();
        children.insert(nibble(&key_hash, depth), child);
        let internal = InternalNode {
            depth: u8::try_from(depth).map_err(|_| DirectoryTrieError::Corrupt)?,
            children,
        };
        self.store_node(DirectoryNode::Internal(internal), created)
    }

    fn upsert_leaf(
        &mut self,
        selected: DirectoryNodeDigest,
        key_hash: [u8; 32],
        entry: DirectoryEntry,
        created: &mut Vec<DirectoryNodeDigest>,
    ) -> Result<DirectoryNodeDigest, DirectoryTrieError> {
        let DirectoryNode::Leaf(mut leaf) = self.load_verified(selected)?.clone() else {
            return Err(DirectoryTrieError::Corrupt);
        };
        if leaf.key_hash != key_hash {
            return Err(DirectoryTrieError::Corrupt);
        }
        match leaf
            .entries
            .binary_search_by(|current| current.name.canonical().cmp(entry.name.canonical()))
        {
            Ok(index) => leaf.entries[index] = entry,
            Err(index) if leaf.entries.len() < MAXIMUM_HASH_COLLISION_ENTRIES => {
                leaf.entries.insert(index, entry);
            }
            Err(_) => return Err(DirectoryTrieError::CollisionCapacity),
        }
        self.store_node(DirectoryNode::Leaf(leaf), created)
    }

    fn store_node(
        &mut self,
        node: DirectoryNode,
        created: &mut Vec<DirectoryNodeDigest>,
    ) -> Result<DirectoryNodeDigest, DirectoryTrieError> {
        validate_node(&node)?;
        let digest = node_digest(&node);
        if let Some(existing) = self.nodes.get(&digest) {
            return if existing == &node {
                Ok(digest)
            } else {
                Err(DirectoryTrieError::DigestCollision)
            };
        }
        self.nodes.insert(digest, node);
        created.push(digest);
        Ok(digest)
    }

    fn load_verified(
        &self,
        digest: DirectoryNodeDigest,
    ) -> Result<&DirectoryNode, DirectoryTrieError> {
        let node = self.nodes.get(&digest).ok_or(DirectoryTrieError::Corrupt)?;
        validate_node(node)?;
        if node_digest(node) == digest {
            Ok(node)
        } else {
            Err(DirectoryTrieError::Corrupt)
        }
    }

    fn verify_node(
        &self,
        digest: DirectoryNodeDigest,
        depth: usize,
        path: &mut Vec<u8>,
        seen_paths: &mut BTreeMap<DirectoryNodeDigest, Vec<u8>>,
    ) -> Result<(), DirectoryTrieError> {
        if seen_paths.insert(digest, path.clone()).is_some() {
            return Err(DirectoryTrieError::Corrupt);
        }
        match self.load_verified(digest)? {
            DirectoryNode::Internal(internal) if usize::from(internal.depth) == depth => {
                for (slot, child) in &internal.children {
                    path.push(*slot);
                    self.verify_node(*child, depth + 1, path, seen_paths)?;
                    path.pop();
                }
            }
            DirectoryNode::Leaf(leaf) if depth == HASH_NIBBLES => {
                if path
                    .iter()
                    .enumerate()
                    .any(|(index, slot)| nibble(&leaf.key_hash, index) != *slot)
                {
                    return Err(DirectoryTrieError::Corrupt);
                }
                for entry in &leaf.entries {
                    if name_hash(entry.name.canonical()) != leaf.key_hash {
                        return Err(DirectoryTrieError::Corrupt);
                    }
                }
            }
            _ => return Err(DirectoryTrieError::Corrupt),
        }
        Ok(())
    }
}

/// Stable immutable-directory failure categories.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum DirectoryTrieError {
    /// Generation or entry relationship is invalid.
    #[error("directory entry is invalid")]
    InvalidEntry,
    /// The expected prior child revision does not match the selected root.
    #[error("directory entry base is stale")]
    StaleEntry,
    /// The canonical name already belongs to a different stable object or generation.
    #[error("directory entry identity conflicts with the selected name")]
    NameConflict,
    /// A hostile digest-collision bucket exceeded its hard safety bound.
    #[error("directory hash-collision bucket is full")]
    CollisionCapacity,
    /// Two different immutable nodes produced one content digest.
    #[error("directory node digest collision detected")]
    DigestCollision,
    /// An immutable node graph violates its digest, depth, fanout or ordering contract.
    #[error("directory node graph is corrupt")]
    Corrupt,
}

/// One immutable content-addressed directory node record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DirectoryNodeRecord {
    pub(crate) digest: DirectoryNodeDigest,
    pub(crate) node: DirectoryNode,
}

pub(crate) enum DirectoryNodeView {
    Internal {
        depth: u8,
        children: Vec<(u8, DirectoryNodeDigest)>,
    },
    Leaf {
        key_hash: [u8; 32],
        entries: Vec<DirectoryEntry>,
    },
}

impl DirectoryNodeRecord {
    /// Content digest binding the complete node encoding.
    #[must_use]
    pub const fn digest(&self) -> DirectoryNodeDigest {
        self.digest
    }

    pub(crate) fn encode(&self) -> Vec<u8> {
        encode_node(&self.node)
    }

    pub(crate) fn decode(
        digest: DirectoryNodeDigest,
        encoded: &[u8],
    ) -> Result<Self, DirectoryTrieError> {
        if encoded.len() > MAXIMUM_ENCODED_NODE_BYTES {
            return Err(DirectoryTrieError::Corrupt);
        }
        let mut cursor = DecodeCursor::new(encoded);
        let node = match cursor.byte()? {
            1 => decode_internal(&mut cursor)?,
            2 => decode_leaf(&mut cursor)?,
            _ => return Err(DirectoryTrieError::Corrupt),
        };
        if !cursor.is_empty() {
            return Err(DirectoryTrieError::Corrupt);
        }
        validate_node(&node)?;
        if node_digest(&node) != digest {
            return Err(DirectoryTrieError::Corrupt);
        }
        Ok(Self { digest, node })
    }

    pub(crate) fn selected_child(
        &self,
        name: &NamespaceComponent,
        depth: usize,
    ) -> Result<Option<DirectoryNodeDigest>, DirectoryTrieError> {
        let key_hash = name_hash(name.canonical());
        match &self.node {
            DirectoryNode::Internal(internal)
                if depth < HASH_NIBBLES && usize::from(internal.depth) == depth =>
            {
                Ok(internal.children.get(&nibble(&key_hash, depth)).copied())
            }
            DirectoryNode::Leaf(leaf) if depth == HASH_NIBBLES && leaf.key_hash == key_hash => {
                Ok(None)
            }
            _ => Err(DirectoryTrieError::Corrupt),
        }
    }

    pub(crate) fn view(&self) -> DirectoryNodeView {
        match &self.node {
            DirectoryNode::Internal(internal) => DirectoryNodeView::Internal {
                depth: internal.depth,
                children: internal
                    .children
                    .iter()
                    .map(|(slot, child)| (*slot, *child))
                    .collect(),
            },
            DirectoryNode::Leaf(leaf) => DirectoryNodeView::Leaf {
                key_hash: leaf.key_hash,
                entries: leaf.entries.clone(),
            },
        }
    }

    pub(crate) fn reachability_references(&self) -> Vec<DirectoryReachabilityReference> {
        match &self.node {
            DirectoryNode::Internal(internal) => internal
                .children
                .values()
                .copied()
                .map(DirectoryReachabilityReference::Node)
                .collect(),
            DirectoryNode::Leaf(leaf) => leaf
                .entries
                .iter()
                .map(|entry| {
                    DirectoryReachabilityReference::ObjectRevision(entry.object_revision_id())
                })
                .collect(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DirectoryReachabilityReference {
    Node(DirectoryNodeDigest),
    ObjectRevision(ObjectRevisionId),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum DirectoryNode {
    Internal(InternalNode),
    Leaf(LeafNode),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct InternalNode {
    depth: u8,
    children: BTreeMap<u8, DirectoryNodeDigest>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct LeafNode {
    key_hash: [u8; 32],
    entries: Vec<DirectoryEntry>,
}

fn validate_replacement(
    previous: Option<&DirectoryEntry>,
    next: &DirectoryEntry,
    expected_revision: Option<ObjectRevisionId>,
) -> Result<(), DirectoryTrieError> {
    if previous.map(DirectoryEntry::object_revision_id) != expected_revision {
        return Err(DirectoryTrieError::StaleEntry);
    }
    if let Some(previous) = previous
        && (previous.object_id != next.object_id
            || previous.kind != next.kind
            || previous.generation != next.generation)
    {
        return Err(DirectoryTrieError::NameConflict);
    }
    Ok(())
}

fn validate_node(node: &DirectoryNode) -> Result<(), DirectoryTrieError> {
    match node {
        DirectoryNode::Internal(internal)
            if usize::from(internal.depth) < HASH_NIBBLES
                && internal.children.len() <= 16
                && internal.children.keys().all(|slot| *slot < 16) =>
        {
            Ok(())
        }
        DirectoryNode::Leaf(leaf)
            if !leaf.entries.is_empty()
                && leaf.entries.len() <= MAXIMUM_HASH_COLLISION_ENTRIES
                && leaf
                    .entries
                    .iter()
                    .all(|entry| name_hash(entry.name.canonical()) == leaf.key_hash)
                && leaf
                    .entries
                    .windows(2)
                    .all(|pair| pair[0].name.canonical() < pair[1].name.canonical()) =>
        {
            Ok(())
        }
        _ => Err(DirectoryTrieError::Corrupt),
    }
}

fn name_hash(canonical: &str) -> [u8; 32] {
    let mut digest = blake3::Hasher::new();
    digest.update(b"meshspan.filesystem.directory-name.v1\0");
    digest.update(canonical.as_bytes());
    digest.finalize().into()
}

pub(crate) fn directory_name_hash(name: &NamespaceComponent) -> [u8; 32] {
    name_hash(name.canonical())
}

fn nibble(hash: &[u8; 32], depth: usize) -> u8 {
    let byte = hash[depth / 2];
    if depth.is_multiple_of(2) {
        byte >> 4
    } else {
        byte & 15
    }
}

fn node_digest(node: &DirectoryNode) -> DirectoryNodeDigest {
    let mut digest = blake3::Hasher::new();
    digest.update(b"meshspan.filesystem.directory-node.v1\0");
    digest.update(&encode_node(node));
    DirectoryNodeDigest::from_bytes(digest.finalize().into())
}

fn encode_node(node: &DirectoryNode) -> Vec<u8> {
    let mut encoded = Vec::new();
    match node {
        DirectoryNode::Internal(internal) => {
            encoded.extend_from_slice(&[1, internal.depth]);
            encoded.extend_from_slice(
                &u16::try_from(internal.children.len())
                    .unwrap_or(u16::MAX)
                    .to_be_bytes(),
            );
            for (slot, child) in &internal.children {
                encoded.push(*slot);
                encoded.extend_from_slice(&child.as_bytes());
            }
        }
        DirectoryNode::Leaf(leaf) => {
            encoded.push(2);
            encoded.extend_from_slice(&leaf.key_hash);
            encoded.extend_from_slice(
                &u16::try_from(leaf.entries.len())
                    .unwrap_or(u16::MAX)
                    .to_be_bytes(),
            );
            for entry in &leaf.entries {
                encode_text(&mut encoded, entry.name.canonical());
                encode_text(&mut encoded, entry.name.display());
                encoded.extend_from_slice(&entry.object_id.as_bytes());
                encoded.extend_from_slice(&entry.object_revision_id.as_bytes());
                encoded.push(match entry.kind {
                    DirectoryEntryKind::Directory => 1,
                    DirectoryEntryKind::File => 2,
                });
                encoded.extend_from_slice(&entry.generation.to_be_bytes());
            }
        }
    }
    encoded
}

fn encode_text(encoded: &mut Vec<u8>, value: &str) {
    encoded.extend_from_slice(&u32::try_from(value.len()).unwrap_or(u32::MAX).to_be_bytes());
    encoded.extend_from_slice(value.as_bytes());
}

fn decode_internal(cursor: &mut DecodeCursor<'_>) -> Result<DirectoryNode, DirectoryTrieError> {
    let depth = cursor.byte()?;
    let count = usize::from(cursor.u16()?);
    if count > 16 {
        return Err(DirectoryTrieError::Corrupt);
    }
    let mut children = BTreeMap::new();
    for _ in 0..count {
        let slot = cursor.byte()?;
        let child = DirectoryNodeDigest::from_bytes(cursor.array()?);
        if children.insert(slot, child).is_some() {
            return Err(DirectoryTrieError::Corrupt);
        }
    }
    Ok(DirectoryNode::Internal(InternalNode { depth, children }))
}

fn decode_leaf(cursor: &mut DecodeCursor<'_>) -> Result<DirectoryNode, DirectoryTrieError> {
    let key_hash = cursor.array()?;
    let count = usize::from(cursor.u16()?);
    if count == 0 || count > MAXIMUM_HASH_COLLISION_ENTRIES {
        return Err(DirectoryTrieError::Corrupt);
    }
    let mut entries = Vec::with_capacity(count);
    for _ in 0..count {
        entries.push(decode_entry(cursor)?);
    }
    Ok(DirectoryNode::Leaf(LeafNode { key_hash, entries }))
}

fn decode_entry(cursor: &mut DecodeCursor<'_>) -> Result<DirectoryEntry, DirectoryTrieError> {
    let canonical = cursor.text()?;
    let display = cursor.text()?;
    let name = NamespaceComponent::from_stored(display, canonical)
        .map_err(|_| DirectoryTrieError::Corrupt)?;
    let object_id =
        ObjectId::from_bytes(cursor.array()?).map_err(|_| DirectoryTrieError::Corrupt)?;
    let object_revision_id =
        ObjectRevisionId::from_bytes(cursor.array()?).map_err(|_| DirectoryTrieError::Corrupt)?;
    let kind = match cursor.byte()? {
        1 => DirectoryEntryKind::Directory,
        2 => DirectoryEntryKind::File,
        _ => return Err(DirectoryTrieError::Corrupt),
    };
    DirectoryEntry::new(name, object_id, object_revision_id, kind, cursor.u64()?)
        .map_err(|_| DirectoryTrieError::Corrupt)
}

struct DecodeCursor<'a> {
    remaining: &'a [u8],
}

impl<'a> DecodeCursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { remaining: bytes }
    }

    const fn is_empty(&self) -> bool {
        self.remaining.is_empty()
    }

    fn byte(&mut self) -> Result<u8, DirectoryTrieError> {
        let (first, remaining) = self
            .remaining
            .split_first()
            .ok_or(DirectoryTrieError::Corrupt)?;
        self.remaining = remaining;
        Ok(*first)
    }

    fn array<const LENGTH: usize>(&mut self) -> Result<[u8; LENGTH], DirectoryTrieError> {
        self.take(LENGTH)?
            .try_into()
            .map_err(|_| DirectoryTrieError::Corrupt)
    }

    fn u16(&mut self) -> Result<u16, DirectoryTrieError> {
        Ok(u16::from_be_bytes(self.array()?))
    }

    fn u32(&mut self) -> Result<u32, DirectoryTrieError> {
        Ok(u32::from_be_bytes(self.array()?))
    }

    fn u64(&mut self) -> Result<u64, DirectoryTrieError> {
        Ok(u64::from_be_bytes(self.array()?))
    }

    fn text(&mut self) -> Result<&'a str, DirectoryTrieError> {
        let length = usize::try_from(self.u32()?).map_err(|_| DirectoryTrieError::Corrupt)?;
        std::str::from_utf8(self.take(length)?).map_err(|_| DirectoryTrieError::Corrupt)
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], DirectoryTrieError> {
        let (selected, remaining) = self
            .remaining
            .split_at_checked(length)
            .ok_or(DirectoryTrieError::Corrupt)?;
        self.remaining = remaining;
        Ok(selected)
    }
}

#[cfg(test)]
#[path = "directory_tests.rs"]
mod tests;
