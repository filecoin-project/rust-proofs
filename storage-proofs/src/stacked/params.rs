use std::collections::HashMap;
use std::fmt;
use std::marker::PhantomData;

use merkletree::merkle::get_merkle_tree_leafs;
#[cfg(feature = "mem-trees")]
use merkletree::store::VecStore;
use merkletree::store::{DiskStore, Store, StoreConfig};
use serde::{Deserialize, Serialize};

use crate::drgraph::Graph;
use crate::error::Result;
use crate::fr32::bytes_into_fr_repr_safe;
use crate::hasher::{Domain, Hasher};
use crate::merkle::{MerkleProof, MerkleTree};
use crate::parameter_cache::ParameterSetMetadata;
use crate::stacked::{
    column::Column, column_proof::ColumnProof, graph::StackedBucketGraph, EncodingProof,
    LabelingProof, LayerChallenges,
};
use crate::util::data_at_node;

pub type Tree<H> = MerkleTree<<H as Hasher>::Domain, <H as Hasher>::Function>;

#[derive(Debug, Copy, Clone)]
pub enum CacheKey {
    PAux,
    TAux,
    CommDTree,
    CommCTree,
    CommQTree,
    CommRLastTree,
}

impl fmt::Display for CacheKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            CacheKey::PAux => write!(f, "p_aux"),
            CacheKey::TAux => write!(f, "t_aux"),
            CacheKey::CommDTree => write!(f, "tree-d"),
            CacheKey::CommCTree => write!(f, "tree-c"),
            CacheKey::CommQTree => write!(f, "tree-q"),
            CacheKey::CommRLastTree => write!(f, "tree-r-last"),
        }
    }
}

impl CacheKey {
    pub fn label_layer(layer: usize) -> String {
        format!("layer-{}", layer)
    }
}

#[derive(Debug, Clone)]
pub struct SetupParams {
    // Number of nodes
    pub nodes: usize,

    // Base degree of DRG
    pub degree: usize,

    pub expansion_degree: usize,

    // Random seed
    pub seed: [u8; 28],

    pub layer_challenges: LayerChallenges,
}

#[derive(Debug, Clone)]
pub struct PublicParams<H>
where
    H: 'static + Hasher,
{
    pub window_graph: StackedBucketGraph<H>,
    pub wrapper_graph: StackedBucketGraph<H>,
    pub layer_challenges: LayerChallenges,
    _h: PhantomData<H>,
}

impl<H> PublicParams<H>
where
    H: Hasher,
{
    pub fn new(
        window_graph: StackedBucketGraph<H>,
        wrapper_graph: StackedBucketGraph<H>,
        layer_challenges: LayerChallenges,
    ) -> Self {
        PublicParams {
            window_graph,
            wrapper_graph,
            layer_challenges,
            _h: PhantomData,
        }
    }
}

impl<H> ParameterSetMetadata for PublicParams<H>
where
    H: Hasher,
{
    fn identifier(&self) -> String {
        format!(
            "layered_drgporep::PublicParams{{ window_graph: {}, wrapper_graph: {}, challenges: {:?} }}",
            self.window_graph.identifier(),
            self.wrapper_graph.identifier(),
            self.layer_challenges,
        )
    }

    fn sector_size(&self) -> u64 {
        self.wrapper_graph.sector_size()
    }
}

impl<'a, H> From<&'a PublicParams<H>> for PublicParams<H>
where
    H: Hasher,
{
    fn from(other: &PublicParams<H>) -> PublicParams<H> {
        PublicParams::new(
            other.window_graph.clone(),
            other.wrapper_graph.clone(),
            other.layer_challenges.clone(),
        )
    }
}

#[derive(Debug, Clone)]
pub struct PublicInputs<T: Domain, S: Domain> {
    pub replica_id: T,
    pub seed: [u8; 32],
    pub tau: Option<Tau<T, S>>,
    pub k: Option<usize>,
}

impl<T: Domain, S: Domain> PublicInputs<T, S> {
    pub fn challenges(
        &self,
        layer_challenges: &LayerChallenges,
        layer: usize,
        leaves: usize,
        partition_k: Option<usize>,
    ) -> Vec<usize> {
        let k = partition_k.unwrap_or(0);

        layer_challenges.derive::<T>(layer, leaves, &self.replica_id, &self.seed, k as u8)
    }

    pub fn all_challenges(
        &self,
        layer_challenges: &LayerChallenges,
        leaves: usize,
        partition_k: Option<usize>,
    ) -> Vec<usize> {
        let k = partition_k.unwrap_or(0);

        layer_challenges.derive_all::<T>(leaves, &self.replica_id, &self.seed, k as u8)
    }
}

#[derive(Debug)]
pub struct PrivateInputs<H: Hasher, G: Hasher> {
    pub p_aux: PersistentAux<H::Domain>,
    pub t_aux: TemporaryAuxCache<H, G>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Proof<H: Hasher, G: Hasher> {
    #[serde(bound(
        serialize = "WindowProof<H, G>: Serialize",
        deserialize = "WindowProof<H, G>: Deserialize<'de>"
    ))]
    pub window_proofs: Vec<WindowProof<H, G>>,
    #[serde(bound(
        serialize = "WrapperProof<H>: Serialize",
        deserialize = "WrapperProof<H>: Deserialize<'de>"
    ))]
    pub wrapper_proofs: Vec<WrapperProof<H>>,
    pub comm_c: H::Domain,
    pub comm_q: H::Domain,
    pub comm_r_last: H::Domain,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WindowProof<H: Hasher, G: Hasher> {
    #[serde(bound(
        serialize = "MerkleProof<G>: Serialize",
        deserialize = "MerkleProof<G>: Deserialize<'de>"
    ))]
    pub comm_d_proof: MerkleProof<G>,
    #[serde(bound(
        serialize = "MerkleProof<H>: Serialize, ColumnProof<H>: Serialize",
        deserialize = "MerkleProof<H>: Deserialize<'de>, ColumnProof<H>: Deserialize<'de>"
    ))]
    pub comm_q_proof: MerkleProof<H>,
    #[serde(bound(
        serialize = "ReplicaColumnProof<H>: Serialize",
        deserialize = "ReplicaColumnProof<H>: Deserialize<'de>"
    ))]
    pub replica_column_proof: ReplicaColumnProof<H>,
    #[serde(bound(
        serialize = "LabelingProof<H>: Serialize",
        deserialize = "LabelingProof<H>: Deserialize<'de>"
    ))]
    /// Indexed by layer in 1..layers.
    pub labeling_proofs: HashMap<usize, LabelingProof<H>>,
    #[serde(bound(
        serialize = "EncodingProof<H>: Serialize",
        deserialize = "EncodingProof<H>: Deserialize<'de>"
    ))]
    pub encoding_proof: EncodingProof<H>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WrapperProof<H: Hasher> {
    #[serde(bound(
        serialize = "MerkleProof<H>: Serialize, ColumnProof<H>: Serialize",
        deserialize = "MerkleProof<H>: Deserialize<'de>, ColumnProof<H>: Deserialize<'de>"
    ))]
    pub comm_r_last_proof: MerkleProof<H>,
    #[serde(bound(
        serialize = "MerkleProof<H>: Serialize, ColumnProof<H>: Serialize",
        deserialize = "MerkleProof<H>: Deserialize<'de>, ColumnProof<H>: Deserialize<'de>"
    ))]
    pub comm_q_parents_proofs: Vec<MerkleProof<H>>,
    #[serde(bound(
        serialize = "LabelingProof<H>: Serialize",
        deserialize = "LabelingProof<H>: Deserialize<'de>"
    ))]
    pub labeling_proof: LabelingProof<H>,
}

impl<H: Hasher> WrapperProof<H> {
    pub fn comm_r_last(&self) -> &H::Domain {
        self.comm_r_last_proof.root()
    }

    /// Verify the full proof.
    pub fn verify<G: Hasher>(
        &self,
        pub_params: &PublicParams<H>,
        pub_inputs: &PublicInputs<<H as Hasher>::Domain, <G as Hasher>::Domain>,
        challenge: usize,
        challenge_index: usize,
        wrapper_graph: &StackedBucketGraph<H>,
        comm_q: &H::Domain,
    ) -> bool {
        let replica_id = &pub_inputs.replica_id;

        check!(challenge < wrapper_graph.size());
        check!(pub_inputs.tau.is_some());

        trace!("verify final replica layer openings");
        check!(self.comm_r_last_proof.proves_challenge(challenge));

        trace!("verify comm_q_parents");
        let mut parents = vec![0; wrapper_graph.expansion_degree()];
        wrapper_graph.expanded_parents(challenge, &mut parents);

        for (proof, parent) in self.comm_q_parents_proofs.iter().zip(parents.iter()) {
            check_eq!(proof.root(), comm_q);
            check!(proof.validate(challenge));
            // TODO: do we need to check for a relationship to `parent`?
        }

        trace!("verify labeling");
        let labeled_node = self.comm_r_last_proof.leaf();
        check!(self.labeling_proof.verify(replica_id, labeled_node));

        true
    }
}

impl<H: Hasher, G: Hasher> WindowProof<H, G> {
    pub fn comm_c(&self) -> &H::Domain {
        self.replica_column_proof.c_x.root()
    }

    /// Verify the full proof.
    pub fn verify(
        &self,
        pub_params: &PublicParams<H>,
        pub_inputs: &PublicInputs<<H as Hasher>::Domain, <G as Hasher>::Domain>,
        challenge: usize,
        challenge_index: usize,
        window_graph: &StackedBucketGraph<H>,
        comm_q: &H::Domain,
    ) -> bool {
        let replica_id = &pub_inputs.replica_id;

        check!(challenge < window_graph.size());
        check!(pub_inputs.tau.is_some());

        // Verify initial data layer
        trace!("verify initial data layer");

        check!(self.comm_d_proof.proves_challenge(challenge));

        if let Some(ref tau) = pub_inputs.tau {
            check_eq!(self.comm_d_proof.root(), &tau.comm_d);
        } else {
            return false;
        }

        // Verify q data layer
        trace!("verify initial q data layer");

        check!(self.comm_q_proof.proves_challenge(challenge));

        if let Some(ref tau) = pub_inputs.tau {
            check_eq!(self.comm_q_proof.root(), comm_q);
        } else {
            return false;
        }

        // Verify replica column openings
        trace!("verify replica column openings");
        let mut parents = vec![0; window_graph.degree()];
        window_graph.parents(challenge, &mut parents);
        check!(self.replica_column_proof.verify(challenge, &parents));

        check!(self.verify_labels(replica_id, &pub_params.layer_challenges, challenge_index));

        trace!("verify encoding");
        // TODO: encoding proof

        true
    }

    /// Verify all labels.
    fn verify_labels(
        &self,
        replica_id: &H::Domain,
        layer_challenges: &LayerChallenges,
        challenge_index: usize,
    ) -> bool {
        // Verify Labels Layer 1..layers
        for layer in 1..=layer_challenges.layers() {
            let expect_challenge =
                layer_challenges.include_challenge_at_layer(layer, challenge_index);
            trace!(
                "verify labeling (layer: {} - expect_challenge: {})",
                layer,
                expect_challenge
            );

            if expect_challenge {
                check!(self.labeling_proofs.contains_key(&layer));
                let labeling_proof = &self.labeling_proofs.get(&layer).unwrap();
                let labeled_node = self.replica_column_proof.c_x.get_node_at_layer(layer);
                check!(labeling_proof.verify(replica_id, labeled_node));
            } else {
                check!(self.labeling_proofs.get(&layer).is_none());
            }
        }

        true
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplicaColumnProof<H: Hasher> {
    #[serde(bound(
        serialize = "ColumnProof<H>: Serialize",
        deserialize = "ColumnProof<H>: Deserialize<'de>"
    ))]
    pub c_x: ColumnProof<H>,
    #[serde(bound(
        serialize = "ColumnProof<H>: Serialize",
        deserialize = "ColumnProof<H>: Deserialize<'de>"
    ))]
    pub drg_parents: Vec<ColumnProof<H>>,
    #[serde(bound(
        serialize = "ColumnProof<H>: Serialize",
        deserialize = "ColumnProof<H>: Deserialize<'de>"
    ))]
    pub exp_parents: Vec<ColumnProof<H>>,
}

impl<H: Hasher> ReplicaColumnProof<H> {
    pub fn verify(&self, challenge: usize, parents: &[u32]) -> bool {
        let expected_comm_c = self.c_x.root();

        trace!("  verify c_x");
        check!(self.c_x.verify(challenge as u32, &expected_comm_c));

        trace!("  verify drg_parents");
        for (proof, parent) in self.drg_parents.iter().zip(parents.iter()) {
            check!(proof.verify(*parent, &expected_comm_c));
        }

        trace!("  verify exp_parents");
        for (proof, parent) in self
            .exp_parents
            .iter()
            .zip(parents.iter().skip(self.drg_parents.len()))
        {
            check!(proof.verify(*parent, &expected_comm_c));
        }

        true
    }
}

pub type TransformedLayers<H, G> = (
    Tau<<H as Hasher>::Domain, <G as Hasher>::Domain>,
    PersistentAux<<H as Hasher>::Domain>,
    TemporaryAux<H, G>,
);

/// Tau for a single parition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tau<D: Domain, E: Domain> {
    pub comm_d: E,
    pub comm_r: D,
}

/// Stored along side the sector on disk.
#[derive(Default, Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PersistentAux<D> {
    pub comm_c: D,
    pub comm_q: D,
    pub comm_r_last: D,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemporaryAux<H: Hasher, G: Hasher> {
    /// The encoded nodes for 1..layers.
    pub labels: Labels<H>,
    pub tree_d_config: StoreConfig,
    pub tree_r_last_config: StoreConfig,
    pub tree_c_config: StoreConfig,
    pub tree_q_config: StoreConfig,
    pub _g: PhantomData<G>,
}

impl<H: Hasher, G: Hasher> TemporaryAux<H, G> {
    pub fn labels_for_layer(&self, layer: usize) -> DiskStore<H::Domain> {
        self.labels.labels_for_layer(layer)
    }

    pub fn domain_node_at_layer(&self, layer: usize, node_index: u32) -> Result<H::Domain> {
        Ok(self.labels_for_layer(layer).read_at(node_index as usize))
    }

    pub fn column(&self, column_index: u32) -> Result<Column<H>> {
        self.labels.column(column_index)
    }

    #[cfg(not(feature = "mem-trees"))]
    pub fn delete(t_aux: TemporaryAux<H, G>) -> Result<()> {
        let tree_d_size = t_aux.tree_d_config.size.unwrap();
        let tree_d_store: DiskStore<G::Domain> =
            DiskStore::new_from_disk(tree_d_size, &t_aux.tree_d_config)?;
        let tree_d: Tree<G> =
            MerkleTree::from_data_store(tree_d_store, get_merkle_tree_leafs(tree_d_size));
        tree_d.delete(t_aux.tree_d_config)?;

        let tree_c_size = t_aux.tree_c_config.size.unwrap();
        let tree_c_store: DiskStore<H::Domain> =
            DiskStore::new_from_disk(tree_c_size, &t_aux.tree_c_config)?;
        let tree_c: Tree<H> =
            MerkleTree::from_data_store(tree_c_store, get_merkle_tree_leafs(tree_c_size));
        tree_c.delete(t_aux.tree_c_config)?;

        for i in 0..t_aux.labels.labels.len() {
            DiskStore::<H::Domain>::delete(t_aux.labels.labels[i].clone())?;
        }

        Ok(())
    }
}

#[derive(Debug)]
pub struct TemporaryAuxCache<H: Hasher, G: Hasher> {
    /// The encoded nodes for 1..layers.
    pub labels: LabelsCache<H>,
    pub tree_d: Tree<G>,
    pub tree_q: Tree<H>,
    pub tree_r_last: Tree<H>,
    pub tree_c: Tree<H>,
    pub t_aux: TemporaryAux<H, G>,
}

impl<H: Hasher, G: Hasher> TemporaryAuxCache<H, G> {
    pub fn new(t_aux: &TemporaryAux<H, G>) -> Result<Self> {
        let tree_d_size = t_aux.tree_d_config.size.unwrap();
        #[cfg(not(feature = "mem-trees"))]
        let tree_d_store: DiskStore<G::Domain> =
            DiskStore::new_from_disk(tree_d_size, &t_aux.tree_d_config)?;
        #[cfg(feature = "mem-trees")]
        let tree_d_store: VecStore<G::Domain> =
            VecStore::new_with_config(tree_d_size, t_aux.tree_d_config.clone())?;
        let tree_d: Tree<G> =
            MerkleTree::from_data_store(tree_d_store, get_merkle_tree_leafs(tree_d_size));

        let tree_c_size = t_aux.tree_c_config.size.unwrap();
        #[cfg(not(feature = "mem-trees"))]
        let tree_c_store: DiskStore<H::Domain> =
            DiskStore::new_from_disk(tree_c_size, &t_aux.tree_c_config)?;
        #[cfg(feature = "mem-trees")]
        let tree_c_store: VecStore<H::Domain> =
            VecStore::new_with_config(tree_c_size, t_aux.tree_c_config.clone())?;
        let tree_c: Tree<H> =
            MerkleTree::from_data_store(tree_c_store, get_merkle_tree_leafs(tree_c_size));

        let tree_r_last_size = t_aux.tree_r_last_config.size.unwrap();
        #[cfg(not(feature = "mem-trees"))]
        let tree_r_last_store: DiskStore<H::Domain> =
            DiskStore::new_from_disk(tree_r_last_size, &t_aux.tree_r_last_config)?;
        #[cfg(feature = "mem-trees")]
        let tree_r_last_store: VecStore<H::Domain> =
            VecStore::new_with_config(tree_r_last_size, t_aux.tree_r_last_config.clone())?;
        let tree_r_last: Tree<H> =
            MerkleTree::from_data_store(tree_r_last_store, get_merkle_tree_leafs(tree_r_last_size));

        let tree_q_size = t_aux.tree_q_config.size.unwrap();
        #[cfg(not(feature = "mem-trees"))]
        let tree_q_store: DiskStore<H::Domain> =
            DiskStore::new_from_disk(tree_q_size, &t_aux.tree_q_config)?;
        #[cfg(feature = "mem-trees")]
        let tree_q_store: VecStore<H::Domain> =
            VecStore::new_with_config(tree_q_size, t_aux.tree_q_config.clone())?;
        let tree_q: Tree<H> =
            MerkleTree::from_data_store(tree_q_store, get_merkle_tree_leafs(tree_q_size));

        Ok(TemporaryAuxCache {
            labels: LabelsCache::new(&t_aux.labels),
            tree_d,
            tree_r_last,
            tree_c,
            tree_q,
            t_aux: t_aux.clone(),
        })
    }

    pub fn labels_for_layer(&self, layer: usize) -> &DiskStore<H::Domain> {
        self.labels.labels_for_layer(layer)
    }

    pub fn domain_node_at_layer(&self, layer: usize, node_index: u32) -> H::Domain {
        self.labels_for_layer(layer).read_at(node_index as usize)
    }

    pub fn column(&self, column_index: u32) -> Result<Column<H>> {
        self.labels.column(column_index)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Labels<H: Hasher> {
    pub labels: Vec<StoreConfig>,
    pub _h: PhantomData<H>,
}

impl<H: Hasher> Labels<H> {
    pub fn new(labels: Vec<StoreConfig>) -> Self {
        Labels {
            labels,
            _h: PhantomData,
        }
    }

    pub fn len(&self) -> usize {
        self.labels.len()
    }

    pub fn is_empty(&self) -> bool {
        self.labels.is_empty()
    }

    pub fn labels_for_layer(&self, layer: usize) -> DiskStore<H::Domain> {
        assert!(layer != 0, "Layer cannot be 0");
        assert!(
            layer <= self.layers(),
            "Layer {} is not available (only {} layers available)",
            layer,
            self.layers()
        );

        let row_index = layer - 1;
        let config = self.labels[row_index].clone();
        assert!(config.size.is_some());

        DiskStore::new_from_disk(config.size.unwrap(), &config).unwrap()
    }

    /// Returns label for the last layer.
    pub fn labels_for_last_layer(&self) -> DiskStore<H::Domain> {
        self.labels_for_layer(self.labels.len() - 1)
    }

    /// How many layers are available.
    fn layers(&self) -> usize {
        self.labels.len()
    }

    /// Build the column for the given node.
    pub fn column(&self, node: u32) -> Result<Column<H>> {
        let rows = self
            .labels
            .iter()
            .map(|label| {
                assert!(label.size.is_some());
                let store = DiskStore::new_from_disk(label.size.unwrap(), &label).unwrap();
                store.read_at(node as usize)
            })
            .collect();

        Ok(Column::new(node, rows))
    }
}

#[derive(Debug)]
pub struct LabelsCache<H: Hasher> {
    pub labels: Vec<DiskStore<H::Domain>>,
    pub _h: PhantomData<H>,
}

impl<H: Hasher> LabelsCache<H> {
    pub fn from_stores(labels: Vec<DiskStore<H::Domain>>) -> Self {
        LabelsCache {
            labels,
            _h: PhantomData,
        }
    }

    pub fn new(labels: &Labels<H>) -> Self {
        let mut disk_store_labels: Vec<DiskStore<H::Domain>> = Vec::with_capacity(labels.len());
        for i in 0..labels.len() {
            disk_store_labels.push(labels.labels_for_layer(i + 1));
        }

        LabelsCache {
            labels: disk_store_labels,
            _h: PhantomData,
        }
    }

    pub fn len(&self) -> usize {
        self.labels.len()
    }

    pub fn labels_for_layer(&self, layer: usize) -> &DiskStore<H::Domain> {
        assert!(layer != 0, "Layer cannot be 0");
        assert!(
            layer <= self.layers(),
            "Layer {} is not available (only {} layers available)",
            layer,
            self.layers()
        );

        let row_index = layer - 1;
        &self.labels[row_index]
    }

    /// Returns the labels on the last layer.
    pub fn labels_for_last_layer(&self) -> &DiskStore<H::Domain> {
        &self.labels[self.labels.len() - 1]
    }

    /// How many layers are available.
    fn layers(&self) -> usize {
        self.labels.len()
    }

    /// Build the column for the given node.
    pub fn column(&self, node: u32) -> Result<Column<H>> {
        let rows = self
            .labels
            .iter()
            .map(|labels| labels.read_at(node as usize))
            .collect();

        Ok(Column::new(node, rows))
    }
}

pub fn get_node<H: Hasher>(data: &[u8], index: usize) -> Result<H::Domain> {
    H::Domain::try_from_bytes(data_at_node(data, index).expect("invalid node math"))
}

/// Generate the replica id as expected for Stacked DRG.
pub fn generate_replica_id<H: Hasher, T: AsRef<[u8]>>(
    prover_id: &[u8; 32],
    sector_id: u64,
    ticket: &[u8; 32],
    comm_d: T,
) -> H::Domain {
    use sha2::{Digest, Sha256};

    let hash = Sha256::new()
        .chain(prover_id)
        .chain(&sector_id.to_be_bytes()[..])
        .chain(ticket)
        .chain(AsRef::<[u8]>::as_ref(&comm_d))
        .result();

    bytes_into_fr_repr_safe(hash.as_ref()).into()
}
