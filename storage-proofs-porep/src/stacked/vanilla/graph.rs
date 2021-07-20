use std::convert::{TryFrom, TryInto};
use std::fmt::{self, Debug, Formatter};
use std::marker::PhantomData;

use anyhow::ensure;
use filecoin_hashers::Hasher;
use log::info;
use sha2raw::Sha256;
use storage_proofs_core::{
    api_version::ApiVersion,
    crypto::{
        derive_porep_domain_seed,
        feistel::{self, FeistelPrecomputed},
        FEISTEL_DST,
    },
    drgraph::{BucketGraph, Graph, BASE_DEGREE},
    error::Result,
    parameter_cache::ParameterSetMetadata,
    settings::SETTINGS,
    util::NODE_SIZE,
    PoRepID,
};

use crate::stacked::vanilla::cache::ParentCache;

/// The expansion degree used for Stacked Graphs.
pub const EXP_DEGREE: usize = 8;

pub(crate) const DEGREE: usize = BASE_DEGREE + EXP_DEGREE;

#[derive(Clone)]
pub struct StackedGraph<H, G>
where
    H: Hasher,
    G: Graph<H> + 'static,
{
    expansion_degree: usize,
    base_graph: G,
    pub(crate) feistel_keys: [feistel::Index; 4],
    feistel_precomputed: FeistelPrecomputed,
    api_version: ApiVersion,
    id: String,
    _h: PhantomData<H>,
}

impl<H, G> Debug for StackedGraph<H, G>
where
    H: Hasher,
    G: Graph<H> + 'static,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("StackedGraph")
            .field("expansion_degree", &self.expansion_degree)
            .field("base_graph", &self.base_graph)
            .field("feistel_precomputed", &self.feistel_precomputed)
            .field("id", &self.id)
            .finish()
    }
}

pub type StackedBucketGraph<H> = StackedGraph<H, BucketGraph<H>>;

#[inline]
fn prefetch(parents: &[u32], data: &[u8]) {
    for parent in parents {
        let start = *parent as usize * NODE_SIZE;
        let end = start + NODE_SIZE;

        prefetch!(data[start..end].as_ptr() as *const i8);
    }
}

#[inline]
fn read_node<'a>(i: usize, parents: &[u32], data: &'a [u8]) -> &'a [u8] {
    let start = parents[i] as usize * NODE_SIZE;
    let end = start + NODE_SIZE;
    &data[start..end]
}

pub fn derive_feistel_keys(porep_id: PoRepID) -> [u64; 4] {
    let mut feistel_keys = [0u64; 4];
    let raw_seed = derive_porep_domain_seed(FEISTEL_DST, porep_id);
    feistel_keys[0] = u64::from_le_bytes(raw_seed[0..8].try_into().expect("from_le_bytes failure"));
    feistel_keys[1] =
        u64::from_le_bytes(raw_seed[8..16].try_into().expect("from_le_bytes failure"));
    feistel_keys[2] =
        u64::from_le_bytes(raw_seed[16..24].try_into().expect("from_le_bytes failure"));
    feistel_keys[3] =
        u64::from_le_bytes(raw_seed[24..32].try_into().expect("from_le_bytes failure"));
    feistel_keys
}

impl<H, G> StackedGraph<H, G>
where
    H: Hasher,
    G: Graph<H> + ParameterSetMetadata + Sync + Send,
{
    pub fn new(
        base_graph: Option<G>,
        nodes: usize,
        base_degree: usize,
        expansion_degree: usize,
        porep_id: PoRepID,
        api_version: ApiVersion,
    ) -> Result<Self> {
        assert_eq!(base_degree, BASE_DEGREE);
        assert_eq!(expansion_degree, EXP_DEGREE);
        ensure!(nodes <= u32::MAX as usize, "too many nodes");

        let base_graph = match base_graph {
            Some(graph) => graph,
            None => G::new(nodes, base_degree, 0, porep_id, api_version)?,
        };

        let bg_id = base_graph.identifier();

        let feistel_keys = derive_feistel_keys(porep_id);

        let res = StackedGraph {
            base_graph,
            id: format!(
                "stacked_graph::StackedGraph{{expansion_degree: {} base_graph: {} }}",
                expansion_degree, bg_id,
            ),
            expansion_degree,
            feistel_keys,
            feistel_precomputed: feistel::precompute((expansion_degree * nodes) as feistel::Index),
            api_version,
            _h: PhantomData,
        };

        Ok(res)
    }

    /// Returns a reference to the parent cache.
    pub fn parent_cache(&self) -> Result<ParentCache> {
        // Number of nodes to be cached in memory
        let default_cache_size = SETTINGS.sdr_parents_cache_size;
        let cache_entries = self.size() as u32;
        let cache_size = cache_entries.min(default_cache_size);

        info!("using parent_cache[{} / {}]", cache_size, cache_entries);

        ParentCache::new(cache_size, cache_entries, self)
    }

    pub fn api_version(&self) -> ApiVersion {
        self.api_version
    }

    pub fn copy_parents_data_exp(
        &self,
        node: u32,
        base_data: &[u8],
        exp_data: &[u8],
        hasher: Sha256,
        mut cache: Option<&mut ParentCache>,
    ) -> Result<[u8; 32]> {
        if let Some(ref mut cache) = cache {
            let cache_parents = cache.read(node as u32)?;
            Ok(self.copy_parents_data_inner_exp(&cache_parents, base_data, exp_data, hasher))
        } else {
            let mut cache_parents = [0u32; DEGREE];

            self.parents(node as usize, &mut cache_parents[..])
                .expect("parents failure");
            Ok(self.copy_parents_data_inner_exp(&cache_parents, base_data, exp_data, hasher))
        }
    }

    pub fn copy_parents_data(
        &self,
        node: u32,
        base_data: &[u8],
        hasher: Sha256,
        mut cache: Option<&mut ParentCache>,
    ) -> Result<[u8; 32]> {
        if let Some(ref mut cache) = cache {
            let cache_parents = cache.read(node as u32)?;
            Ok(self.copy_parents_data_inner(&cache_parents, base_data, hasher))
        } else {
            let mut cache_parents = [0u32; DEGREE];

            self.parents(node as usize, &mut cache_parents[..])
                .expect("parents failure");
            Ok(self.copy_parents_data_inner(&cache_parents, base_data, hasher))
        }
    }

    fn copy_parents_data_inner_exp(
        &self,
        cache_parents: &[u32],
        base_data: &[u8],
        exp_data: &[u8],
        mut hasher: Sha256,
    ) -> [u8; 32] {
        prefetch(&cache_parents[..BASE_DEGREE], base_data);
        prefetch(&cache_parents[BASE_DEGREE..], exp_data);

        // fill buffer
        let parents = [
            read_node(0, cache_parents, base_data),
            read_node(1, cache_parents, base_data),
            read_node(2, cache_parents, base_data),
            read_node(3, cache_parents, base_data),
            read_node(4, cache_parents, base_data),
            read_node(5, cache_parents, base_data),
            read_node(6, cache_parents, exp_data),
            read_node(7, cache_parents, exp_data),
            read_node(8, cache_parents, exp_data),
            read_node(9, cache_parents, exp_data),
            read_node(10, cache_parents, exp_data),
            read_node(11, cache_parents, exp_data),
            read_node(12, cache_parents, exp_data),
            read_node(13, cache_parents, exp_data),
        ];

        // round 1 (14)
        hasher.input(&parents);

        // round 2 (14)
        hasher.input(&parents);

        // round 3 (9)
        hasher.input(&parents[..8]);
        hasher.finish_with(&parents[8])
    }

    fn copy_parents_data_inner(
        &self,
        cache_parents: &[u32],
        base_data: &[u8],
        mut hasher: Sha256,
    ) -> [u8; 32] {
        prefetch(&cache_parents[..BASE_DEGREE], base_data);

        // fill buffer
        let parents = [
            read_node(0, cache_parents, base_data),
            read_node(1, cache_parents, base_data),
            read_node(2, cache_parents, base_data),
            read_node(3, cache_parents, base_data),
            read_node(4, cache_parents, base_data),
            read_node(5, cache_parents, base_data),
        ];

        // round 1 (0..6)
        hasher.input(&parents);

        // round 2 (6..12)
        hasher.input(&parents);

        // round 3 (12..18)
        hasher.input(&parents);

        // round 4 (18..24)
        hasher.input(&parents);

        // round 5 (24..30)
        hasher.input(&parents);

        // round 6 (30..36)
        hasher.input(&parents);

        // round 7 (37)
        hasher.finish_with(parents[0])
    }
}

impl<H, G> ParameterSetMetadata for StackedGraph<H, G>
where
    H: Hasher,
    G: Graph<H> + ParameterSetMetadata,
{
    fn identifier(&self) -> String {
        self.id.clone()
    }

    fn sector_size(&self) -> u64 {
        self.base_graph.sector_size()
    }
}

impl<H, G> Graph<H> for StackedGraph<H, G>
where
    H: Hasher,
    G: Graph<H> + ParameterSetMetadata + Sync + Send,
{
    type Key = Vec<u8>;

    fn size(&self) -> usize {
        self.base_graph().size()
    }

    fn degree(&self) -> usize {
        self.base_graph.degree() + self.expansion_degree
    }

    #[inline]
    fn parents(&self, node: usize, parents: &mut [u32]) -> Result<()> {
        self.base_parents(node, &mut parents[..self.base_graph().degree()])?;

        // expanded_parents takes raw_node
        self.expanded_parents(
            node,
            &mut parents
                [self.base_graph().degree()..self.base_graph().degree() + self.expansion_degree()],
        )?;

        Ok(())
    }

    fn seed(&self) -> [u8; 28] {
        self.base_graph().seed()
    }

    fn new(
        nodes: usize,
        base_degree: usize,
        expansion_degree: usize,
        porep_id: PoRepID,
        api_version: ApiVersion,
    ) -> Result<Self> {
        Self::new_stacked(nodes, base_degree, expansion_degree, porep_id, api_version)
    }

    fn create_key(
        &self,
        _id: &H::Domain,
        _node: usize,
        _parents: &[u32],
        _base_parents_data: &[u8],
        _exp_parents_data: Option<&[u8]>,
    ) -> Result<Self::Key> {
        unimplemented!("not used");
    }
}

impl<'a, H, G> StackedGraph<H, G>
where
    H: Hasher,
    G: Graph<H> + ParameterSetMetadata + Sync + Send,
{
    /// Assign one parent to `node` using a Chung's construction with a reversible
    /// permutation function from a Feistel cipher (controlled by `invert_permutation`).
    fn correspondent(&self, node: usize, i: usize) -> u32 {
        // We can't just generate random values between `[0, size())`, we need to
        // expand the search space (domain) to accommodate every unique parent assignment
        // generated here. This can be visualized more clearly as a matrix where the each
        // new parent of each new node is assigned a unique `index`:
        //
        //
        //          | Parent 1 | Parent 2 | Parent 3 |
        //
        // | Node 1 |     0    |     1    |     2    |
        //
        // | Node 2 |     3    |     4    |     5    |
        //
        // | Node 3 |     6    |     7    |     8    |
        //
        // | Node 4 |     9    |     A    |     B    |
        //
        // This starting `index` will be shuffled to another position to generate a
        // parent-child relationship, e.g., if generating the parents for the second node,
        // `permute` would be called with values `[3; 4; 5]` that would be mapped to other
        // indexes in the search space of `[0, B]`, say, values `[A; 0; 4]`, that would
        // correspond to nodes numbered `[4; 1, 2]` which will become the parents of the
        // second node. In a later pass invalid parents like 2, self-referencing, and parents
        // with indexes bigger than 2 (if in the `forward` direction, smaller than 2 if the
        // inverse), will be removed.
        let a = (node * self.expansion_degree) as feistel::Index + i as feistel::Index;

        let transformed = feistel::permute(
            self.size() as feistel::Index * self.expansion_degree as feistel::Index,
            a,
            &self.feistel_keys,
            self.feistel_precomputed,
        );

        match self.api_version {
            ApiVersion::V1_0_0 => transformed as u32 / self.expansion_degree as u32,
            ApiVersion::V1_1_0 => u32::try_from(transformed as u64 / self.expansion_degree as u64)
                .expect("invalid transformation"),
        }

        // Collapse the output in the matrix search space to the row of the corresponding
        // node (losing the column information, that will be regenerated later when calling
        // back this function in the `reversed` direction).
    }

    pub fn generate_expanded_parents(&self, node: usize, expanded_parents: &mut [u32]) {
        debug_assert_eq!(expanded_parents.len(), self.expansion_degree);
        for (i, el) in expanded_parents.iter_mut().enumerate() {
            *el = self.correspondent(node, i);
        }
    }

    pub fn new_stacked(
        nodes: usize,
        base_degree: usize,
        expansion_degree: usize,
        porep_id: PoRepID,
        api_version: ApiVersion,
    ) -> Result<Self> {
        Self::new(
            None,
            nodes,
            base_degree,
            expansion_degree,
            porep_id,
            api_version,
        )
    }

    pub fn base_graph(&self) -> &G {
        &self.base_graph
    }

    pub fn expansion_degree(&self) -> usize {
        self.expansion_degree
    }

    pub fn base_parents(&self, node: usize, parents: &mut [u32]) -> Result<()> {
        // No cache usage, generate on demand.
        self.base_graph().parents(node, parents)
    }

    /// Assign `self.expansion_degree` parents to `node` using an invertible permutation
    /// that is applied one way for the forward layers and one way for the reversed
    /// ones.
    #[inline]
    pub fn expanded_parents(&self, node: usize, parents: &mut [u32]) -> Result<()> {
        // No cache usage, generate on demand.
        self.generate_expanded_parents(node, parents);
        Ok(())
    }
}

impl<H, G> PartialEq for StackedGraph<H, G>
where
    H: Hasher,
    G: Graph<H>,
{
    fn eq(&self, other: &StackedGraph<H, G>) -> bool {
        self.base_graph == other.base_graph && self.expansion_degree == other.expansion_degree
    }
}

impl<H, G> Eq for StackedGraph<H, G>
where
    H: Hasher,
    G: Graph<H>,
{
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::HashSet;

    use filecoin_hashers::poseidon::PoseidonHasher;

    // Test that 3 (or more) rounds of the Feistel cipher can be used
    // as a pseudorandom permutation, that is, each input will be mapped
    // to a unique output (and though not test here, since the cipher
    // is symmetric, the decryption rounds also work as the inverse
    // permutation), for more details see:
    // https://en.wikipedia.org/wiki/Feistel_cipher#Theoretical_work.
    #[test]
    fn test_shuffle() {
        let n = 2_u64.pow(10);
        let d = EXP_DEGREE as u64;
        // Use a relatively small value of `n` as Feistel is expensive (but big
        // enough that `n >> d`).

        let mut shuffled: HashSet<u64> = HashSet::with_capacity((n * d) as usize);

        let feistel_keys = &[1, 2, 3, 4];
        let feistel_precomputed = feistel::precompute((n * d) as feistel::Index);

        for i in 0..n {
            for k in 0..d {
                let permuted =
                    feistel::permute(n * d, i * d + k, feistel_keys, feistel_precomputed);

                // Since the permutation implies a one-to-one correspondence,
                // traversing the entire input space should generate the entire
                // output space (in `shuffled`) without repetitions (since a duplicate
                // output would imply there is another output that wasn't generated
                // and the permutation would be incomplete).
                assert!(shuffled.insert(permuted));
            }
        }

        // Actually implied by the previous `assert!` this is left in place as an
        // extra safety check that indeed the permutation preserved all the output
        // space (of `n * d` nodes) without repetitions (which the `HashSet` would
        // have skipped as duplicates).
        assert_eq!(shuffled.len(), (n * d) as usize);
    }

    #[test]
    /// The initial implementation had a bug which prevented parents from ever falling in the later half of a sector.
    /// In fact, it is even worse than that, in the case of 64GiB sectors.
    /// This test demonstrates conclusively that non-legacy graphs do not suffer from this pathology.
    /// It also suggests, inconclusively, that legacy graphds do suffer from it (which we already know).
    fn test_graph_distribution_pathology() {
        let sector32_nodes: u32 = 1 << 30;
        let sector64_nodes: u32 = 1 << 31;

        let porep_id = |id: u8| {
            let mut porep_id = [0u8; 32];
            porep_id[0] = id;

            porep_id
        };

        test_pathology_aux(porep_id(3), sector32_nodes, ApiVersion::V1_0_0);
        test_pathology_aux(porep_id(4), sector64_nodes, ApiVersion::V1_0_0);

        test_pathology_aux(porep_id(8), sector32_nodes, ApiVersion::V1_1_0);
        test_pathology_aux(porep_id(9), sector64_nodes, ApiVersion::V1_1_0);
    }

    fn test_pathology_aux(porep_id: PoRepID, nodes: u32, api_version: ApiVersion) {
        // In point of fact, the concrete graphs expected to be non-pathological
        // appear to demonstrate this immediately (i.e. in the first node). We
        // test more than that just to make the tentative diagnosis of pathology
        // more convincing in the cases where we expect it. In the interest of
        // keeping the tests brief, we keep this fairly small, though, since we
        // already know the previous porep_ids exhibit the problem. The main
        // reason to test those cases at all is to convince ourselves the test
        // is sound.
        let test_n = 1_000;

        let expect_pathological = match api_version {
            ApiVersion::V1_0_0 => true,
            ApiVersion::V1_1_0 => false,
        };

        let graph = StackedBucketGraph::<PoseidonHasher>::new_stacked(
            nodes as usize,
            BASE_DEGREE,
            EXP_DEGREE,
            porep_id,
            api_version,
        )
        .expect("stacked bucket graph new_stacked failed");

        // If a parent index is not less than half the total node count, then
        // the parent falls in the second half of the previous layer. By the
        // definition of 'pathology' used here, that means the graph producing
        // this parent is not pathological.
        let demonstrably_large_enough = |p: &u32| *p >= (nodes / 2);

        dbg!(&porep_id, &nodes, &expect_pathological);
        for i in 0..test_n {
            let mut expanded_parents = [0u32; EXP_DEGREE];
            graph
                .expanded_parents(i, &mut expanded_parents)
                .expect("expanded_parents");

            if expect_pathological {
                // If we ever see a large-enough parent, then this graph is not
                // pathological, so the test fails.
                assert!(
                    !expanded_parents.iter().any(demonstrably_large_enough),
                    "Expected pathological graph but found large-enough parent."
                );
            } else if expanded_parents.iter().any(demonstrably_large_enough) {
                // If we ever see a large-enough parent, then this graph is
                // not pathological, and the test succeeds. This is the only
                // way for a test expecting a non-pathological graph to
                // succeed, so there is no risk of false negatives (i.e.
                // failure to identify pathological graphs when unexpected).
                return;
            }
        }

        // If we get here, we did not observe a parent large enough to conclude
        // that the graph is not pathological. In that case, the test fails if we
        // expected a non-pathological graph and succeeds otherwise. NOTE: this
        // could lead us to conclude that an actually non-pathological graph is
        // pathological, if `test_n` is set too low. Since the primary purpose
        // of this test is to assure us that newer graphs are not pathological,
        // it suffices to set `test_n` high enough to detect that.
        assert!(expect_pathological, "Did not expect pathological graph, but did not see large-enough parent to prove otherwise.");
    }

    // Tests that the set of expander edges has not been truncated.
    #[test]
    fn test_high_parent_bits() {
        // 64GiB sectors have 2^31 nodes.
        const N_NODES: usize = 1 << 31;

        // `u32` truncation would reduce the expander edge bit-length from 34 bits to 32 bits, thus
        // the first parent truncated would be the node at index `2^32 / EXP_DEGREE = 2^29`.
        const FIRST_TRUNCATED_PARENT: u32 = 1 << 29;

        // The number of child nodes to test before failing. This value was chosen arbitrarily and
        // can be changed.
        const N_CHILDREN_SAMPLED: usize = 3;

        // Non-legacy porep-id.
        let mut porep_id = [0u8; 32];
        porep_id[..8].copy_from_slice(&5u64.to_le_bytes());

        let graph = StackedBucketGraph::<PoseidonHasher>::new_stacked(
            N_NODES,
            BASE_DEGREE,
            EXP_DEGREE,
            porep_id,
            ApiVersion::V1_1_0,
        )
        .expect("stacked bucket graph new_stacked");

        let mut exp_parents = [0u32; EXP_DEGREE];
        for v in 0..N_CHILDREN_SAMPLED {
            graph
                .expanded_parents(v, &mut exp_parents[..])
                .expect("expanded_parents");
            if exp_parents.iter().any(|u| *u >= FIRST_TRUNCATED_PARENT) {
                return;
            }
        }
        panic!();
    }

    // Checks that the distribution of parent node indexes within a sector is within a set bound.
    #[test]
    fn test_exp_parent_histogram() {
        // 64GiB sectors have 2^31 nodes.
        const N_NODES: usize = 1 << 31;

        // The number of children used to construct the histogram. This value is chosen
        // arbitrarily and can be changed.
        const N_CHILDREN_SAMPLED: usize = 10000;

        // The number of bins used to partition the set of sector nodes. This value was chosen
        // arbitrarily and can be changed to any integer that is a multiple of `EXP_DEGREE` and
        // evenly divides `N_NODES`.
        const N_BINS: usize = 32;
        const N_NODES_PER_BIN: u32 = (N_NODES / N_BINS) as u32;
        const PARENT_COUNT_PER_BIN_UNIFORM: usize = N_CHILDREN_SAMPLED * EXP_DEGREE / N_BINS;

        // This test will pass if every bin's parent count is within the bounds:
        // `(1 +/- FAILURE_THRESHOLD) * PARENT_COUNT_PER_BIN_UNIFORM`.
        const FAILURE_THRESHOLD: f32 = 0.4;
        const MAX_PARENT_COUNT_ALLOWED: usize =
            ((1.0 + FAILURE_THRESHOLD) * PARENT_COUNT_PER_BIN_UNIFORM as f32) as usize - 1;
        const MIN_PARENT_COUNT_ALLOWED: usize =
            ((1.0 - FAILURE_THRESHOLD) * PARENT_COUNT_PER_BIN_UNIFORM as f32) as usize + 1;

        // Non-legacy porep-id.
        let mut porep_id = [0u8; 32];
        porep_id[..8].copy_from_slice(&5u64.to_le_bytes());

        let graph = StackedBucketGraph::<PoseidonHasher>::new_stacked(
            N_NODES,
            BASE_DEGREE,
            EXP_DEGREE,
            porep_id,
            ApiVersion::V1_1_0,
        )
        .expect("stacked bucket graph new_stacked failed");

        // Count the number of parents in each bin.
        let mut hist = [0usize; N_BINS];
        let mut exp_parents = [0u32; EXP_DEGREE];
        for sample_index in 0..N_CHILDREN_SAMPLED {
            let v = sample_index * N_NODES / N_CHILDREN_SAMPLED;
            graph
                .expanded_parents(v, &mut exp_parents[..])
                .expect("expanded_parents failed");
            for u in exp_parents.iter() {
                let bin_index = (u / N_NODES_PER_BIN) as usize;
                hist[bin_index] += 1;
            }
        }

        let success = hist.iter().all(|&n_parents| {
            (MIN_PARENT_COUNT_ALLOWED..=MAX_PARENT_COUNT_ALLOWED).contains(&n_parents)
        });

        assert!(success);
    }
}
