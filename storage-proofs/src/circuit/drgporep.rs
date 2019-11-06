use std::marker::PhantomData;

use bellperson::gadgets::boolean::Boolean;
use bellperson::gadgets::num;
use bellperson::{Circuit, ConstraintSystem, SynthesisError};
use fil_sapling_crypto::jubjub::JubjubEngine;
use paired::bls12_381::{Bls12, Fr};

use crate::circuit::constraint;
use crate::circuit::create_label::create_label as kdf;
use crate::circuit::encode;
use crate::circuit::por::{PoRCircuit, PoRCompound};
use crate::circuit::variables::Root;
use crate::compound_proof::{CircuitComponent, CompoundProof};
use crate::crypto::pedersen::JJ_PARAMS;
use crate::drgporep::DrgPoRep;
use crate::drgraph::Graph;
use crate::fr32::fr_into_bytes;
use crate::hasher::Hasher;
use crate::merklepor;
use crate::parameter_cache::{CacheableParameters, ParameterSetMetadata};
use crate::proof::ProofScheme;
use crate::util::bytes_into_boolean_vec_be;

/// DRG based Proof of Replication.
///
/// # Fields
///
/// * `params` - parameters for the curve
///
/// ----> Private `replica_node` - The replica node being proven.
///
/// * `replica_node` - The replica node being proven.
/// * `replica_node_path` - The path of the replica node being proven.
/// * `replica_root` - The merkle root of the replica.
///
/// * `replica_parents` - A list of all parents in the replica, with their value.
/// * `replica_parents_paths` - A list of all parents paths in the replica.
///
/// ----> Private `data_node` - The data node being proven.
///
/// * `data_node_path` - The path of the data node being proven.
/// * `data_root` - The merkle root of the data.
/// * `replica_id` - The id of the replica.
///
//implement_drgporep!(
//    DrgPoRepCircuit,
//    DrgPoRepCompound,
//    "drg-proof-of-replication",
//    false
//);

pub struct DrgPoRepCircuit<'a, H: Hasher> {
    params: &'a <Bls12 as JubjubEngine>::Params,
    replica_nodes: Vec<Option<Fr>>,
    #[allow(clippy::type_complexity)]
    replica_nodes_paths: Vec<Vec<Option<(Fr, bool)>>>,
    replica_root: Root<Bls12>,
    replica_parents: Vec<Vec<Option<Fr>>>,
    #[allow(clippy::type_complexity)]
    replica_parents_paths: Vec<Vec<Vec<Option<(Fr, bool)>>>>,
    data_nodes: Vec<Option<Fr>>,
    #[allow(clippy::type_complexity)]
    data_nodes_paths: Vec<Vec<Option<(Fr, bool)>>>,
    data_root: Root<Bls12>,
    replica_id: Option<Fr>,
    private: bool,
    _h: PhantomData<H>,
}

impl<'a, H: Hasher> DrgPoRepCircuit<'a, H> {
    #[allow(clippy::type_complexity, clippy::too_many_arguments)]
    pub fn synthesize<CS>(
        mut cs: CS,
        replica_nodes: Vec<Option<Fr>>,
        replica_nodes_paths: Vec<Vec<Option<(Fr, bool)>>>,
        replica_root: Root<Bls12>,
        replica_parents: Vec<Vec<Option<Fr>>>,
        replica_parents_paths: Vec<Vec<Vec<Option<(Fr, bool)>>>>,
        data_nodes: Vec<Option<Fr>>,
        data_nodes_paths: Vec<Vec<Option<(Fr, bool)>>>,
        data_root: Root<Bls12>,
        replica_id: Option<Fr>,
        private: bool,
    ) -> Result<(), SynthesisError>
    where
        CS: ConstraintSystem<Bls12>,
    {
        DrgPoRepCircuit::<H> {
            params: &*JJ_PARAMS,
            replica_nodes,
            replica_nodes_paths,
            replica_root,
            replica_parents,
            replica_parents_paths,
            data_nodes,
            data_nodes_paths,
            data_root,
            replica_id,
            private,
            _h: Default::default(),
        }
        .synthesize(&mut cs)
    }
}

#[derive(Default, Clone)]
pub struct ComponentPrivateInputs {
    pub comm_r: Option<Root<Bls12>>,
    pub comm_d: Option<Root<Bls12>>,
}

impl<'a, H: Hasher> CircuitComponent for DrgPoRepCircuit<'a, H> {
    type ComponentPrivateInputs = ComponentPrivateInputs;
}

pub struct DrgPoRepCompound<H, G>
where
    H: Hasher,
    G::Key: AsRef<H::Domain>,
    G: Graph<H>,
{
    // Sad phantom is sad
    _h: PhantomData<H>,
    _g: PhantomData<G>,
}

impl<E: JubjubEngine, C: Circuit<E>, H: Hasher, G: Graph<H>, P: ParameterSetMetadata>
    CacheableParameters<E, C, P> for DrgPoRepCompound<H, G>
where
    G::Key: AsRef<H::Domain>,
{
    fn cache_prefix() -> String {
        format!("drg-proof-of-replication-{}", H::name())
    }
}

impl<'a, H, G> CompoundProof<'a, Bls12, DrgPoRep<'a, H, G>, DrgPoRepCircuit<'a, H>>
    for DrgPoRepCompound<H, G>
where
    H: 'a + Hasher,
    G::Key: AsRef<H::Domain>,
    G: 'a + Graph<H> + ParameterSetMetadata + Sync + Send,
{
    fn generate_public_inputs(
        pub_in: &<DrgPoRep<'a, H, G> as ProofScheme<'a>>::PublicInputs,
        pub_params: &<DrgPoRep<'a, H, G> as ProofScheme<'a>>::PublicParams,
        // We can ignore k because challenges are generated by caller and included
        // in PublicInputs.
        _k: Option<usize>,
    ) -> Vec<Fr> {
        let replica_id = pub_in.replica_id.expect("missing replica id");
        let challenges = &pub_in.challenges;

        assert_eq!(pub_in.tau.is_none(), pub_params.private);

        let (comm_r, comm_d) = match pub_in.tau {
            None => (None, None),
            Some(tau) => (Some(tau.comm_r), Some(tau.comm_d)),
        };

        let leaves = pub_params.graph.size();

        let por_pub_params = merklepor::PublicParams {
            leaves,
            private: pub_params.private,
        };

        let mut input: Vec<Fr> = Vec::new();
        input.push(replica_id.into());

        let mut parents = vec![0; pub_params.graph.degree()];
        for challenge in challenges {
            let mut por_nodes = vec![*challenge as u32];
            pub_params.graph.parents(*challenge, &mut parents);
            por_nodes.extend_from_slice(&parents);

            for node in por_nodes {
                let por_pub_inputs = merklepor::PublicInputs {
                    commitment: comm_r,
                    challenge: node as usize,
                };
                let por_inputs = PoRCompound::<H>::generate_public_inputs(
                    &por_pub_inputs,
                    &por_pub_params,
                    None,
                );

                input.extend(por_inputs);
            }

            let por_pub_inputs = merklepor::PublicInputs {
                commitment: comm_d,
                challenge: *challenge,
            };

            let por_inputs =
                PoRCompound::<H>::generate_public_inputs(&por_pub_inputs, &por_pub_params, None);
            input.extend(por_inputs);
        }
        input
    }

    fn circuit(
        public_inputs: &<DrgPoRep<'a, H, G> as ProofScheme<'a>>::PublicInputs,
        component_private_inputs: <DrgPoRepCircuit<'a, H> as CircuitComponent>::ComponentPrivateInputs,
        proof: &<DrgPoRep<'a, H, G> as ProofScheme<'a>>::Proof,
        public_params: &<DrgPoRep<'a, H, G> as ProofScheme<'a>>::PublicParams,
    ) -> DrgPoRepCircuit<'a, H> {
        let challenges = public_params.challenges_count;
        let len = proof.nodes.len();

        assert!(len <= challenges, "too many challenges");
        assert_eq!(proof.replica_parents.len(), len);
        assert_eq!(proof.replica_nodes.len(), len);

        let replica_nodes: Vec<_> = proof
            .replica_nodes
            .iter()
            .map(|node| Some(node.data.into()))
            .collect();

        let replica_nodes_paths: Vec<_> = proof
            .replica_nodes
            .iter()
            .map(|node| node.proof.as_options())
            .collect();

        let is_private = public_params.private;

        let (data_root, replica_root) = if is_private {
            (
                component_private_inputs.comm_d.expect("is_private"),
                component_private_inputs.comm_r.expect("is_private"),
            )
        } else {
            (
                Root::Val(Some(proof.data_root.into())),
                Root::Val(Some(proof.replica_root.into())),
            )
        };

        let replica_id = public_inputs.replica_id;

        let replica_parents: Vec<_> = proof
            .replica_parents
            .iter()
            .map(|parents| {
                parents
                    .iter()
                    .map(|(_, parent)| Some(parent.data.into()))
                    .collect()
            })
            .collect();

        let replica_parents_paths: Vec<Vec<_>> = proof
            .replica_parents
            .iter()
            .map(|parents| {
                let p: Vec<_> = parents
                    .iter()
                    .map(|(_, parent)| parent.proof.as_options())
                    .collect();
                p
            })
            .collect();

        let data_nodes: Vec<_> = proof
            .nodes
            .iter()
            .map(|node| Some(node.data.into()))
            .collect();

        let data_nodes_paths: Vec<_> = proof
            .nodes
            .iter()
            .map(|node| node.proof.as_options())
            .collect();

        assert_eq!(
            public_inputs.tau.is_none(),
            public_params.private,
            "inconsistent private state"
        );

        DrgPoRepCircuit {
            params: &*JJ_PARAMS,
            replica_nodes,
            replica_nodes_paths,
            replica_root,
            replica_parents,
            replica_parents_paths,
            data_nodes,
            data_nodes_paths,
            data_root,
            replica_id: replica_id.map(Into::into),
            private: public_params.private,
            _h: Default::default(),
        }
    }

    fn blank_circuit(
        public_params: &<DrgPoRep<'a, H, G> as ProofScheme<'a>>::PublicParams,
    ) -> DrgPoRepCircuit<'a, H> {
        let depth = public_params.graph.merkle_tree_depth() as usize;
        let degree = public_params.graph.degree();
        let challenges_count = public_params.challenges_count;

        let replica_nodes = vec![None; challenges_count];
        let replica_nodes_paths = vec![vec![None; depth]; challenges_count];

        let replica_root = Root::Val(None);
        let replica_parents = vec![vec![None; degree]; challenges_count];
        let replica_parents_paths = vec![vec![vec![None; depth]; degree]; challenges_count];
        let data_nodes = vec![None; challenges_count];
        let data_nodes_paths = vec![vec![None; depth]; challenges_count];
        let data_root = Root::Val(None);

        DrgPoRepCircuit {
            params: &*JJ_PARAMS,
            replica_nodes,
            replica_nodes_paths,
            replica_root,
            replica_parents,
            replica_parents_paths,
            data_nodes,
            data_nodes_paths,
            data_root,
            replica_id: None,
            private: public_params.private,
            _h: Default::default(),
        }
    }
}

///
/// # Public Inputs
///
/// * [0] replica_id/0
/// * [1] replica_id/1
/// * [2] replica auth_path_bits
/// * [3] replica commitment (root hash)
/// * for i in 0..replica_parents.len()
///   * [ ] replica parent auth_path_bits
///   * [ ] replica parent commitment (root hash) // Same for all.
/// * [r + 1] data auth_path_bits
/// * [r + 2] data commitment (root hash)
///
///  Total = 6 + (2 * replica_parents.len())
/// # Private Inputs
///
/// * [ ] replica value/0
/// * for i in 0..replica_parents.len()
///  * [ ] replica parent value/0
/// * [ ] data value/
///
/// Total = 2 + replica_parents.len()
///
impl<'a, H: Hasher> Circuit<Bls12> for DrgPoRepCircuit<'a, H> {
    fn synthesize<CS: ConstraintSystem<Bls12>>(self, cs: &mut CS) -> Result<(), SynthesisError> {
        let params = self.params;

        let replica_id = self.replica_id;
        let replica_root = self.replica_root;
        let data_root = self.data_root;

        let nodes = self.data_nodes.len();

        assert_eq!(self.replica_nodes.len(), nodes);
        assert_eq!(self.replica_nodes_paths.len(), nodes);
        assert_eq!(self.replica_parents.len(), nodes);
        assert_eq!(self.replica_parents_paths.len(), nodes);
        assert_eq!(self.data_nodes_paths.len(), nodes);

        // get the replica_id in bits
        let replica_id_bits = match replica_id {
            Some(id) => {
                let raw_bytes = fr_into_bytes::<Bls12>(&id);
                bytes_into_boolean_vec_be(cs.namespace(|| "replica_id_bits"), Some(&raw_bytes), 256)
            }
            None => bytes_into_boolean_vec_be(cs.namespace(|| "replica_id_bits"), None, 256),
        }?;

        let replica_node_num = num::AllocatedNum::alloc(cs.namespace(|| "replica_id_num"), || {
            replica_id.ok_or_else(|| SynthesisError::AssignmentMissing)
        })?;

        replica_node_num.inputize(cs.namespace(|| "replica_id"))?;

        let replica_root_var = Root::Var(replica_root.allocated(cs.namespace(|| "replica_root"))?);
        let data_root_var = Root::Var(data_root.allocated(cs.namespace(|| "data_root"))?);

        for i in 0..self.data_nodes.len() {
            let mut cs = cs.namespace(|| format!("challenge_{}", i));
            // ensure that all inputs are well formed
            let replica_node_path = &self.replica_nodes_paths[i];
            let replica_parents_paths = &self.replica_parents_paths[i];
            let data_node_path = &self.data_nodes_paths[i];

            let replica_node = &self.replica_nodes[i];
            let replica_parents = &self.replica_parents[i];
            let data_node = &self.data_nodes[i];

            assert_eq!(replica_parents.len(), replica_parents_paths.len());
            assert_eq!(data_node_path.len(), replica_node_path.len());
            assert_eq!(replica_node.is_some(), data_node.is_some());

            // Inclusion checks
            {
                let mut cs = cs.namespace(|| "inclusion_checks");
                PoRCircuit::<_, H>::synthesize(
                    cs.namespace(|| "replica_inclusion"),
                    &params,
                    Root::Val(*replica_node),
                    replica_node_path.clone(),
                    replica_root_var.clone(),
                    self.private,
                )?;

                // validate each replica_parents merkle proof
                for j in 0..replica_parents.len() {
                    PoRCircuit::<_, H>::synthesize(
                        cs.namespace(|| format!("parents_inclusion_{}", j)),
                        &params,
                        Root::Val(replica_parents[j]),
                        replica_parents_paths[j].clone(),
                        replica_root_var.clone(),
                        self.private,
                    )?;
                }

                // validate data node commitment
                PoRCircuit::<_, H>::synthesize(
                    cs.namespace(|| "data_inclusion"),
                    &params,
                    Root::Val(*data_node),
                    data_node_path.clone(),
                    data_root_var.clone(),
                    self.private,
                )?;
            }

            // Encoding checks
            {
                let mut cs = cs.namespace(|| "encoding_checks");
                // get the parents into bits
                let parents_bits: Vec<Vec<Boolean>> = replica_parents
                    .iter()
                    .enumerate()
                    .map(|(i, val)| match val {
                        Some(val) => {
                            let bytes = fr_into_bytes::<Bls12>(val);
                            bytes_into_boolean_vec_be(
                                cs.namespace(|| format!("parents_{}_bits", i)),
                                Some(&bytes),
                                256,
                            )
                        }
                        None => bytes_into_boolean_vec_be(
                            cs.namespace(|| format!("parents_{}_bits", i)),
                            None,
                            256,
                        ),
                    })
                    .collect::<Result<Vec<Vec<Boolean>>, SynthesisError>>()?;

                // generate the encryption key
                let key = kdf(cs.namespace(|| "kdf"), &replica_id_bits, parents_bits, None)?;

                let replica_node_num =
                    num::AllocatedNum::alloc(cs.namespace(|| "replica_node"), || {
                        (*replica_node).ok_or_else(|| SynthesisError::AssignmentMissing)
                    })?;

                let decoded = encode::decode(cs.namespace(|| "decode"), &key, &replica_node_num)?;

                // TODO this should not be here, instead, this should be the leaf Fr in the data_auth_path
                // TODO also note that we need to change/makesurethat the leaves are the data, instead of hashes of the data
                let expected = num::AllocatedNum::alloc(cs.namespace(|| "data node"), || {
                    data_node.ok_or_else(|| SynthesisError::AssignmentMissing)
                })?;

                // ensure the encrypted data and data_node match
                constraint::equal(&mut cs, || "equality", &expected, &decoded);
            }
        }
        // profit!
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::circuit::test::*;
    use crate::compound_proof;
    use crate::drgporep;
    use crate::drgraph::{graph_height, new_seed, BucketGraph, BASE_DEGREE};
    use crate::fr32::{bytes_into_fr, fr_into_bytes};
    use crate::hasher::{Blake2sHasher, Hasher, PedersenHasher};
    use crate::porep::PoRep;
    use crate::proof::{NoRequirements, ProofScheme};
    use crate::util::data_at_node;

    use ff::Field;
    use rand::SeedableRng;
    use rand_xorshift::XorShiftRng;

    #[test]
    fn drgporep_input_circuit_with_bls12_381() {
        let rng = &mut XorShiftRng::from_seed(crate::TEST_SEED);

        let nodes = 12;
        let degree = BASE_DEGREE;
        let challenge = 2;

        let replica_id: Fr = Fr::random(rng);

        let mut data: Vec<u8> = (0..nodes)
            .flat_map(|_| fr_into_bytes::<Bls12>(&Fr::random(rng)))
            .collect();

        // TODO: don't clone everything
        let original_data = data.clone();
        let data_node: Option<Fr> = Some(
            bytes_into_fr::<Bls12>(
                data_at_node(&original_data, challenge).expect("failed to read original data"),
            )
            .unwrap(),
        );

        let sp = drgporep::SetupParams {
            drg: drgporep::DrgParams {
                nodes,
                degree,
                expansion_degree: 0,
                seed: new_seed(),
            },
            private: false,
            challenges_count: 1,
        };

        // MT for original data is always named tree-d, and it will be
        // referenced later in the process as such.
        use merkletree::store::{StoreConfig, DEFAULT_CACHED_ABOVE_BASE_LAYER};
        let cache_dir = tempfile::tempdir().unwrap();
        let cache_path = cache_dir.as_ref().to_str().unwrap();
        let config = StoreConfig::new(
            cache_path.to_string(),
            "tree-d".to_string(),
            DEFAULT_CACHED_ABOVE_BASE_LAYER,
        );

        let pp = drgporep::DrgPoRep::<PedersenHasher, BucketGraph<_>>::setup(&sp)
            .expect("failed to create drgporep setup");
        let (tau, aux) = drgporep::DrgPoRep::<PedersenHasher, _>::replicate(
            &pp,
            &replica_id.into(),
            data.as_mut_slice(),
            None,
            Some(config),
        )
        .expect("failed to replicate");

        let pub_inputs = drgporep::PublicInputs {
            replica_id: Some(replica_id.into()),
            challenges: vec![challenge],
            tau: Some(tau.into()),
        };

        let priv_inputs = drgporep::PrivateInputs::<PedersenHasher> {
            tree_d: &aux.tree_d,
            tree_r: &aux.tree_r,
        };

        let proof_nc =
            drgporep::DrgPoRep::<PedersenHasher, _>::prove(&pp, &pub_inputs, &priv_inputs)
                .expect("failed to prove");

        assert!(
            drgporep::DrgPoRep::<PedersenHasher, _>::verify(&pp, &pub_inputs, &proof_nc)
                .expect("failed to verify"),
            "failed to verify (non circuit)"
        );

        let replica_node: Option<Fr> = Some(proof_nc.replica_nodes[0].data.into());

        let replica_node_path = proof_nc.replica_nodes[0].proof.as_options();
        let replica_root = Root::Val(Some(proof_nc.replica_root.into()));
        let replica_parents = proof_nc
            .replica_parents
            .iter()
            .map(|v| {
                v.iter()
                    .map(|(_, parent)| Some(parent.data.into()))
                    .collect()
            })
            .collect();
        let replica_parents_paths: Vec<_> = proof_nc
            .replica_parents
            .iter()
            .map(|v| {
                v.iter()
                    .map(|(_, parent)| parent.proof.as_options())
                    .collect()
            })
            .collect();

        let data_node_path = proof_nc.nodes[0].proof.as_options();
        let data_root = Root::Val(Some(proof_nc.data_root.into()));
        let replica_id = Some(replica_id);

        assert!(
            proof_nc.nodes[0].proof.validate(challenge),
            "failed to verify data commitment"
        );
        assert!(
            proof_nc.nodes[0]
                .proof
                .validate_data(&fr_into_bytes::<Bls12>(&data_node.unwrap())),
            "failed to verify data commitment with data"
        );

        let mut cs = TestConstraintSystem::<Bls12>::new();
        DrgPoRepCircuit::<PedersenHasher>::synthesize(
            cs.namespace(|| "drgporep"),
            vec![replica_node],
            vec![replica_node_path],
            replica_root,
            replica_parents,
            replica_parents_paths,
            vec![data_node],
            vec![data_node_path],
            data_root,
            replica_id,
            false,
        )
        .expect("failed to synthesize circuit");

        if !cs.is_satisfied() {
            println!(
                "failed to satisfy: {:?}",
                cs.which_is_unsatisfied().unwrap()
            );
        }

        assert!(cs.is_satisfied(), "constraints not satisfied");
        assert_eq!(cs.num_inputs(), 18, "wrong number of inputs");
        assert_eq!(cs.num_constraints(), 149607, "wrong number of constraints");

        assert_eq!(cs.get_input(0, "ONE"), Fr::one());

        assert_eq!(
            cs.get_input(1, "drgporep/replica_id/input variable"),
            replica_id.unwrap()
        );

        let generated_inputs =
            <DrgPoRepCompound<_, _> as CompoundProof<_, _, _>>::generate_public_inputs(
                &pub_inputs,
                &pp,
                None,
            );
        let expected_inputs = cs.get_inputs();

        for ((input, label), generated_input) in
            expected_inputs.iter().skip(1).zip(generated_inputs.iter())
        {
            assert_eq!(input, generated_input, "{}", label);
        }

        assert_eq!(
            generated_inputs.len(),
            expected_inputs.len() - 1,
            "inputs are not the same length"
        );
    }

    #[test]
    fn drgporep_input_circuit_num_constraints() {
        let rng = &mut XorShiftRng::from_seed(crate::TEST_SEED);

        // 1 GB
        let n = (1 << 30) / 32;
        let m = BASE_DEGREE;
        let tree_depth = graph_height(n);

        let mut cs = TestConstraintSystem::<Bls12>::new();
        DrgPoRepCircuit::<PedersenHasher>::synthesize(
            cs.namespace(|| "drgporep"),
            vec![Some(Fr::random(rng)); 1],
            vec![vec![Some((Fr::random(rng), false)); tree_depth]; 1],
            Root::Val(Some(Fr::random(rng))),
            vec![vec![Some(Fr::random(rng)); m]; 1],
            vec![vec![vec![Some((Fr::random(rng), false)); tree_depth]; m]; 1],
            vec![Some(Fr::random(rng)); 1],
            vec![vec![Some((Fr::random(rng), false)); tree_depth]; 1],
            Root::Val(Some(Fr::random(rng))),
            Some(Fr::random(rng)),
            false,
        )
        .expect("failed to synthesize circuit");

        assert_eq!(cs.num_inputs(), 18, "wrong number of inputs");
        assert_eq!(cs.num_constraints(), 380439, "wrong number of constraints");
    }

    #[test]
    #[ignore] // Slow test – run only when compiled for release.
    fn test_drgporep_compound_pedersen() {
        drgporep_test_compound::<PedersenHasher>();
    }

    #[test]
    #[ignore] // Slow test – run only when compiled for release.
    fn test_drgporep_compound_blake2s() {
        drgporep_test_compound::<Blake2sHasher>();
    }

    fn drgporep_test_compound<H: Hasher>() {
        // femme::pretty::Logger::new()
        //     .start(log::LevelFilter::Trace)
        //     .ok();

        let rng = &mut XorShiftRng::from_seed(crate::TEST_SEED);

        let nodes = 5;
        let degree = BASE_DEGREE;
        let challenges = vec![1, 3];

        let replica_id: Fr = Fr::random(rng);
        let mut data: Vec<u8> = (0..nodes)
            .flat_map(|_| fr_into_bytes::<Bls12>(&Fr::random(rng)))
            .collect();

        // Only generate seed once. It would be bad if we used different seeds in the same test.
        let seed = new_seed();

        let setup_params = compound_proof::SetupParams {
            vanilla_params: drgporep::SetupParams {
                drg: drgporep::DrgParams {
                    nodes,
                    degree,
                    expansion_degree: 0,
                    seed,
                },
                private: false,
                challenges_count: 2,
            },
            partitions: None,
        };

        let public_params =
            DrgPoRepCompound::<H, BucketGraph<_>>::setup(&setup_params).expect("setup failed");

        // MT for original data is always named tree-d, and it will be
        // referenced later in the process as such.
        use merkletree::store::{StoreConfig, DEFAULT_CACHED_ABOVE_BASE_LAYER};
        let cache_dir = tempfile::tempdir().unwrap();
        let cache_path = cache_dir.as_ref().to_str().unwrap();
        let config = StoreConfig::new(
            cache_path.to_string(),
            "tree-d".to_string(),
            DEFAULT_CACHED_ABOVE_BASE_LAYER,
        );

        let (tau, aux) = drgporep::DrgPoRep::<H, _>::replicate(
            &public_params.vanilla_params,
            &replica_id.into(),
            data.as_mut_slice(),
            None,
            Some(config)
        )
        .expect("failed to replicate");

        let public_inputs = drgporep::PublicInputs::<H::Domain> {
            replica_id: Some(replica_id.into()),
            challenges,
            tau: Some(tau),
        };
        let private_inputs = drgporep::PrivateInputs {
            tree_d: &aux.tree_d,
            tree_r: &aux.tree_r,
        };

        // This duplication is necessary so public_params don't outlive public_inputs and private_inputs.
        let setup_params = compound_proof::SetupParams {
            vanilla_params: drgporep::SetupParams {
                drg: drgporep::DrgParams {
                    nodes,
                    degree,
                    expansion_degree: 0,
                    seed,
                },
                private: false,
                challenges_count: 2,
            },
            partitions: None,
        };

        let public_params =
            DrgPoRepCompound::<H, BucketGraph<_>>::setup(&setup_params).expect("setup failed");

        {
            let (circuit, inputs) = DrgPoRepCompound::<H, _>::circuit_for_test(
                &public_params,
                &public_inputs,
                &private_inputs,
            );

            let mut cs = TestConstraintSystem::new();

            circuit
                .synthesize(&mut cs)
                .expect("failed to synthesize test circuit");
            assert!(cs.is_satisfied());
            assert!(cs.verify(&inputs));

            let blank_circuit = <DrgPoRepCompound<_, _> as CompoundProof<_, _, _>>::blank_circuit(
                &public_params.vanilla_params,
            );

            let mut cs_blank = TestConstraintSystem::new();
            blank_circuit
                .synthesize(&mut cs_blank)
                .expect("failed to synthesize blank circuit");

            let a = cs_blank.pretty_print_list();

            let b = cs.pretty_print_list();

            for (i, (a, b)) in a.chunks(100).zip(b.chunks(100)).enumerate() {
                assert_eq!(a, b, "failed at chunk {}", i);
            }
        }

        {
            let gparams = DrgPoRepCompound::<H, _>::groth_params(&public_params.vanilla_params)
                .expect("failed to get groth params");

            let proof = DrgPoRepCompound::<H, _>::prove(
                &public_params,
                &public_inputs,
                &private_inputs,
                &gparams,
            )
            .expect("failed while proving");

            let verified = DrgPoRepCompound::<H, _>::verify(
                &public_params,
                &public_inputs,
                &proof,
                &NoRequirements,
            )
            .expect("failed while verifying");

            assert!(verified);
        }
    }
}
