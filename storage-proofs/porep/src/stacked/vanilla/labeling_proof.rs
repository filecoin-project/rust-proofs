use std::marker::PhantomData;

//use libfuzzer_sys::arbitrary;
use log::trace;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use storage_proofs_core::{fr32::bytes_into_fr_repr_safe, hasher::Hasher};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LabelingProof<H: Hasher> {
    pub(crate) parents: Vec<H::Domain>,
    pub(crate) layer_index: u32,
    pub(crate) node: u64,
    #[serde(skip)]
    _h: PhantomData<H>,
}

impl<H: Hasher> LabelingProof<H> {
    pub fn new(layer_index: u32, node: u64, parents: Vec<H::Domain>) -> Self {
        LabelingProof {
            node,
            layer_index,
            parents,
            _h: PhantomData,
        }
    }

    fn create_label(&self, replica_id: &H::Domain) -> H::Domain {
        let mut hasher = Sha256::new();
        let mut buffer = [0u8; 64];

        // replica_id
        buffer[..32].copy_from_slice(AsRef::<[u8]>::as_ref(replica_id));

        // layer index
        buffer[32..36].copy_from_slice(&(self.layer_index as u32).to_be_bytes());

        // node id
        buffer[36..44].copy_from_slice(&(self.node as u64).to_be_bytes());

        hasher.input(&buffer[..]);

        // parents
        for parent in &self.parents {
            let data = AsRef::<[u8]>::as_ref(parent);
            hasher.input(data);
        }

        bytes_into_fr_repr_safe(hasher.result().as_ref()).into()
    }

    pub fn verify(&self, replica_id: &H::Domain, expected_label: &H::Domain) -> bool {
        let label = self.create_label(replica_id);
        check_eq!(expected_label, &label);

        true
    }
}
