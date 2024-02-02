//! QKD network routing manager, get route to SAE

use std::collections::HashMap;
use crate::{KmeId, SaeId};

#[allow(dead_code)]
#[derive(Clone)]
pub(super) struct QkdRouter {
    sae_to_kme_associations: HashMap<SaeId, KmeId>,
}

#[allow(dead_code)]
impl QkdRouter {
    pub(super) fn new() -> Self {
        Self {
            sae_to_kme_associations: HashMap::new(),
        }
    }

    pub(super) fn add_sae_to_kme_association(&mut self, sae_id: SaeId, kme_id: KmeId) {
        self.sae_to_kme_associations.insert(sae_id, kme_id);
    }

    pub(super) fn get_kme_id_from_sae_id(&self, sae_id: SaeId) -> Option<&KmeId> {
        self.sae_to_kme_associations.get(&sae_id)
    }
}