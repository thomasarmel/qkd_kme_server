//! QKD network routing manager, get route to SAE

use std::collections::HashMap;

#[allow(dead_code)]
#[derive(Clone)]
pub(super) struct QkdRouter {
    sae_to_kme_associations: HashMap<i64, i64>,
}

#[allow(dead_code)]
impl QkdRouter {
    pub(super) fn new() -> Self {
        Self {
            sae_to_kme_associations: HashMap::new(),
        }
    }

    pub(super) fn add_sae_to_kme_association(&mut self, sae_id: i64, kme_id: i64) {
        self.sae_to_kme_associations.insert(sae_id, kme_id);
    }

    pub(super) fn get_kme_id_from_sae_id(&self, sae_id: i64) -> Option<&i64> {
        self.sae_to_kme_associations.get(&sae_id)
    }
}