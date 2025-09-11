use crate::nodes::PartyId;

/// A certificate on a message of type [M].
pub trait Certificate<M> {
    fn is_valid(&self, message: &M, threshold: usize) -> bool;
    fn includes(&self, id: &PartyId) -> bool;
}

#[cfg(test)]
pub(crate) mod test {
    use crate::batched_avss::certificate::Certificate;
    use crate::nodes::{Nodes, PartyId};
    use fastcrypto::groups::GroupElement;
    use itertools::Itertools;
    use serde::Serialize;

    pub struct TestCertificate<EG: GroupElement> {
        pub(crate) included: Vec<u16>,
        pub(crate) nodes: Nodes<EG>,
    }

    impl<EG: GroupElement + Serialize, M> Certificate<M> for TestCertificate<EG> {
        fn is_valid(&self, _message: &M, threshold: usize) -> bool {
            let weights = self
                .included
                .iter()
                .map(|id| self.nodes.share_ids_of(*id).unwrap().len())
                .collect_vec();
            weights.iter().sum::<usize>() >= threshold
        }

        fn includes(&self, index: &PartyId) -> bool {
            self.included.contains(index)
        }
    }
}
