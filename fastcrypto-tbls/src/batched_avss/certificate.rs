use crate::batched_avss::avss::Message;
use crate::nodes::{Nodes, PartyId};
use fastcrypto::groups::GroupElement;
use itertools::Itertools;
use serde::Serialize;

/// A certificate on a [Message].
pub trait Certificate<M> {
    fn is_valid(&self, message: &M, threshold: usize) -> bool;
    fn includes(&self, id: &PartyId) -> bool;
}

#[cfg(test)]
pub struct TestCertificate<EG: GroupElement> {
    pub(crate) included: Vec<u16>,
    pub(crate) nodes: Nodes<EG>,
}

#[cfg(test)]
impl<G: GroupElement, EG: GroupElement + Serialize> Certificate<Message<G, EG>>
    for TestCertificate<EG>
{
    fn is_valid(&self, _message: &Message<G, EG>, threshold: usize) -> bool {
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
