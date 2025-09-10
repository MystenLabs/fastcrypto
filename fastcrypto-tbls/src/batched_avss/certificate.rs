use crate::batched_avss::avss::Message;
use crate::nodes::PartyId;

/// A certificate on a [Message].
pub trait Certificate<M> {
    fn is_valid(&self, message: &M, threshold: usize) -> bool;
    fn includes(&self, id: &PartyId) -> bool;
}
