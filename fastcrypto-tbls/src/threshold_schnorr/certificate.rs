use crate::nodes::PartyId;

/// A certificate on a message of type [M].
pub trait Certificate<M> {
    fn is_valid(&self, message: &M, threshold: usize) -> bool;
    fn includes(&self, id: &PartyId) -> bool;
}
