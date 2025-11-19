use crate::types::Ratio;
use std::{cmp::Ordering, collections::BinaryHeap};

#[derive(Eq, PartialEq)]
struct QueueElement {
  s: Ratio,
  i: usize,
}

impl Ord for QueueElement {
  fn cmp(&self, other: &Self) -> Ordering {
    other.s.cmp(&self.s).then(other.i.cmp(&self.i))
  }
}

impl PartialOrd for QueueElement {
  fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
    Some(self.cmp(other))
  }
}

struct Generator<'a> {
  weights: &'a [u64],
  c: Ratio,
  r: usize,
  queue: BinaryHeap<QueueElement>,
}

impl<'a> Generator<'a> {
  fn new(weights: &'a [u64], c: Ratio) -> Self {
    assert!(!weights.is_empty());
    debug_assert!(weights.is_sorted_by(|a, b| a >= b));
    assert!(*weights.last().unwrap() > 0);
    assert!(c >= 0.into());
    assert!(c < 1.into());

    let mut queue = BinaryHeap::new();
    queue.push(QueueElement {
      s: (Ratio::from_integer(1) - c)
        / Ratio::from_integer(*weights.first().unwrap()),
      i: 0,
    });

    Self {
      weights,
      c,
      r: 0,
      queue,
    }
  }
}

impl Iterator for Generator<'_> {
  type Item = usize;

  fn next(&mut self) -> Option<Self::Item> {
    let elem = self.queue.pop().unwrap();
    let new_value = (elem.s * self.weights[elem.i] + self.c).to_integer();

    self.queue.push(QueueElement {
      s: (Ratio::from_integer(new_value + 1) - self.c)
        / Ratio::from_integer(self.weights[elem.i]),
      i: elem.i,
    });
    if (elem.i == self.r) && (self.r + 1 < self.weights.len()) {
      self.r += 1;
      self.queue.push(QueueElement {
        s: (Ratio::from_integer(1) - self.c)
          / Ratio::from_integer(self.weights[self.r]),
        i: self.r,
      });
    }

    Some(elem.i)
  }
}

pub fn generate(
  weights: &[u64],
  c: Ratio,
) -> impl Iterator<Item = usize> + use<'_> {
  Generator::new(weights, c)
}
