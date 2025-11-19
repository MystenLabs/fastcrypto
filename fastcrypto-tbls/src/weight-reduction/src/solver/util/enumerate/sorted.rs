fn append_tail(n: u64, total_num_tickets: u64, v: &mut Vec<u64>) {
  assert!(n > 0);

  if n >= total_num_tickets {
    for _ in 0..total_num_tickets {
      v.push(1);
    }
  } else {
    let t = total_num_tickets.div_ceil(n);
    let d = t * n - total_num_tickets;

    for _ in 0..(n - d) {
      v.push(t);
    }
    for _ in 0..d {
      v.push(t - 1);
    }
  }
}

enum Enumerator {
  InProgress { n: u64, v: Vec<u64> },
  Finished,
}

impl Enumerator {
  fn new(n: u64, total_num_tickets: u64) -> Self {
    let mut v = Vec::new();
    append_tail(n, total_num_tickets, &mut v);

    Enumerator::InProgress { n, v }
  }
}

impl Iterator for Enumerator {
  type Item = Vec<u64>;

  fn next(&mut self) -> Option<Self::Item> {
    match self {
      Enumerator::InProgress { n, v } => {
        let n = *n;

        let res = v.clone();

        if v.len() <= 1 {
          *self = Enumerator::Finished;
        } else {
          let mut sum = v.pop().unwrap();
          while (v.len() >= 2) && (*v.last().unwrap() == v[v.len() - 2]) {
            sum += v.pop().unwrap();
          }

          let sum = sum - 1;
          *v.last_mut().unwrap() += 1;
          append_tail(n - v.len() as u64, sum, v);
        }

        Some(res)
      }
      Enumerator::Finished => None,
    }
  }
}

pub fn enumerate(
  n: u64,
  total_num_tickets: u64,
) -> impl Iterator<Item = Vec<u64>> {
  Enumerator::new(n, total_num_tickets)
}

pub fn enumerate_infinite(n: u64) -> impl Iterator<Item = Vec<u64>> {
  (0..=u64::MAX)
    .flat_map(move |total_num_tickets| enumerate(n, total_num_tickets))
}
