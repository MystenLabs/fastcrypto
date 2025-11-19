#[derive(Debug, Clone)]
pub struct Tickets {
  tickets: Vec<u64>,
  total: u64,
}

impl Tickets {
  pub fn new() -> Self {
    Self {
      tickets: Vec::new(),
      total: 0,
    }
  }

  pub fn update(&mut self, index: usize) {
    while index >= self.tickets.len() {
      self.tickets.push(0);
    }
    self.tickets[index] += 1;
    self.total += 1;
  }

  pub fn get(&self, index: usize) -> u64 {
    match self.tickets.get(index) {
      Some(&x) => x,
      None => 0,
    }
  }

  pub fn data(&self) -> &[u64] {
    &self.tickets
  }

  pub fn extract_data(self) -> Vec<u64> {
    self.tickets
  }

  pub fn total(&self) -> u64 {
    self.total
  }

  pub fn clear(&mut self) {
    self.tickets.clear();
    self.total = 0;
  }

  #[cfg(test)]
  pub fn from_vec(tickets: Vec<u64>) -> Self {
    let total = tickets.iter().sum();
    Self { tickets, total }
  }
}
