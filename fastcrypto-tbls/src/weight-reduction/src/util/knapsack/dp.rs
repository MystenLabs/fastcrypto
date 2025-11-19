#[derive(Debug)]
pub struct DP {
  max_weight: u64,
  dp: Vec<u64>,
}

impl DP {
  // Create a knapsack dynamic programming data with configured max weight
  // and adversarial tickets target. Returns None only when it's immediately
  // clear we can achieve the adversarial tickets target -- if and only if
  // adv_tickets_target = 0.
  pub fn new(max_weight: u64, adv_tickets_target: u64) -> Option<DP> {
    if adv_tickets_target == 0 {
      return None;
    }

    let mut dp = Vec::with_capacity(adv_tickets_target as usize);
    dp.push(0);

    Some(DP { max_weight, dp })
  }

  // Create a copy of the data structure with a new configured adversarial
  // tickets target. It must be less or equal to the previously configured
  // adversarial tickets target. Returns None iff the new adversarial tickets
  // target has already been achieved.
  pub fn make_copy(&self, adv_tickets_target: u64) -> Option<DP> {
    assert!(adv_tickets_target <= self.dp.capacity() as u64);

    let adv_tickets_target = adv_tickets_target as usize;
    if adv_tickets_target < self.dp.len() {
      return None;
    }

    let mut dp = Vec::with_capacity(adv_tickets_target);
    for &x in self.dp.iter().take(adv_tickets_target) {
      dp.push(x);
    }

    Some(DP {
      max_weight: self.max_weight,
      dp,
    })
  }

  // Apply an element with weight w and t tickets. Returns None iff
  // the configured adversarial tickets target is achieved.
  pub fn apply(mut self, w: u64, t: u64) -> Option<DP> {
    assert!(w > 0);

    if (w > self.max_weight) || (t == 0) {
      return Some(self);
    }
    let adv_tickets_target = self.dp.capacity();
    if t as usize >= adv_tickets_target {
      return None;
    }

    for i in (1..self.dp.len()).rev() {
      if self.dp[i] != 0 {
        let ww = self.dp[i] + w;
        let tt = i + t as usize;
        if ww <= self.max_weight {
          if tt >= adv_tickets_target {
            return None;
          }
          while self.dp.len() <= tt {
            self.dp.push(0);
          }
          if (ww < self.dp[tt]) || (self.dp[tt] == 0) {
            self.dp[tt] = ww;
          }
        }
      }
    }

    let t = t as usize;
    while self.dp.len() <= t {
      self.dp.push(0);
    }
    if (w < self.dp[t]) || (self.dp[t] == 0) {
      self.dp[t] = w;
    }

    Some(self)
  }

  // Returns the maximum achievable adversarial number of tickets.
  pub fn adversarial_tickets(&self) -> u64 {
    for (t, &w) in self.dp.iter().enumerate().rev() {
      if w != 0 {
        return t as u64;
      }
    }
    0
  }
  pub fn adv_tickets_target(&self) -> u64 {
    self.dp.capacity() as u64
  }
}
