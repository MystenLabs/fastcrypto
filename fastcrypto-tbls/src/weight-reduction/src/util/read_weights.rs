use anyhow::Context;

fn read_weights_internal<R: std::io::Read>(
  reader: R,
) -> Result<Vec<u64>, anyhow::Error> {
  let content = std::io::read_to_string(reader)?;
  let weights: Result<Vec<u64>, _> = content
    .split_whitespace()
    .map(str::parse)
    .filter(|x| match x {
      Ok(x) => *x > 0,
      Err(_) => true,
    })
    .collect();
  let mut weights = weights?;
  weights.sort_unstable_by(|a, b| b.cmp(a));
  Ok(weights)
}

pub fn read_weights(path: &str) -> Result<Vec<u64>, anyhow::Error> {
  let file = std::fs::File::open(path)
    .with_context(|| format!("unable to read from {path}"))?;
  read_weights_internal(file)
}

#[cfg(test)]
mod tests {
  use super::read_weights_internal;

  #[test]
  fn basic() {
    let content = "25\n54\n";
    let ret = read_weights_internal(content.as_bytes()).unwrap();
    assert_eq!(vec![54, 25], ret);
  }

  #[test]
  fn error() {
    let content = "25\n5a\n";
    let ret = read_weights_internal(content.as_bytes());
    assert!(ret.is_err());
  }

  #[test]
  fn zero() {
    let content = "25\n0\n54\n";
    let ret = read_weights_internal(content.as_bytes()).unwrap();
    assert_eq!(vec![54, 25], ret);
  }
}
