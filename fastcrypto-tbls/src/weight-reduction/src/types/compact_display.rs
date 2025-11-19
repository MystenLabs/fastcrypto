use core::fmt;

#[derive(Debug, Clone, Copy)]
pub struct CompactDisplay<'a>(pub &'a [u64]);

fn delete_head(mut arr: &[u64], elem: u64) -> &[u64] {
  loop {
    match arr.split_first() {
      None => return arr,
      Some((&first, new_arr)) => {
        if first != elem {
          return arr;
        }
        arr = new_arr;
      }
    }
  }
}

impl fmt::Display for CompactDisplay<'_> {
  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    write!(f, "[")?;

    let mut first = true;
    let mut arr = self.0;
    while let Some(&first_elem) = arr.first() {
      if first {
        first = false;
      } else {
        write!(f, ", ")?;
      }
      let new_arr = delete_head(arr, first_elem);
      write!(f, "[{}; {}]", first_elem, arr.len() - new_arr.len())?;
      arr = new_arr;
    }

    write!(f, "]")?;
    Ok(())
  }
}
