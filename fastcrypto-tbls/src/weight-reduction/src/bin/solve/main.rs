use clap::Parser;
use mimalloc::MiMalloc;
use solver::{
  solver::{bruteforce_sorted, faster_swiper, gcd_wr, super_swiper, swiper},
  types::{CompactDisplay, Ratio},
  util::{
    basic::{calc_adv_tickets_target, calc_max_adv_weight},
    knapsack::adversarial_tickets,
    read_weights,
  },
};
use std::time::{Duration, Instant};

#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

#[derive(Debug, Copy, Clone, clap::ValueEnum)]
enum Algorithm {
  BruteforceSorted,
  Swiper,
  FasterSwiper,
  SuperSwiper,
  GcdWr,
}

#[derive(Parser, Debug)]
struct Cli {
  #[arg(long, value_delimiter = ',')]
  alpha: Vec<Ratio>,

  #[arg(long)]
  beta: Ratio,

  #[arg(long)]
  weights_path: String,

  #[arg(long)]
  algorithm: Algorithm,

  #[arg(long)]
  show_tickets: bool,

  /// Run the solver repeatedly for this long and average the duration.
  #[arg(long, value_parser = humantime::parse_duration, default_value = "0s")]
  measure_duration: Duration,
}

fn run(
  algorithm: Algorithm,
  alpha: Ratio,
  beta: Ratio,
  weights: &[u64],
  measure_duration: Duration,
) -> (Vec<u64>, Duration) {
  let f = match algorithm {
    Algorithm::BruteforceSorted => bruteforce_sorted::solve,
    Algorithm::Swiper => swiper::solve,
    Algorithm::FasterSwiper => faster_swiper::solve,
    Algorithm::SuperSwiper => super_swiper::solve,
    Algorithm::GcdWr => gcd_wr::solve,
  };

  let start = Instant::now();
  let mut count = 0;
  loop {
    let ret = f(alpha, beta, weights);
    count += 1;

    let duration = start.elapsed();
    if duration >= measure_duration {
      return (ret, duration / count);
    }
  }
}

fn main() -> Result<(), anyhow::Error> {
  let cli = Cli::parse();

  let weights = read_weights(&cli.weights_path)?;
  assert!(!weights.is_empty());
  let total_weight = weights.iter().sum::<u64>();

  for alpha in cli.alpha {
    let (tickets, duration) = run(
      cli.algorithm,
      alpha,
      cli.beta,
      &weights,
      cli.measure_duration,
    );

    let total_num_tickets = tickets.iter().sum::<u64>();
    let total_adv_tickets = adversarial_tickets(
      &weights,
      &tickets,
      calc_max_adv_weight(alpha, total_weight),
      calc_adv_tickets_target(cli.beta, total_num_tickets),
    )
    .unwrap();
    assert!(tickets.iter().all(|&t| t > 0));
    let non_zero = tickets.len();

    print!(
      "alpha: {alpha} beta: {} \
      total_num_tickets: {total_num_tickets} \
      total_adv_tickets: {total_adv_tickets} \
      non_zero: {non_zero}",
      cli.beta,
    );
    if cli.show_tickets {
      print!(" tickets: {}", CompactDisplay(&tickets));
    }
    println!(" duration: {duration:?}");
  }

  Ok(())
}
