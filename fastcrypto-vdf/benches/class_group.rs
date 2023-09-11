// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use criterion::measurement::Measurement;
use criterion::{criterion_group, criterion_main, BatchSize, BenchmarkGroup, Criterion};
#[cfg(feature = "gmp")]
use fastcrypto_vdf::class_group::gmp::{Discriminant, QuadraticForm};
#[cfg(not(feature = "gmp"))]
use fastcrypto_vdf::class_group::num_bigint::{Discriminant, QuadraticForm};
use fastcrypto_vdf::ParameterizedGroupElement;
use num_bigint::BigInt;
use num_traits::Num;

fn class_group_ops_single<M: Measurement>(
    discriminant_string: &str,
    group: &mut BenchmarkGroup<M>,
) {
    let discriminant =
        Discriminant::try_from(BigInt::from_str_radix(discriminant_string, 10).unwrap()).unwrap();
    let discriminant_size = discriminant.bits();
    let x = QuadraticForm::generator(&discriminant).mul(&BigInt::from(1234));
    let y = QuadraticForm::generator(&discriminant).mul(&BigInt::from(4321));
    let z = y.clone();

    group.bench_function(format!("Compose/{}", discriminant_size), move |b| {
        b.iter(|| x.compose(&y))
    });

    group.bench_function(format!("Double/{}", discriminant_size), move |b| {
        b.iter_batched(|| z.clone(), |z| z.double(), BatchSize::SmallInput)
    });
}

fn class_group_ops(c: &mut Criterion) {
    #[cfg(not(feature = "gmp"))]
    let dep = "num-bigint";

    #[cfg(feature = "gmp")]
    let dep = "gmp";

    let mut group: BenchmarkGroup<_> = c.benchmark_group(format!("Class Group ({})", dep));

    class_group_ops_single("-9458193260787340859710210783898414376413627187338129653105774703043377776905956484932486183722303201135571583745806165441941755833466966188398807387661571", & mut group);
    class_group_ops_single("-173197108158285529655099692042166386683260486655764503111574151459397279244340625070436917386670107433539464870917173822190635872887684166173874718269704667936351650895772937202272326332043347073303124000059154982400685660701006453457007094026343973435157790533480400962985543272080923974737725172126369794019", &mut group);
    class_group_ops_single("-22095660145335626734136723882213867119525158486748326436658405688938881635930095910545975113322422007557877549811131380944483682691496712374646265646126342225157173833472005173943132929485917949098339821198173613625980795853654091563015612198119470420924203352103137372682223982372799834940380723501717965717242096771649865587215657476090641867312160372980901581090340446629098783840147337471587570044401118113386981699458468470810571214101437629329863005183213111853162312552251726608759833055175875835838072491157367445961993945932717938911079166219543839017151351421582746995142830619506410440886315365249596935583", & mut group);
}

criterion_group! {
name = class_group_benchmarks;
config = Criterion::default().sample_size(100);
targets = class_group_ops,
}

criterion_main!(class_group_benchmarks);
