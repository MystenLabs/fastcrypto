// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::marker::PhantomData;

use ark_ff::PrimeField;
use ark_relations::{
    lc,
    r1cs::{
        ConstraintSynthesizer, ConstraintSystemRef, LinearCombination, SynthesisError, Variable,
    },
};

/// A dummy circuit that checks an addition constraint between some of its inputs
/// as well as a parametrized number of dummy constraints.
#[derive(Debug, Copy, Clone)]
pub struct DummyCircuit<F: PrimeField> {
    /// the first input to the circuit
    pub a: Option<F>,
    /// the second input to the circuit
    pub b: Option<F>,
    /// The number of variables to the circuit
    pub num_variables: usize,
    /// the number of constraints to the circuit
    pub num_constraints: usize,
}

impl<F: PrimeField> ConstraintSynthesizer<F> for DummyCircuit<F> {
    // We'll be proving a relationship involving the product c of a & b.
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        let a = cs.new_witness_variable(|| self.a.ok_or(SynthesisError::AssignmentMissing))?;
        let b = cs.new_witness_variable(|| self.b.ok_or(SynthesisError::AssignmentMissing))?;
        let c = cs.new_input_variable(|| {
            let a = self.a.ok_or(SynthesisError::AssignmentMissing)?;
            let b = self.b.ok_or(SynthesisError::AssignmentMissing)?;

            Ok(a * b)
        })?;

        // a, b, c are above, let's define the rest.
        for _ in 0..(self.num_variables - 3) {
            let _ = cs.new_witness_variable(|| self.a.ok_or(SynthesisError::AssignmentMissing))?;
        }

        for _ in 0..self.num_constraints - 1 {
            cs.enforce_constraint(lc!() + a, lc!() + b, lc!() + c)?;
        }

        cs.enforce_constraint(lc!(), lc!(), lc!())?;

        Ok(())
    }
}

/// A circuit that checks a parametrized number of R1CS constraints that verify the computation of the Fibonacci sequence.
/// It generates constraints in layers, numbered from 1 to num_constraints, specifying the computation of the Fibonacci sequence.
/// On each layer, it does:
///
/// 1. Add two new public inputs a = initial_a and b = initial_b at the first layer, or retrieve them from the previous layer if the layer if larger.
/// 2. Add a new witness variable c,
/// 3. Add and check a constraint that c = a + b,
/// 4. Initialize the values a = b; b = c; and repeat from step 1.
///
/// Note: we encode the addition (c = a + b) less efficiently than what R1CS would allow, but this is not a problem for the purpose of this demo.
#[derive(Debug)]
pub struct Fibonacci<F: PrimeField> {
    num_constraints: usize,
    initial_a: F,
    initial_b: F,
    _engine: PhantomData<F>,
}

impl<F: PrimeField> Fibonacci<F> {
    /// Create a new instance of the Fibonacci circuit. We have to provide the initial values of a and b, the first and second initial values of
    /// a sequence verifying the Fibonacci recursion.
    pub fn new(num_constraints: usize, initial_a: F, initial_b: F) -> Self {
        Self {
            num_constraints,
            initial_a,
            initial_b,
            _engine: PhantomData,
        }
    }
}

impl<F: PrimeField> ConstraintSynthesizer<F> for Fibonacci<F> {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        let mut assignments = Vec::new();
        let mut a_val = self.initial_a;
        let mut a_var = cs.new_input_variable(|| Ok(a_val))?;
        assignments.push((a_val, a_var));

        let mut b_val = self.initial_b;
        let mut b_var = cs.new_input_variable(|| Ok(b_val))?;
        assignments.push((a_val, a_var));

        for _i in 0..self.num_constraints - 1 {
            let c_val = a_val + b_val;
            let c_var = cs.new_witness_variable(|| Ok(c_val))?;

            cs.enforce_constraint(lc!() + a_var + b_var, lc!() + Variable::One, lc!() + c_var)?;

            assignments.push((c_val, c_var));
            a_val = b_val;
            a_var = b_var;
            b_val = c_val;
            b_var = c_var;
        }

        let mut a_lc = LinearCombination::zero();
        let mut b_lc = LinearCombination::zero();
        let mut c_val = F::zero();

        for (val, var) in assignments {
            a_lc = a_lc + var;
            b_lc = b_lc + var;
            c_val += val;
        }
        c_val = c_val.square();

        let c_var = cs.new_witness_variable(|| Ok(c_val))?;

        cs.enforce_constraint(lc!() + a_lc, lc!() + b_lc, lc!() + c_var)?;

        Ok(())
    }
}
