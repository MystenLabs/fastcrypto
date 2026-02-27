use std::cmp::max;
use std::ops::{Add, Mul};
use fastcrypto::groups::{GroupElement, ristretto255::RistrettoScalar};

// Splits vector `v` into two vectors `v_even` and `v_odd` where `v_even` contains the elements at even indices and 
// `v_odd` contains the elements at odd indices.
pub fn reduce<T>(v: &[T]) -> (Vec<T>, Vec<T>) 
where 
    T: Copy
{
    let mut v_even = Vec::with_capacity((v.len() + 1) / 2);
    let mut v_odd = Vec::with_capacity(v.len() / 2);
    for (i, val) in v.iter().enumerate() {
        if i % 2 == 0 { v_even.push(*val); } else { v_odd.push(*val); }
    }
    (v_even, v_odd)
}

// Extends vector `v` to length `n` by appending default values of type `T` if `v` is shorter than `n`.
pub fn extend<T>(v: &[T], n: usize) -> Vec<T>
where 
    T: Copy + Default 
{
    let mut v_ext = Vec::with_capacity(n);
    v_ext.extend_from_slice(&v[..v.len().min(n)]);
    v_ext.resize(n, T::default());
    v_ext
}

// Computes the inner product of two vectors `v` and `w`, i.e., result = sum_i (v_i * w_i).
pub fn inner_product<T>(v: &[T], w: &[RistrettoScalar]) -> T 
where
    T: Copy + Mul<RistrettoScalar, Output = T> + Add<Output = T> + Default,
{
    let mut result = T::default(); // ZERO
    let v_ext = extend(v, max(v.len(), w.len()));
    let w_ext = &extend(w, max(v.len(), w.len()));
    v_ext.iter().zip(w_ext).for_each(|(v_val, w_val)| {
        result = result.add(v_val.mul(*w_val));
    });
    result
}

// Computes the weighted inner product of two vectors `v` and `w` with a given `weight`, i.e., result = sum_i (v_i * w_i * weight^i).
pub fn weighted_inner_product<T>(v: &[T], w: &[RistrettoScalar], weight: &RistrettoScalar) -> T
where 
    T: Copy + Mul<RistrettoScalar, Output = T> + Add<Output = T> + Default,
{
    let mut exp = RistrettoScalar::generator(); // ONE
    let mut result = T::default(); // ZERO
    let v_ext = extend(v, max(v.len(), w.len()));
    let w_ext = &extend(w, max(v.len(), w.len()));
    v_ext.iter().zip(w_ext).for_each(|(v_val, w_val)| {
        exp = exp.mul(weight);
        result = result.add(v_val.mul(w_val.mul(&exp)));
    });
    result
}

// Scales each element of vector `v` by a given `scalar`, i.e., result[i] = v[i] * scalar.
pub fn scale<'a, T>(v: &[T], scalar: &'a RistrettoScalar) -> Vec<T> 
where
    T: Copy + Mul<&'a RistrettoScalar, Output = T>
{
    v.iter().map(|x| x.mul(scalar)).collect()
}

// Adds two vectors `v` and `w` element-wise, i.e., result[i] = v[i] + w[i].
pub fn add<T>(v: &[T], w: &[T]) -> Vec<T> 
where
    T: Copy + Add<Output = T> + Default
{
    // let mut result = Vec::with_capacity(max(v.len(), w.len()));
    let v_ext = extend(v, max(v.len(), w.len()));
    let w_ext = &extend(w, max(v.len(), w.len()));
    v_ext.iter().zip(w_ext).map(|(v_val, w_val)| v_val.add(*w_val)).collect::<Vec<T>>()
}