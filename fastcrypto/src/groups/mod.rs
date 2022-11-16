use serde::de::DeserializeOwned;
use serde::Serialize;

//
// Macros for operator overloading.
//
macro_rules! impl_binary_op {
    ($lhs:ident, $rhs:ident, $out:ident, $op:ident, $op_method:ident, $group:ident) => {
        impl $op<$rhs> for $lhs {
            type Output = $out;

            #[inline]
            fn $op_method(self, other: $rhs) -> Self::Output {
                $group::$op_method(&self, &other)
            }
        }

        impl<'a> $op<$rhs> for &'a $lhs {
            type Output = $out;

            #[inline]
            fn $op_method(self, other: $rhs) -> Self::Output {
                $group::$op_method(self, &other)
            }
        }

        impl<'a> $op<&'a $rhs> for $lhs {
            type Output = $out;

            #[inline]
            fn $op_method(self, other: &'a $rhs) -> Self::Output {
                $group::$op_method(&self, other)
            }
        }

        impl<'a, 'b> $op<&'a $rhs> for &'b $lhs {
            type Output = $out;

            #[inline]
            fn $op_method(self, other: &'a $rhs) -> Self::Output {
                $group::$op_method(self, other)
            }
        }
    };
}

macro_rules! impl_unary_op {
    ($t:ident, $op:ident, $op_method:ident, $group:ident) => {
        impl $op for $t {
            type Output = $t;

            #[inline]
            fn $op_method(self) -> $t {
                $group::$op_method(&self)
            }
        }

        impl<'a> $op for &'a $t {
            type Output = $t;

            #[inline]
            fn $op_method(self) -> $t {
                $group::$op_method(self)
            }
        }
    };
}

/// Impl operator overload for the elements of a given group.
macro_rules! impl_group {
    ($scalar:ident, $element:ident, $group:ident) => {
        impl_binary_op!($element, $element, $element, Add, add, $group);
        impl_binary_op!($element, $element, $element, Sub, sub, $group);
        impl_binary_op!($scalar, $element, $element, Mul, mul, $group);
        impl_unary_op!($element, Neg, neg, $group);
    };
}

pub mod ristretto255;

/// Trait impl'd by additive groups.
pub trait AdditiveGroup {
    /// Type representing elements of this group.
    type Element: PartialEq + Eq + Serialize + DeserializeOwned;

    /// Type representing scalars for this group, e.g. integers modulo the group order.
    /// These are used for scalar multiplication of [Self::Element]s.
    type Scalar: From<u64> + Eq + PartialEq + Serialize + DeserializeOwned;

    /// Return an instance of the identity element in this group.
    fn identity() -> Self::Element;

    /// Return true if the given element is the identity of this group.
    fn is_identity(element: &Self::Element) -> bool {
        element == &Self::identity()
    }

    /// Return the sum of two elements.
    fn add(a: &Self::Element, b: &Self::Element) -> Self::Element;

    /// Return the additive inverse of an element.
    fn neg(a: &Self::Element) -> Self::Element;

    /// Return the difference of two elements.
    fn sub(a: &Self::Element, b: &Self::Element) -> Self::Element {
        Self::add(a, &Self::neg(b))
    }

    /// Return the result of a scalar multiplication of a group element with the given scalar.
    fn mul(scalar: &Self::Scalar, element: &Self::Element) -> Self::Element;
}
