# Weight Reduction: Proof and Analysis

## Definitions

- **Original weights**: $w_i$ for $i = 1, \ldots, n$
- **Reduced weights**: $w'_i$ for $i = 1, \ldots, n$
- **Total original weight**: $W = \sum_{i=1}^n w_i$
- **Total reduced weight**: $W' = \sum_{i=1}^n w'_i$
- **Effective divisor**: $d = W / W'$
- **Precision loss**: $\delta = \sum_{i=1}^n \max(w_i - w'_i \cdot d, 0)$

For any subset $S$, let $w(S) = \sum_{i \in S} w_i$ and $w'(S) = \sum_{i \in S} w'_i$.

## Precision Bounds

**Claim.** For any coalition $S \subseteq \{1, \ldots, n\}$:
$$
w'(S) \cdot d - \delta \leq w(S) \leq w'(S) \cdot d + \delta
$$

### Upper bound: $w(S) \leq w'(S) \cdot d + \delta$

$$
\begin{aligned}
w(S) - w'(S) \cdot d &= \sum_{i \in S} (w_i - w'_i \cdot d) \\
&\leq \sum_{i \in S} \max(w_i - w'_i \cdot d, 0) \\
&\leq \sum_{i=1}^n \max(w_i - w'_i \cdot d, 0) = \delta
\end{aligned}
$$

### Lower bound: $w(S) \geq w'(S) \cdot d - \delta$

Since $\sum_{i=1}^n (w'_i \cdot d - w_i) = W' \cdot d - W = 0$, the sum of positive differences equals the sum of negative differences:

$$
\sum_{i=1}^n \max(w'_i \cdot d - w_i, 0) = \sum_{i=1}^n \max(w_i - w'_i \cdot d, 0) = \delta
$$

Therefore:

$$
\begin{aligned}
w'(S) \cdot d - w(S) &= \sum_{i \in S} (w'_i \cdot d - w_i) \\
&\leq \sum_{i \in S} \max(w'_i \cdot d - w_i, 0) \\
&\leq \sum_{i=1}^n \max(w'_i \cdot d - w_i, 0) = \delta
\end{aligned}
$$

## Algorithm Classification

### Unilateral Algorithms

These algorithms (e.g. **new_reduced**) only decrease weights as a percentage of total weight. For these the **unilateral inequality** holds:

- $w(S) \leq ud \implies w'(S) \leq u \implies w(S) \leq ud + \delta$

We write $u \to [ud,\ ud+\delta]$ to denote this.

### Bilateral Algorithms

These algorithms (e.g. **super_swiper**) may both increase or decrease weights as a percentage of total weight. For these the **bilateral inequality** holds:

- $w(S) \leq ud - \delta \implies w'(S) \leq u \implies w(S) \leq ud + \delta$

We write $u \to [ud-\delta,\ ud+\delta]$ to denote this.

## Parameter Derivation

### Given

- $t_{min}$: lower bound on $t$ in original space, i.e. $t' \to [t_{min}, \cdot]$
- $L$: upper bound in original space for $t'+f'$, i.e. $t'+f' \to [\cdot, L]$
    - Required: $L < 2\, t_{min} + \delta_{allowed}$
- $\delta_{allowed}$: upper bound on error range for parameters
- $f$: the unique value such that $f' \to [f, \cdot]$

### For unilateral algorithms

Target $\delta \leq \delta_{allowed}$. Set:

- $t' = t_{min}/d$
- $f' = (L - t_{min} - \delta)/d$
- $f = f'd$

Mapping to original space:

| Parameter | Range |
|-----------|-------|
| $t'$ | $[t_{min},\ t_{min} + \delta]$ |
| $f'$ | $[L - t_{min} - \delta,\ L - t_{min}]$ |
| $t' + f'$ | $[L - \delta,\ L]$ |

### For bilateral algorithms

Target $\delta \leq \delta_{allowed}/2$. Set:

- $t' = (t_{min} + \delta)/d$
- $f' = (L - t_{min} - 2\delta)/d$
- $f = f'd - \delta$

Mapping to original space:

| Parameter | Range |
|-----------|-------|
| $t'$ | $[t_{min},\ t_{min} + 2\delta]$ |
| $f'$ | $[L - t_{min} - 3\delta,\ L - t_{min} - \delta]$ |
| $t' + f'$ | $[L - 2\delta,\ L]$ |

## Guaranteed Properties

The parameter choices above yield three properties for both algorithm types. We use the arrow notation from the mapping tables, where the left arrow of $u \to [a, b]$ is $w(S) \leq a \implies w'(S) \leq u$ and the right arrow is $w'(S) \leq u \implies w(S) \leq b$.

**1. Safety.** If $w(S) \leq t_{min}$ then $w'(S) \leq t'$.

Any coalition that cannot break the original scheme also cannot break the reduced scheme. This is the left arrow of the $t'$ mapping.

**2. Liveness.** If $w(S) > L$ then $w'(S) > t' + f'$.

This is the contrapositive of the right arrow of the $t' + f'$ mapping.

**3. Byzantine Removal.** If $w'(S) \geq t' + f'$ and $T \subseteq S$ with $w(T) \leq f$, then $w'(S \setminus T) \geq t'$.

*Proof.* By definition, $f$ is the lower bound of the range that $f'$ maps to, so $w(T) \leq f \implies w'(T) \leq f'$ (left arrow of the $f'$ mapping). Therefore:

$$
w'(S \setminus T) = w'(S) - w'(T) \geq (t' + f') - f' = t'.
$$

This property ensures that after collecting enough reduced weight ($t' + f'$) in signatures, removing all Byzantine parties (with original weight at most $f$) still leaves at least $t'$ reduced weight — enough to reconstruct.

## Concrete Comparison

### Example 1: $t_{min} = 34\%,\ L = 75\%,\ \delta_{allowed} = 8\%$

**Unilateral (new_reduced)** with $\delta = 8\%$:

- $t' = 34\%,\quad f' = 33\%,\quad f = 33\%$
- $t' = 34\% \to [34\%,\ 42\%]$
- $f' = 33\% \to [33\%,\ 41\%]$
- $t' + f' = 67\% \to [67\%,\ 75\%]$

**Bilateral (super_swiper)** with $\delta = 4\%$:

- $t' = 38\%,\quad f' = 33\%,\quad f = 29\%$
- $t' = 38\% \to [34\%,\ 42\%]$
- $f' = 33\% \to [29\%,\ 37\%]$
- $t' + f' = 71\% \to [67\%,\ 75\%]$

### Example 2: $t_{min} = 52\%,\ L = 80\%,\ \delta_{allowed} = 8\%$

**Unilateral (new_reduced)** with $\delta = 8\%$:

- $t' = 52\%,\quad f' = 20\%,\quad f = 20\%$
- $t' = 52\% \to [52\%,\ 60\%]$
- $f' = 20\% \to [20\%,\ 28\%]$
- $t' + f' = 72\% \to [72\%,\ 80\%]$

**Bilateral (super_swiper)** with $\delta = 4\%$:

- $t' = 56\%,\quad f' = 20\%,\quad f = 16\%$
- $t' = 56\% \to [52\%,\ 60\%]$
- $f' = 20\% \to [16\%,\ 24\%]$
- $t' + f' = 76\% \to [72\%,\ 80\%]$
