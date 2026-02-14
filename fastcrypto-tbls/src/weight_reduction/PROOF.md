# Liveness Proof for Weight Reduction

## Definitions

- **Original weights**: $w_i$ for $i = 1, \ldots, n$
- **Reduced weights**: $w'_i$ for $i = 1, \ldots, n$
- **Total original weight**: $W = \sum_{i=1}^n w_i$
- **Total reduced weight**: $W' = \sum_{i=1}^n w'_i$
- **Effective divisor**: $d = W / W'$ (exact ratio, no floor)
- **Precision loss**: $\delta = \sum_{i=1}^n \max(w_i - w'_i \cdot d, 0)$

## Key Properties to Prove

**For any coalition $S \subseteq \{1, \ldots, n\}$:**

1. **Upper bound**: $w(S) \leq w'(S) \cdot d + \delta$
2. **Lower bound**: $w(S) \geq w'(S) \cdot d - \delta$

Where:
- $w(S) = \sum_{i \in S} w_i$
- $w'(S) = \sum_{i \in S} w'_i$

## Proof of Upper Bound

We want to show: $w(S) \leq w'(S) \cdot d + \delta$.

For any subset $S$:

$$
\begin{aligned}
w(S) - w'(S) \cdot d &= \sum_{i \in S} (w_i - w'_i \cdot d) \\
&\leq \sum_{i \in S} \max(w_i - w'_i \cdot d, 0) \\
&\leq \sum_{i=1}^n \max(w_i - w'_i \cdot d, 0) \\
&= \delta
\end{aligned}
$$

Therefore: $w(S) \leq w'(S) \cdot d + \delta$

This is the precision loss we calculate in `weight_reduction_checks.rs`.

## Proof of Lower Bound

We want to show: $w(S) \geq w'(S) \cdot d - \delta$, or equivalently $w'(S) \cdot d - w(S) \leq \delta$.

Since $d = W/W'$, we have:

$$
\sum_{i=1}^n (w'_i \cdot d - w_i) = W' \cdot d - W = W - W = 0
$$

This means the sum of positive differences equals the sum of negative differences:
$$
\sum_{i=1}^n \max(w'_i \cdot d - w_i, 0) = -\sum_{i=1}^n \min(w'_i \cdot d - w_i, 0)
$$

Now, when $w'_i \cdot d - w_i < 0$, we have $\min(w'_i \cdot d - w_i, 0) = w'_i \cdot d - w_i = -(w_i - w'_i \cdot d) = -\max(w_i - w'_i \cdot d, 0)$ (since $w_i - w'_i \cdot d > 0$). When $w'_i \cdot d - w_i \geq 0$, both $\min(w'_i \cdot d - w_i, 0) = 0$ and $\max(w_i - w'_i \cdot d, 0) = 0$. Therefore:

$$
-\sum_{i=1}^n \min(w'_i \cdot d - w_i, 0) = \sum_{i=1}^n \max(w_i - w'_i \cdot d, 0) = \delta
$$

So we conclude:
$$
\sum_{i=1}^n \max(w'_i \cdot d - w_i, 0) = \delta
$$

Now, for any subset $S$:

$$
\begin{aligned}
w'(S) \cdot d - w(S) &= \sum_{i \in S} (w'_i \cdot d - w_i) \\
&\leq \sum_{i \in S} \max(w'_i \cdot d - w_i, 0) \\
&\leq \sum_{i=1}^n \max(w'_i \cdot d - w_i, 0) \\
&= \delta
\end{aligned}
$$

Therefore: $w(S) \geq w'(S) \cdot d - \delta$

## Summary

Combining both bounds, for any coalition $S$:
$$
w'(S) \cdot d - \delta \leq w(S) \leq w'(S) \cdot d + \delta
$$
and equivalently:
$$
\frac{w(S) - \delta}{d} \leq w'(S) \leq \frac{w(S) + \delta}{d}
$$

## AVSS Constraints

Let $W$ and $t$ be the total weight and threshold of the original nodes, and $W'$ and $t'$ be the total weight and threshold of the reduced nodes. Let $f$ be a given parameter such that $0 < f < t$ and $t + 2f \leq W$. Let $\delta_{\text{allowed}}$ be the given allowed liveness loss. In the algorithm, we start from a high enough $\beta$ and step down till $2\delta \leq \delta_{\text{allowed}}$. WLOG, we can set $\delta_{\text{allowed}} = 2\delta$ by taking $\delta_{\text{allowed}}$ to be the actually achieved quantity.

We enforce four constraints:

1. **Safety**: For all $S$ such that $w(S) \leq t$, we have $w'(S) \leq t'$. This is guaranteed by taking $t' = (t+2\delta)/d$. The dealer polynomial is set to be of degree $t'-1$.

2. **f-constraint**: For all $S$ such that $w(S) \leq f - 2\delta$, we have $w'(S) \leq f'$. This is guaranteed by taking $f' = (f-\delta)/d$. These slacks are carefully calibrated to ensure $t'+2f' = (t+2f)/d \leq W'$.

3. **Liveness**: For all $S$ such that $w(S) \geq t+f+\delta_{\text{allowed}}$, we need $w'(S) \geq t'+f'$. This is required as the DKG algorithm requires a liveness of $t'+f'$. This follows given the implication $w'(S) \geq (t+f+\delta_{\text{allowed}} -\delta)/d = (t'd-2\delta+f'd+\delta+2\delta-\delta)/d = t'+f'$.

4. **Dual Liveness**: For all $S$ such that $w'(S) \geq t'+f'$, we need $w(S) \geq t+f$. This follows given the implication $w(S) \geq (t'+f')d - \delta = t+2\delta + f - \delta - \delta = t+f$.

5. **Standard DKG constraint**: $0 < f' < t'$, and $t' + 2f' \leq W'$

In effect, we have:
1. $\delta_{\text{allowed}} = 2\delta$
2. $t' = (t+2\delta)/d$
3. $f' = (f-\delta)/d$
4. $w(S) \leq t+\delta \implies w'(S) \leq t' \implies w(S) \leq t+3\delta$.
5. $w(S) \leq f - 2\delta \implies w'(S) \leq f' \implies w(S) \leq f$.
6. $w(S) \geq t+f+2\delta \implies w'(S) \geq t'+f' \implies w(S) \geq t+f$.