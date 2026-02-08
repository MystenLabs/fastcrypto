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

## DKG Constraints

Let $W$ and $t$ be the total weight and threshold of the original nodes, and $W'$ and $t'$ be the total weight and threshold of the reduced nodes. Let $f$ be a given parameter such that $0 < f < t$ and $t + 2f \leq W$.

We want four constraints:

1. **Safety**: For all $S$ such that $w(S) \leq t-1$, we have $w'(S) < \beta W'$. This is guaranteed by supplying $\alpha = (t-1)/W$ and $\beta$ to the super swiper algorithm and then setting threshold $t' = \beta W'$. The dealer polynomial is set to be of degree $t'-1$.

2. **f-constraint**: For all $S$ such that $w(S) \geq f$, we have $w'(S) \geq f'$.

3. **Liveness**: For all $S$ such that $w(S) \geq t+f+\delta_{\text{allowed}}$, we need $w'(S) \geq t'+f'$. This is required as the DKG algorithm requires a liveness of $t'+f'$.

4. **Standard DKG constraint**: $0 < f' < t'$, and $t' + 2f' \leq W'$

## Relation between $\beta$ and $\delta_{\text{allowed}}$

**From f-constraint**: For all $S$ with $w(S) \geq f$, we require $w'(S) \geq f'$. We can fulfill this by setting $f' = (f-\delta)/d$.

**From liveness constraint**: For all $S$ with $w(S) \geq t+f+\delta_{\text{allowed}}$, we need $w'(S) \geq t'+f'$.

Now, $w(S) \geq t+f+\delta_{\text{allowed}}$ implies $w'(S) \geq (t+f+\delta_{\text{allowed}} -\delta)/d = t'+f'+((t+\delta_{\text{allowed}})/d-t')$.

This can be fulfilled by setting $\delta_{\text{allowed}} = t'd - t = (\beta - \alpha)W + 1$.

Thus we can set $\beta = (\delta_{\text{allowed}} - 1)/W + \alpha$.