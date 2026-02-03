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

2. **Liveness**: For all $S$ such that $w(S) \geq t+f+\delta_{\text{allowed}}$, we need $w'(S) \geq t'+f'$. This is required as the DKG algorithm requires a liveness of $t'+f'$.

3. **f-constraint**: For all $S$ such that $w(S) \leq f - \delta_f$ (where $\delta_f$ is a parameter), we have $w'(S) \leq f'$.

4. **Standard DKG constraint**: $0 < f' < t'$, and $t' + 2f' \leq W'$

## Tight Bounds for $f'$

Using the inequalities above, we derive tight bounds for $f'$ in terms of $W$, $t$, $f$, $\beta$, $W'$, $t'$, and $\delta$.

**From constraint 3**: For all $S$ with $w(S) \leq f - \delta_f$, we require $w'(S) \leq f'$.

To find the maximum possible $w'(S)$ given $w(S) \leq f - \delta_f$, we use the lower bound $w(S) \geq w'(S) \cdot d - \delta$:
$$
w(S) \leq f - \delta_f \implies w'(S) \cdot d - \delta \leq w(S) \leq f - \delta_f
$$

Therefore:
$$
w'(S) \leq \frac{f - \delta_f + \delta}{d}
$$

To ensure $w'(S) \leq f'$ for all such $S$, we need:
$$
f' \geq \frac{f - \delta_f + \delta}{d}
$$

**From constraint 2**: For all $S$ with $w(S) \geq t+f+\delta_{\text{allowed}}$, we require $w'(S) \geq t'+f'$.

To find the minimum possible $w'(S)$ given $w(S) \geq t+f+\delta_{\text{allowed}}$, we use the upper bound $w(S) \leq w'(S) \cdot d + \delta$:
$$
w(S) \leq w'(S) \cdot d + \delta
$$

If $w(S) \geq t+f+\delta_{\text{allowed}}$, then:
$$
w'(S) \cdot d + \delta \geq w(S) \geq t+f+\delta_{\text{allowed}}
$$

Therefore:
$$
w'(S) \geq \frac{t+f+\delta_{\text{allowed}}-\delta}{d}
$$

To ensure $w'(S) \geq t'+f'$ for all such $S$, we need:
$$
\frac{t+f+\delta_{\text{allowed}}-\delta}{d} \geq t'+f'
$$

Rearranging gives an upper bound on $f'$:
$$
f' \leq \frac{t+f+\delta_{\text{allowed}}-\delta}{d} - t'
$$

**Additional constraints**: We also require $0 < f < t$ (given) and $t' + 2f' \leq W'$.

From $t' + 2f' \leq W'$, we get:
$$
f' \leq \frac{W' - t'}{2}
$$

We also require $f' < t'$.

**Combining all constraints, the tight bounds for $f'$ are:**

The upper bound from constraint 2 is $\frac{t+f+\delta_{\text{allowed}}-\delta}{d} - t'$. Additionally, we require $f' < t'$ and $f' \leq \frac{W' - t'}{2}$.

Therefore:
$$
\frac{f - \delta_f + \delta}{d} \leq f' \leq \min\left(\frac{t+f+\delta_{\text{allowed}}-\delta}{d} - t', \frac{W' - t'}{2}, t'-1\right)
$$

These bounds ensure that:
- Constraint 3 is satisfied: all coalitions $S$ with $w(S) \leq f - \delta_f$ have $w'(S) \leq f'$
- Constraint 2 is satisfied: all coalitions $S$ with $w(S) \geq t+f+\delta_{\text{allowed}}$ have $w'(S) \geq t'+f'$
- $0 < f' < t'$ 
- $t' + 2f' \leq W'$ 

