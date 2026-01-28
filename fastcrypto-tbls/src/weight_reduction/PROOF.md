# Liveness Proof for Weight Reduction

## Definitions

- **Original weights**: $w_i$ for $i = 1, \ldots, n$
- **Reduced weights**: $w'_i$ for $i = 1, \ldots, n$
- **Total original weight**: $W = \sum_{i=1}^n w_i$
- **Total reduced weight**: $W' = \sum_{i=1}^n w'_i$
- **Effective divisor**: $d = W / W'$ (exact ratio, no floor)
- **Precision loss**: $\delta = \sum_{i=1}^n \max(w_i - w'_i \cdot d, 0)$

## Key Property to Prove

**For any coalition $S \subseteq \{1, \ldots, n\}$:**
$$
w(S) - w'(S) \cdot d \leq \delta
$$

Where:
- $w(S) = \sum_{i \in S} w_i$
- $w'(S) = \sum_{i \in S} w'_i$

## Proof

For any subset $S$:

$$
\begin{aligned}
w(S) - w'(S) \cdot d &= \sum_{i \in S} (w_i - w'_i \cdot d) \\
&\leq \sum_{i \in S} \max(w_i - w'_i \cdot d, 0) \\
&\leq \sum_{i=1}^n \max(w_i - w'_i \cdot d, 0) \\
&= \delta
\end{aligned}
$$

This is the precision loss we calculate in `weight_reduction_checks.rs`.

## DKG Constraints

Let $W$ and $t$ be the total weight and threshold of the original nodes, and $W'$ and $t'$ be the total weight and threshold of the reduced nodes. Set $f = (W-t)/2$.

We want two constraints:

1. **Safety**: For all $S$ such that $w(S) \leq t-1$, we want to have $w'(S) < \beta W'$. This is guaranteed by supplying $\alpha = (t-1)/W$ and $\beta$ to the super swiper algorithm and then setting threshold $t' = \beta W'$. The dealer polynomial is set to be of degree $t'-1$. Also set $f' = (W'-t')/2$.

2. **Liveness**: For all $S$ such that $w(S) \geq t+f+\delta_{\text{allowed}}$, we have $w'(S) \geq t'+f'$. This is required as the DKG algorithm requires a liveness of $t'+f'$.

Now, we know $w(S) \leq w'(S).d + \delta$, so we can substitute it into the liveness condition:
$$w(S) \geq t+f+\delta_{\text{allowed}} \implies w'(S).d + \delta \geq t+f + \delta_{\text{allowed}}$$
Thus our target inequality is satisfied when: $t+f + \delta_{\text{allowed}} \geq (t'+f').d + \delta$.

This is the condition we check in `nodes.rs`. We start from $\beta = 1/2$ and decrease it until the condition is met.
