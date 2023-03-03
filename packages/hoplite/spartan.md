# Spartan: Full Protocol Description

_This doc is a work in progress. Do not recommend reading._

_Reference implementation: [Hoplite](https://github.com/personaelabs/Hoplite)_

## Public Setup

- Compute the Pedersen commitment generators using [hash-to-curve](https://github.com/personaelabs/spartan-ecdsa/blob/main/packages/secq256k1/src/hashtocurve.rs).

## Building blocks

$Fp$: The finite field used in the protocol.

### Pedersen commitment

Commitment
Multi-commitments

### proof-of-dot-prod

TBD

### proof-of-equality

TBD

### proof-of-opening

TBD

### Closed form evaluation of a multilinear polynomial

$$
\widetilde{Z}(r_y) = (1 - r_y[0]) ・ \widetilde{w}(r_y[1..]) + r_y[0]・\widetilde{(io, 1)}(r_y[1..]) \\


r_y = (2, 3, 4) \\
\widetilde{w}(x_1, x_2) = x_1 + 2x_2 \\
\widetilde{io}(x_1, x_2, 1) = x_1 + 2x_2 + 3 * 1 \\

\widetilde{Z}(r_y) = (1 - 2)・(3 + 2 * 4) + 2 * (3 +  2 * 4) \\
= -1 * 11 + 2 * 11 = 11


$$

$z = (io, 1, w)$

### zk-sum-check

The details of the zk-sum-check protocol isn't provided in the Spartan paper (it only mentions that it uses methods form prior constructions). The following is a description of the zk-sum-check protocol used in the [original Spartan implementation](https://github.com/microsoft/Spartan).

_Required prior knowledge: [The sum-check protocol](https://zkproof.org/2020/03/16/sum-checkprotocol/)_

**Notations**

- $g$: The polynomial which the sum is proven. We assume that $g$ is a multilinear polynomial (i.e. degree = 1) for simplicity.
- $H$: The sum of evaluates of $g$ over the boolean hypercube.
- $m$: The number of variables in $g$.
- $s$: $\lfloor{log_2{m}}\rfloor$

The protocol consists of $m$ rounds.

**Prover: First round**

In the first round, the prover computes
$$g_1(X) = \sum_{i\in\{0, 1\}^{s-1}} g(X, x_2, ... x_m)$$

In the standard sum-check protocol $g_1$ is sent to the verifier and the verifier checks
$$g_1(0) + g_1(1) \stackrel{?}{=} H$$

and

$$g_1(r_1) \stackrel{?}{=} \sum_{i\in\{0, 1\}^{s-1}} g(r_1, x_2, ... x_m)$$

where $r_1$ is a challenge.
The evaluation of $g$ in the second check is proven in the successive sum-check protocol.

In zk-sum-check, we instead provide the proof of evaluation of $g_1(0)$ $g_1(1)$ and $g_1(r_1)$ without revealing the coefficients of $g_1$, using proof-of-dot-product. For efficiency, we combine the evaluations into a single proof as follows.

First, since we assume $g$ is a multilinear polynomial, we can write

$$g_1(X) = p_1X + p_0$$
where $p_0, p_1 \in Fp$ . $p_1$ is the coefficient and $p_0$ is the y-intercept.

Before running proof-of-dot-prod, the prover must send commitments

$$C_{g1} = \mathrm{multicom}((p_1, p_2), r_{g1})$$
$$C_{eval} = \mathrm{com}(g_1(r), r_{eval})$$
$$C_{sum} = \mathrm{com}((g_1(0) + g_1(1), r_{sum}))$$  
to the verifier.

The prover computes the weighted sum of and $g_1(0) + g_1(1)$ and $g(r_1)$ using weights $w_0, w_1 \in F_p$ sent from the verifier as
$$(g_1(0) + g_1(1)) * w_0 + g_1(r_1) * w_1$$
$$= p_1w_0 + 2p_0w_0 + p_1w_1r_1 + p_0w_1$$
$$= p_1(w_0 + r_1w_1) + p_0(2w_0 + w_1)$$

Thus, we use proof-of-dot-prod to prove
$$(w_0 + r_1w_1, 2w_0 + w_1) \cdot (p_1, p_0) = (g_1(0) + g_1(1)) * w_0 + g_1(r_1) * w_1$$

Now we proceed to the rest of the rounds

### Prover: Rest of the rounds

The rest of the rounds proceed similary as the first round except that prover proves the evaluations of the polynomial
$$g_i(X) = \sum_{b\in \{0, 1\}^{s-1-i}}g(r_1, ...r_{i-1}, X, x_{i+1},...,{x_m})$$

### Prover: Last round

In the standard sum-check protocol, the verifier queries $g(r_1, ... ,r_m)$ using the oracle of $g$. and checks the result is equal to $g_m(r_m)$. In the Spartan's version of zk-sum-check, the prover instead provides the proof of evaluation of $g(r_1, ... ,r_m)$ **doing another zk-sum-check**. The details of this second zk-sum-check protocol is described later in this doc.

### Verification

The verifier receives

- Claimed sum $H$
- proof-of-dot-products $\{dp_1, dp_2, ... dp_m\}$

Recall that the dot-product relation is
$$(w_0 + r_1w_1, 2w_0 + w_1) \cdot (p_1, p_0) = (g_1(0) + g_1(1)) * w_0 + g_1(r_1) * w_1$$

The verifier have access to $r_1, w_0, w_1$ and the commitments $Cy, Cx, C_{eval}$..
The verifier computes the **target commitment**
$$Ct = C_{sum} * w_0 + C_{eval} * w_1$$

and checks the dot product proof

$$
TBD
$$

## Main Protocol

Now we'll see how Spartan (_SpartanNIZK to be precise!_) uses the above building blocks to construct an NIZK for R1CS satisfiability.

---

**Below this is especially WIP! A lot of incomplete stuff!**

1.$P$ Commit the witness polynomial

- $P: C = PC.commit(pp, \bar{w}, S)$
  send $C$ to the verifier 2.$V$ Randomly sample a challenge $\tau$ to query $\mathbb{g}$
- $\tau \in \mathbb{F^{log_m}}$ and send $\tau$ to the prover

4. Let $T_1 = 0$,
5. $V: sample r_x \in \mathbb{F^{u1}}$
6. $G_{io},\tau(x) = (\sum_{y \in \{0, 1\}^s} \widetilde{A}(x, y)\widetilde{Z}(y) + \sum_{y \in \{0, 1\}^s}\widetilde{B}(x, y)\widetilde{Z}(y) - \sum_{y \in \{0, 1\}^s}\widetilde{C}(x, y)\widetilde{Z}(y))\widetilde{eq}(x, \tau)$

$\sum_{x \in \{0, 1\}^s} G_{io},\tau(x) = 0$ for a random $\tau$ iff all the constraints are satisfied

- Run sumcheck on $G_{io},\tau(x)$
- At the last step of the sum check where the verifier queries $G_{io}, \tau(x)$, we use the following sub-protocol.

Define

- $\bar{A}(x) = \sum_{y \in \{0, 1\}^s} \widetilde{A}(x, y)$
- $\bar{B}(x) = \sum_{y \in \{0, 1\}^s} \widetilde{B}(x, y)$
- $\bar{C}(x) = \sum_{y \in \{0, 1\}^s} \widetilde{C}(x, y)$
- $M_{r_x}(y) = r_A *  \widetilde{A}(x, y)\widetilde{Z}(y) + r_B *  \widetilde{B}(x, y)\widetilde{Z}(y) + r_C *  \widetilde{C}(x, y)\widetilde{Z}(y)$

Verify that $\bar{A}(x) * \bar{B}(x) - \bar{C}(x) = 0$

Run the sum-check protocol to verify $M_{r_x}(y)$

- $P$
  - Send evaluations $v_A = \bar{A}(r_x), v_B = \bar{B}(r_x), v_C = \bar{C}(r_x)$ to the verifier.
  - Send the opening $v_Z = Z(r_x)$ to the verifier
- $V$
  - Check $(v_A + v_B - v_C) * eq(r_x, \tau) = e_x$
    The last part of the second sum-check protocol
  - $v_1 = \widetilde{A}(r_x, r_y)$
  - $v_2 = \widetilde{B}(r_x, r_y)$
  - $v_3 = \widetilde{C}(r_x, r_y)$
  - check taht $(r_A * v_1 + r_B * v_2 + r_C * v_3) * v_z = e_y$

In the last round, the verifier needs to query $g(x)$. We will construct a protocol that is specific to Spartan that allows us to query $g(x)$ in zero-knowledge.

### The second zk-sum-check

Instead of constructing a generic method to evalute $g(X)$ in zk, we focus on $g(X)$ which is specific to Spartan. Recall that we want to prove the sum of
$$G_{io},\tau(x) = (\sum_{y \in \{0, 1\}^s} \widetilde{A}(x, y)\widetilde{Z}(y) + \sum_{y \in \{0, 1\}^s}\widetilde{B}(x, y)\widetilde{Z}(y) - \sum_{y \in \{0, 1\}^s}\widetilde{C}(x, y)\widetilde{Z}(y))\widetilde{eq}(x, \tau)$$

By looking at the terms of $\widetilde{F}(x)$, each term is in a form that is suitable to apply the SumCheck protocol. Assume for now that we can check the validity of each term (i.e each sum of $\widetilde{A}(x, y)\widetilde{Z}$, $\widetilde{B}(x, y)\widetilde{Z}$ and $\widetilde{C}(x, y)\widetilde{Z}$), we can check the relation of the sums as follows.

Define

- $\bar{A}(x) = \sum_{y \in \{0, 1\}^s} \widetilde{A}(x, y)$
- $\bar{B}(x) = \sum_{y \in \{0, 1\}^s} \widetilde{B}(x, y)$
- $\bar{C}(x) = \sum_{y \in \{0, 1\}^s} \widetilde{C}(x, y)$

Now, recall that we want to evaluate $G_{io},\tau(x)$ only at the last round of the zk-sum-check over the all round_challenges $r_x = \{r_1, r_2, ... r_m\}$.

Hence the prover can provide the evaluations $v_A, v_B$ and $v_C$ to the verifier.
$$v_A = \bar{A}(r_x), v_B = \bar{B}(r_x), v_C = \bar{C}(r_x)$$
The verifier checks that the evaluation of $G_{io}$ is equal to the evaluation of $g_m(r_m)$
$$g_m(r_m) \stackrel{?}{=} (v_A + v_B - v_C)\widetilde{eq}(r_x, \tau)$$

The verifier also needs to check the validity of $\bar{A}(x), \bar{B}(x), \bar{C}(x)$.
This is where the second zk-sum-check comes in.

We can check each term individually, but for efficiency, we use a random linear combination of the three terms.

and sample challnges $r_A, r_B, r_C \in_R F_p$ to compute the random linear combination

$$
\widetilde{M}(x) \\ = r_A \bar{A}(r_x) + r_B\bar{B}(r_x) + r_C\bar{C}(r_x)  \\
= (r_A\widetilde{A}(r_x, r_y) + r_B\widetilde{B}(r_x, r_y) + r_C\widetilde{C}(r_x, r_y))\widetilde{Z}(r_x, r_y)
$$

At the end of the second zk-sum-check, the verifier needs to evaluate $\widetilde{Z}(r_x, r_y)$. In order to evaluate without knowing the coefficients, we use the proof_log-of-dot-prod protocol. Note that the prover needs to commit to $Z(x)$ at the beginning so it cannot just come up with a $Z(x)$ that passes the final check of the second zk-sum-check.
