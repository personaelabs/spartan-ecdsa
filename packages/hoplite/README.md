# Hoplite

Hoplite is a Spartan reference implementation designed to be the spec for the Halo2 Spartan verification circuit. [Srinath's Spartan implementation](https://github.com/microsoft/Spartan) uses stateful classes, making it difficult to conceptualize the verification process in terms of circuit constraints. To better understand the verification process, it would be helpful to re-implement the verification in a circuit-like coding manner. For example

- The verification should be stateless (i.e. should employ functional programming)
- The R1CS matrices should be hard-coded into the circuit

Additionally, this reference implementation should include thorough documentation to facilitate collaboration and audits.
