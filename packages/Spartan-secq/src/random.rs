use super::scalar::Scalar;
use super::transcript::ProofTranscript;
use merlin::Transcript;
use rand_core::OsRng;
pub struct RandomTape {
  tape: Transcript,
}

impl RandomTape {
  pub fn new(name: &'static [u8]) -> Self {
    let tape = {
      let mut rng = OsRng::default();
      let mut tape = Transcript::new(name);
      tape.append_scalar(b"init_randomness", &Scalar::random(&mut rng));
      tape
    };
    Self { tape }
  }

  pub fn random_scalar(&mut self, label: &'static [u8]) -> Scalar {
    self.tape.challenge_scalar(label)
  }

  pub fn random_vector(&mut self, label: &'static [u8], len: usize) -> Vec<Scalar> {
    self.tape.challenge_vector(label, len)
  }
}
