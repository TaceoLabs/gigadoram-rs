use std::time::Duration;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Timings {
    phases: Vec<PhaseTiming>,
}

impl Timings {
    pub fn record(&mut self, phase: impl Into<String>, elapsed: Duration) {
        self.phases.push(PhaseTiming {
            phase: phase.into(),
            elapsed,
        });
    }

    pub fn phases(&self) -> &[PhaseTiming] {
        &self.phases
    }

    pub fn total(&self) -> Duration {
        self.phases
            .iter()
            .map(|phase| phase.elapsed)
            .sum::<Duration>()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PhaseTiming {
    pub phase: String,
    pub elapsed: Duration,
}
