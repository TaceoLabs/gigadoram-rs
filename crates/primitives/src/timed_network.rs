use std::{
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use bytes::Bytes;
use mpc_net::{ConnectionStats, Network};

#[derive(Clone, Debug, Default)]
pub struct CommunicationTimer(Arc<Mutex<CommunicationState>>);

#[derive(Debug, Default)]
struct CommunicationState {
    active: usize,
    started: Option<Instant>,
    elapsed: Duration,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct TimingBreakdown {
    pub total: Duration,
    pub communication: Duration,
}

impl CommunicationTimer {
    pub fn elapsed(&self) -> Duration {
        let state = self.0.lock().expect("communication timer poisoned");
        state
            .started
            .map_or(state.elapsed, |start| state.elapsed + start.elapsed())
    }

    fn start(&self) {
        let mut state = self.0.lock().expect("communication timer poisoned");
        if state.active == 0 {
            state.started = Some(Instant::now());
        }
        state.active += 1;
    }

    fn stop(&self) {
        let mut state = self.0.lock().expect("communication timer poisoned");
        state.active -= 1;
        if state.active == 0 {
            let elapsed = state.started.take().unwrap().elapsed();
            state.elapsed += elapsed;
        }
    }
}

#[derive(Debug)]
pub struct TimedNetwork<N> {
    inner: N,
    timer: CommunicationTimer,
}

impl<N> TimedNetwork<N> {
    pub fn new(inner: N, timer: CommunicationTimer) -> Self {
        Self { inner, timer }
    }

    fn timed<T>(&self, operation: impl FnOnce(&N) -> eyre::Result<T>) -> eyre::Result<T> {
        self.timer.start();
        let result = operation(&self.inner);
        self.timer.stop();
        result
    }
}

impl<N: Network> Network for TimedNetwork<N> {
    fn id(&self) -> usize {
        self.inner.id()
    }

    fn send(&self, to: usize, data: Bytes) -> eyre::Result<()> {
        self.timed(|inner| inner.send(to, data))
    }

    fn recv(&self, from: usize) -> eyre::Result<Bytes> {
        self.timed(|inner| inner.recv(from))
    }

    fn flush(&self) -> eyre::Result<()> {
        self.timed(Network::flush)
    }

    fn get_connection_stats(&self) -> ConnectionStats {
        self.inner.get_connection_stats()
    }
}

#[macro_export]
macro_rules! network_phase {
    ($timing:expr, $field:ident, $body:expr) => {{
        let wall = std::time::Instant::now();
        let communication = $timing
            .as_ref()
            .map(|timing| timing.communication_timer.elapsed())
            .unwrap_or_default();
        let result = $body;
        if let Some(timing) = &mut $timing {
            timing.$field.total += wall.elapsed();
            timing.$field.communication += timing
                .communication_timer
                .elapsed()
                .saturating_sub(communication);
        }
        result
    }};
}

#[macro_export]
macro_rules! local_phase {
    ($timing:expr, $field:ident, $body:expr) => {{
        let start = std::time::Instant::now();
        let result = $body;
        if let Some(timing) = &mut $timing {
            timing.$field += start.elapsed();
        }
        result
    }};
}
