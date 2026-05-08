#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Gate {
    Xor { lhs: usize, rhs: usize },
    And { lhs: usize, rhs: usize },
    Not { input: usize },
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Circuit {
    pub name: String,
    pub input_wires: usize,
    pub gates: Vec<Gate>,
    pub output_wires: Vec<usize>,
}

impl Circuit {
    pub fn new(name: impl Into<String>, input_wires: usize) -> Self {
        Self {
            name: name.into(),
            input_wires,
            gates: Vec::new(),
            output_wires: Vec::new(),
        }
    }

    pub fn add_gate(&mut self, gate: Gate) -> usize {
        let wire = self.input_wires + self.gates.len();
        self.gates.push(gate);
        wire
    }

    pub fn set_outputs(&mut self, wires: impl Into<Vec<usize>>) {
        self.output_wires = wires.into();
    }
}
