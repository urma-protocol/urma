#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Progress {
    pub headers_synced: u64,
    pub headers_target: u64,
    pub peers_connected: usize,
    pub synced: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LightSync {
    Absent,
    Cold(Progress),
    Running(Progress),
}
