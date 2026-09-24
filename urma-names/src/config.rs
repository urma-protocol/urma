use crate::{name::Name, state::NameState};
use std::collections::BTreeMap;

pub fn state_of(names: &BTreeMap<Name, NameState>, name: &Name) -> NameState {
    match names.get(name) {
        Some(state) => state.clone(),
        None => NameState::unbound(),
    }
}
