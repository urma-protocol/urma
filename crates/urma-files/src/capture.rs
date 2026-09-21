use crate::catalog::Content;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use urma_runtime::error::{Error, ensure};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Capture {
    Files,
    Session {
        id: String,
        state: SessionState,
        assertions: BTreeMap<String, String>,
        originals: Vec<String>,
        derivatives: Vec<Derivative>,
    },
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SessionState {
    Open,
    Closed,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Derivative {
    pub original: String,
    pub derived: String,
    pub transformation: String,
}

impl Capture {
    pub fn validate(&self, schema: &str, entries: &BTreeMap<&str, &Content>) -> Result<(), Error> {
        match self {
            Self::Files => ensure!(
                schema == "urma.private-files",
                "capture profile requires session metadata"
            ),
            Self::Session {
                id,
                state: _state,
                assertions,
                originals,
                derivatives,
            } => {
                ensure!(
                    schema == "urma.capture-evidence",
                    "capture semantics require capture profile"
                );
                ensure!(
                    !id.is_empty() && id.len() <= 256,
                    "invalid capture session ID"
                );
                ensure!(assertions.len() <= 64, "too many capture assertions");
                for (name, value) in assertions {
                    ensure!(
                        !name.is_empty() && name.len() <= 64 && value.len() <= 4096,
                        "capture assertion exceeds limits"
                    );
                }
                validate_members(entries, originals, derivatives)?;
            }
        }
        Ok(())
    }
}

fn validate_members(
    entries: &BTreeMap<&str, &Content>,
    originals: &[String],
    derivatives: &[Derivative],
) -> Result<(), Error> {
    ensure!(
        !originals.is_empty(),
        "capture session requires an original"
    );
    let mut members = BTreeSet::new();
    for original in originals {
        ensure!(
            matches!(entries.get(original.as_str()), Some(Content::File { .. })),
            "capture original must reference a nonempty file"
        );
        ensure!(
            members.insert(original.as_str()),
            "duplicate capture original"
        );
    }
    for link in derivatives {
        ensure!(
            originals.contains(&link.original),
            "derivative must reference a declared original"
        );
        ensure!(
            matches!(
                entries.get(link.derived.as_str()),
                Some(Content::File { .. })
            ),
            "derivative must reference a nonempty file"
        );
        ensure!(
            members.insert(link.derived.as_str()),
            "duplicate or cyclic derivative relationship"
        );
        ensure!(
            !link.transformation.is_empty() && link.transformation.len() <= 4096,
            "derivative transformation assertion required"
        );
    }
    for (path, content) in entries {
        if matches!(content, Content::File { .. } | Content::EmptyFile { .. }) {
            ensure!(
                members.contains(path),
                "capture file must be an original or derivative"
            );
        }
    }
    Ok(())
}
