// Author: Jeff
// Date: 2026-05-28
// Description: Platform-neutral program authorization snapshot for active testing policy
// Notes: Active autonomous actions require a current snapshot before network traffic

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProgramRulesSnapshot {
    pub captured_at: OffsetDateTime,
    pub expires_at: OffsetDateTime,
    pub automation_allowed: bool,
    pub source: String,
    #[serde(default)]
    pub notes: Vec<String>,
}

impl ProgramRulesSnapshot {
    // Return true when the rules artifact is still current
    pub fn is_current_at(&self, now: OffsetDateTime) -> bool {
        self.captured_at <= now && now < self.expires_at
    }
}
