/*******************************************************************
 * Filename:        attack.rs
 * Author:          Jeff
 * Date:            2026-05-09
 * Description:     Attack mode implementations — Sniper, Battering Ram,
 *                  Pitchfork, and Cluster Bomb — each producing a sequence
 *                  of (label, payload_row) pairs for the fuzzer loop
 * Notes:           These mirror Burp Intruder's attack modes.
 *                  Sniper: one position at a time, others hold their original value.
 *                  Battering Ram: same payload in all positions simultaneously.
 *                  Pitchfork: advance all payload lists in parallel; stops at shortest.
 *                  Cluster Bomb: cartesian product of all payload lists.
 *                  "payload_row" is a Vec<&str> indexed to align with template positions.
 *******************************************************************/

use itertools::Itertools;

// One generated request from an attack mode: human label + per-position payloads
#[derive(Debug, Clone)]
pub struct AttackRequest {
    // human-readable label for the result table (e.g. "pos=1 payload=admin")
    pub label: String,
    // payload for each template position in order; empty string = use original marker name
    pub payloads: Vec<String>,
}

// Generate Sniper attack requests: iterate each position independently, others blank
// Total requests = positions × max(payload_list_length)
pub fn sniper(positions: &[String], payload_lists: &[Vec<String>]) -> Vec<AttackRequest> {
    let list = payload_lists.first().cloned().unwrap_or_default();
    let mut out = Vec::new();

    for (pos_idx, pos_name) in positions.iter().enumerate() {
        for payload in &list {
            // build a row: payload only at this position, empty elsewhere
            let mut row = vec![String::new(); positions.len()];
            row[pos_idx] = payload.clone();
            out.push(AttackRequest {
                label: format!("pos={pos_name} payload={payload}"),
                payloads: row,
            });
        }
    }
    out
}

// Generate Battering Ram requests: same payload inserted into every position at once
// Total requests = payload_list_length
pub fn battering_ram(positions: &[String], payload_lists: &[Vec<String>]) -> Vec<AttackRequest> {
    let list = payload_lists.first().cloned().unwrap_or_default();
    list.iter().map(|payload| AttackRequest {
        label: format!("payload={payload}"),
        payloads: vec![payload.clone(); positions.len()],
    }).collect()
}

// Generate Pitchfork requests: advance all lists simultaneously, stop at shortest
// Total requests = min(payload_list_length across all lists)
pub fn pitchfork(positions: &[String], payload_lists: &[Vec<String>]) -> Vec<AttackRequest> {
    if payload_lists.is_empty() { return vec![]; }
    let min_len = payload_lists.iter().map(|l| l.len()).min().unwrap_or(0);
    (0..min_len).map(|i| {
        let payloads: Vec<String> = payload_lists.iter().map(|l| l[i].clone()).collect();
        // pad if fewer lists than positions
        let mut row = payloads;
        row.resize(positions.len(), String::new());
        AttackRequest {
            label: format!("row={i} payloads={}", row.join(",")),
            payloads: row,
        }
    }).collect()
}

// Generate Cluster Bomb requests: cartesian product of all payload lists
// Total requests = product of all list lengths — can explode; warn if > 10 000
pub fn cluster_bomb(positions: &[String], payload_lists: &[Vec<String>]) -> Vec<AttackRequest> {
    if payload_lists.is_empty() { return vec![]; }

    // compute total request count for early warning
    let total: usize = payload_lists.iter().map(|l| l.len()).product();
    if total > 10_000 {
        eprintln!("  [warn] cluster-bomb will generate {total} requests — this may take a long time");
    }

    // build cartesian product iteratively using itertools
    let product: Vec<Vec<&str>> = payload_lists
        .iter()
        .map(|l| l.iter().map(|s| s.as_str()).collect::<Vec<_>>())
        .multi_cartesian_product()
        .collect();

    product.into_iter().map(|combo| {
        let mut row: Vec<String> = combo.iter().map(|s| s.to_string()).collect();
        row.resize(positions.len(), String::new());
        AttackRequest {
            label: format!("combo={}", combo.join(",")),
            payloads: row,
        }
    }).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn positions() -> Vec<String> { vec!["id".into(), "role".into()] }
    fn single_list() -> Vec<Vec<String>> { vec![vec!["1".into(), "2".into(), "3".into()]] }
    fn two_lists() -> Vec<Vec<String>> {
        vec![vec!["a".into(), "b".into()], vec!["x".into(), "y".into()]]
    }

    #[test]
    fn sniper_one_position_at_a_time() {
        let reqs = sniper(&positions(), &single_list());
        // 2 positions × 3 payloads = 6 requests
        assert_eq!(reqs.len(), 6);
        // first 3 should target position "id"
        assert!(reqs[0].label.contains("pos=id"));
        // next 3 should target "role"
        assert!(reqs[3].label.contains("pos=role"));
    }

    #[test]
    fn sniper_non_active_positions_are_empty() {
        let reqs = sniper(&positions(), &single_list());
        // when position 0 is active, position 1 must be empty
        assert_eq!(reqs[0].payloads[1], "");
    }

    #[test]
    fn battering_ram_same_payload_in_all_positions() {
        let reqs = battering_ram(&positions(), &single_list());
        assert_eq!(reqs.len(), 3);
        for req in &reqs {
            assert_eq!(req.payloads[0], req.payloads[1]);
        }
    }

    #[test]
    fn pitchfork_stops_at_shortest_list() {
        let lists = vec![
            vec!["a".into(), "b".into(), "c".into()],
            vec!["x".into(), "y".into()],
        ];
        let reqs = pitchfork(&positions(), &lists);
        assert_eq!(reqs.len(), 2);  // stops at len 2 (shortest)
        assert_eq!(reqs[0].payloads, vec!["a", "x"]);
    }

    #[test]
    fn cluster_bomb_cartesian_product() {
        let reqs = cluster_bomb(&positions(), &two_lists());
        // 2 × 2 = 4 combinations
        assert_eq!(reqs.len(), 4);
        // first should be a,x
        assert!(reqs[0].payloads.contains(&"a".to_string()));
        assert!(reqs[0].payloads.contains(&"x".to_string()));
    }
}
