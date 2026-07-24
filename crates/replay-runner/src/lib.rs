/*******************************************************************
 * Filename:        lib.rs
 * Author:          Jeff
 * Date:            2026-07-24
 * Description:     replay-runner — the only crate that sends live traffic
 *                  for the adaptive hunt. Executes an already-approved,
 *                  in-scope replay plan and records exactly what was sent
 *                  and received; refuses anything not marked executable.
 * Notes:           Scaffold only in Task 0; the policy-gated runner lands
 *                  in Task 4 behind failing tests against a loopback server.
 *******************************************************************/

// Module scaffold — the live runner arrives in Task 4
