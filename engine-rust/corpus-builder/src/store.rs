// Author: Jeff
// Date: 2026-05-01
// Description: SQLite-backed corpus store — subdomains and paths indexed by domain

use rusqlite::{Connection, Result, params};

pub struct Corpus {
    conn: Connection,
}

impl Corpus {
    pub fn open(path: &str) -> Result<Self> {
        let conn = Connection::open(path)?;
        conn.execute_batch("
            CREATE TABLE IF NOT EXISTS subdomains (
                domain    TEXT NOT NULL,
                subdomain TEXT NOT NULL,
                source    TEXT NOT NULL DEFAULT 'unknown',
                seen_at   INTEGER DEFAULT (strftime('%s', 'now')),
                PRIMARY KEY (domain, subdomain)
            );
            CREATE TABLE IF NOT EXISTS paths (
                domain   TEXT NOT NULL,
                path     TEXT NOT NULL,
                seen_at  INTEGER DEFAULT (strftime('%s', 'now')),
                PRIMARY KEY (domain, path)
            );
            CREATE INDEX IF NOT EXISTS idx_sub_domain ON subdomains(domain);
            CREATE INDEX IF NOT EXISTS idx_path_domain ON paths(domain);
        ")?;
        Ok(Self { conn })
    }

    // Insert subdomain; silently ignores duplicates
    pub fn insert_subdomain(&self, domain: &str, subdomain: &str, source: &str) -> Result<()> {
        self.conn.execute(
            "INSERT OR IGNORE INTO subdomains (domain, subdomain, source) VALUES (?1, ?2, ?3)",
            params![domain, subdomain, source],
        )?;
        Ok(())
    }

    // Insert path; silently ignores duplicates
    pub fn insert_path(&self, domain: &str, path: &str) -> Result<()> {
        self.conn.execute(
            "INSERT OR IGNORE INTO paths (domain, path) VALUES (?1, ?2)",
            params![domain, path],
        )?;
        Ok(())
    }

    // Bulk-insert subdomains for one domain inside a single transaction.
    // Without this, each insert is its own autocommit fsync — orders of
    // magnitude slower for large mining runs.
    pub fn insert_subdomains_batch(
        &mut self,
        domain: &str,
        subdomains: &[String],
        source: &str,
    ) -> Result<()> {
        let tx = self.conn.transaction()?;
        {
            let mut stmt = tx.prepare(
                "INSERT OR IGNORE INTO subdomains (domain, subdomain, source) VALUES (?1, ?2, ?3)",
            )?;
            for sub in subdomains {
                stmt.execute(params![domain, sub, source])?;
            }
        }
        tx.commit()
    }

    // Bulk-insert paths for one domain inside a single transaction
    pub fn insert_paths_batch(&mut self, domain: &str, paths: &[String]) -> Result<()> {
        let tx = self.conn.transaction()?;
        {
            let mut stmt = tx.prepare(
                "INSERT OR IGNORE INTO paths (domain, path) VALUES (?1, ?2)",
            )?;
            for path in paths {
                stmt.execute(params![domain, path])?;
            }
        }
        tx.commit()
    }

    // Return all known subdomains for a domain, sorted
    pub fn subdomains(&self, domain: &str) -> Result<Vec<String>> {
        let mut stmt = self.conn.prepare(
            "SELECT subdomain FROM subdomains WHERE domain = ?1 ORDER BY subdomain",
        )?;
        let rows = stmt.query_map(params![domain], |row| row.get(0))?;
        rows.collect()
    }

    // Return all known paths for a domain, sorted by frequency (most common first)
    pub fn paths(&self, domain: &str) -> Result<Vec<String>> {
        let mut stmt = self.conn.prepare(
            "SELECT path FROM paths WHERE domain = ?1 ORDER BY path",
        )?;
        let rows = stmt.query_map(params![domain], |row| row.get(0))?;
        rows.collect()
    }

    // Summary counts for display
    pub fn stats(&self) -> Result<(u64, u64, u64)> {
        let domains: u64 = self.conn.query_row(
            "SELECT COUNT(DISTINCT domain) FROM subdomains", [], |r| r.get(0)
        )?;
        let subdomains: u64 = self.conn.query_row(
            "SELECT COUNT(*) FROM subdomains", [], |r| r.get(0)
        )?;
        let paths: u64 = self.conn.query_row(
            "SELECT COUNT(*) FROM paths", [], |r| r.get(0)
        )?;
        Ok((domains, subdomains, paths))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mem_corpus() -> Corpus {
        Corpus::open(":memory:").unwrap()
    }

    #[test]
    fn insert_and_query_subdomains() {
        let c = mem_corpus();
        c.insert_subdomain("example.com", "api.example.com", "ct_log").unwrap();
        c.insert_subdomain("example.com", "www.example.com", "ct_log").unwrap();
        let subs = c.subdomains("example.com").unwrap();
        assert_eq!(subs.len(), 2);
        assert!(subs.contains(&"api.example.com".to_string()));
    }

    #[test]
    fn duplicate_insert_is_ignored() {
        let c = mem_corpus();
        c.insert_subdomain("example.com", "api.example.com", "ct_log").unwrap();
        c.insert_subdomain("example.com", "api.example.com", "brute").unwrap();
        assert_eq!(c.subdomains("example.com").unwrap().len(), 1);
    }

    #[test]
    fn stats_counts_correctly() {
        let c = mem_corpus();
        c.insert_subdomain("a.com", "www.a.com", "ct_log").unwrap();
        c.insert_subdomain("b.com", "www.b.com", "ct_log").unwrap();
        c.insert_path("a.com", "/admin").unwrap();
        let (domains, subs, paths) = c.stats().unwrap();
        assert_eq!(domains, 2);
        assert_eq!(subs, 2);
        assert_eq!(paths, 1);
    }

    #[test]
    fn batch_insert_writes_all_rows() {
        let mut c = mem_corpus();
        let subs: Vec<String> = (0..100).map(|i| format!("h{i}.example.com")).collect();
        c.insert_subdomains_batch("example.com", &subs, "ct_log").unwrap();
        assert_eq!(c.subdomains("example.com").unwrap().len(), 100);
    }

    #[test]
    fn batch_insert_dedups_against_existing() {
        let mut c = mem_corpus();
        c.insert_subdomain("example.com", "api.example.com", "ct_log").unwrap();
        let more = vec!["api.example.com".into(), "www.example.com".into()];
        c.insert_subdomains_batch("example.com", &more, "brute").unwrap();
        assert_eq!(c.subdomains("example.com").unwrap().len(), 2);
    }
}
