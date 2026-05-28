use std::{
    cell::RefCell,
    collections::HashMap,
    time::{Duration, Instant},
};

use monoio::net::TcpStream;

use crate::boringtls::BoringStream;
use crate::http::h1::H1Connection;

const MAX_POOL_PER_KEY: usize = 128;
const MAX_IDLE: Duration = Duration::from_secs(30);

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PoolKey {
    host: String,
    port: u16,
    tls: bool,
}

impl PoolKey {
    pub fn new(host: String, port: u16, tls: bool) -> Self {
        Self {
            host: host.to_ascii_lowercase(),
            port,
            tls,
        }
    }
}

pub enum PooledConnection {
    Http(H1Connection<TcpStream>),
    Https(H1Connection<BoringStream<TcpStream>>),
}

struct PoolEntry {
    conn: PooledConnection,
    last_used: Instant,
}

pub struct ProxyPool {
    entries: HashMap<PoolKey, Vec<PoolEntry>>,
}

impl ProxyPool {
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }

    pub fn take(&mut self, key: &PoolKey) -> Option<PooledConnection> {
        let Some(entries) = self.entries.get_mut(key) else {
            return None;
        };

        let now = Instant::now();
        while let Some(entry) = entries.pop() {
            if now.duration_since(entry.last_used) <= MAX_IDLE {
                if entries.is_empty() {
                    self.entries.remove(key);
                }
                return Some(entry.conn);
            }
        }

        self.entries.remove(key);
        None
    }

    pub fn put(&mut self, key: PoolKey, conn: PooledConnection) {
        let entries = self.entries.entry(key).or_default();
        if entries.len() >= MAX_POOL_PER_KEY {
            return;
        }
        entries.push(PoolEntry {
            conn,
            last_used: Instant::now(),
        });
    }
}

// Keep the pool thread-local since monoio sockets are !Send.
thread_local! {
    static PROXY_POOL: RefCell<ProxyPool> = RefCell::new(ProxyPool::new());
}

pub fn take_connection(key: &PoolKey) -> Option<PooledConnection> {
    PROXY_POOL.with(|pool| pool.borrow_mut().take(key))
}

pub fn return_connection(key: PoolKey, conn: PooledConnection) {
    PROXY_POOL.with(|pool| pool.borrow_mut().put(key, conn))
}
