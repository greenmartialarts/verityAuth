use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

pub struct IpRateLimiter {
    attempts: Mutex<HashMap<IpAddr, Vec<Instant>>>,
}

impl IpRateLimiter {
    pub fn new() -> Self {
        Self {
            attempts: Mutex::new(HashMap::new()),
        }
    }

    pub fn check_rate_limit(&self, ip: IpAddr) -> bool {
        let mut map = self.attempts.lock().unwrap();
        let now = Instant::now();
        let one_minute_ago = now - Duration::from_secs(60);

        let ip_attempts = map.entry(ip).or_insert_with(Vec::new);
        
        // Retain only attempts within the last 60 seconds
        ip_attempts.retain(|&time| time > one_minute_ago);

        if ip_attempts.len() >= 10 {
            false
        } else {
            ip_attempts.push(now);
            true
        }
    }
}

pub fn get_failed_delay(failures: i32) -> Duration {
    if failures >= 15 {
        Duration::from_secs(5)
    } else if failures >= 10 {
        Duration::from_secs(2)
    } else if failures >= 5 {
        Duration::from_millis(500)
    } else {
        Duration::from_millis(0)
    }
}
