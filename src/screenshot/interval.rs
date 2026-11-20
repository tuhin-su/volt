use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::time::sleep;

use crate::evidence::EvidenceVault;
use crate::screenshot::capture::ScreenshotEngine;

pub struct IntervalScreenshotWorker {
    engine: ScreenshotEngine,
    vault: Arc<EvidenceVault>,
    interval: Duration,
    running: Arc<AtomicBool>,
}

impl IntervalScreenshotWorker {
    pub fn new(
        engine: ScreenshotEngine,
        vault: Arc<EvidenceVault>,
        interval_secs: u64,
        running: Arc<AtomicBool>,
    ) -> Self {
        Self {
            engine,
            vault,
            interval: Duration::from_secs(interval_secs),
            running,
        }
    }

    pub async fn run(self) {
        tracing::info!(
            "Screenshot interval worker started (every {:?})",
            self.interval
        );
        while self.running.load(Ordering::Relaxed) {
            sleep(self.interval).await;
            if !self.running.load(Ordering::Relaxed) {
                break;
            }

            match self.engine.capture("interval", None) {
                Ok(rec) => {
                    let _ = self.vault.record_event("SCREENSHOT_INTERVAL", &rec.sha256);
                    tracing::debug!("Captured interval screenshot: {}", rec.filename);
                }
                Err(e) => {
                    tracing::warn!("Interval screenshot failed: {}", e);
                }
            }
        }
        tracing::info!("Screenshot interval worker stopped");
    }
}
