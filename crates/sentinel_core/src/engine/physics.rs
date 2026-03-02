use crate::engine::EngineEvent;
use crate::model::{ProcRow, Snapshot};
use std::time::Duration;
use sysinfo::{CpuRefreshKind, Disks, MemoryRefreshKind, RefreshKind, System};
use tokio::sync::mpsc;

/// Runs sysinfo sampling on a blocking thread and publishes snapshots.
/// This is a minimal stub; tiered clocks can be layered on (fast/slow).
pub async fn run_physics(tx: mpsc::Sender<EngineEvent>) {
    let _ = tokio::task::spawn_blocking(move || {
        let mut sys = System::new_with_specifics(
            RefreshKind::new()
                .with_cpu(CpuRefreshKind::everything())
                .with_memory(MemoryRefreshKind::everything())
                .with_processes(sysinfo::ProcessRefreshKind::everything()),
        );
        let mut disks = Disks::new_with_refreshed_list();

        loop {
            sys.refresh_cpu();
            sys.refresh_memory();
            sys.refresh_processes();
            disks.refresh();

            let (total_disk, free_disk) = disks
                .list()
                .iter()
                .fold((0u64, 0u64), |(total, free), disk| {
                    (total + disk.total_space(), free + disk.available_space())
                });

            let disk_free_pct = if total_disk > 0 {
                Some((free_disk as f32 / total_disk as f32) * 100.0)
            } else {
                None
            };

            let mut rows: Vec<ProcRow> = sys
                .processes()
                .values()
                .map(|p| ProcRow {
                    pid: p.pid().as_u32(),
                    name: p.name().to_string(),
                    cpu: p.cpu_usage(),
                    mem: p.memory() as f32 / 1024.0 / 1024.0,
                })
                .collect();

            // Sort by CPU desc, then PID asc for deterministic tie-breaks.
            rows.sort_by(|a, b| {
                b.cpu
                    .partial_cmp(&a.cpu)
                    .unwrap_or(std::cmp::Ordering::Equal)
                    .then_with(|| a.pid.cmp(&b.pid))
                    .then_with(|| a.name.cmp(&b.name))
            });
            rows.truncate(40);

            let snap = Snapshot {
                cpu: sys.global_cpu_info().cpu_usage(),
                mem_gb: sys.used_memory() as f32 / 1024.0 / 1024.0 / 1024.0,
                disk_free_pct,
                procs: rows,
                plugins: vec![],
            };

            if tx.blocking_send(EngineEvent::Physics(snap)).is_err() {
                break;
            }

            std::thread::sleep(Duration::from_millis(1000));
        }
    })
    .await;
}
