use crate::plan::Plan;

pub fn normalize_plan(mut p: Plan) -> Plan {
    p.changes.kernel_cmdline.params.add.sort();
    p.changes.kernel_cmdline.params.remove.sort();

    p.changes.systemd.dropins.sort_by(|a, b| {
        a.unit.cmp(&b.unit).then_with(|| a.name.cmp(&b.name))
    });

    p.rollback.snapshot_paths.sort();
    p.targets.hardware_tags.sort();
    p.verification.preflight_checks.sort();
    p.verification.postflight_checks.sort();

    p
}
