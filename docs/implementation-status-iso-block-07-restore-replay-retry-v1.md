# ISO-BLOCK-07 RinFS restore replay retry

Date: 2026-10-25

## Source change

RinFS now records retryable restore-replay failures separately from sticky
read-only state. I/O and allocation errors during cache quiescence, restore
record synchronization, and mounted replay can be retried through
`rinfs_restore_transaction_mount_recover()` after the failed operation has
released its transaction handle. The recovery path still loads and validates
the pending record before clearing a retry fence; its pre-replay sync
republishes the checksummed phase before replay resumes.

If clearing the record reports an error, RinFS restores the prior in-memory
record and pending bit before fencing the mount. This preserves the replay
anchor when the clear may have reached storage despite the error. Missing or
corrupt records and non-retryable errors remain sticky fail-closed. A lower
layer that has already installed a sticky fence is not downgraded.

## Remaining work

This is source-only. No build, regression, fault-injection, reboot, QEMU, or
physical-media acceptance was run. Validate retry after cache-sync,
quiescence, phase-write, and record-clear failures against fresh remount and
same-mount recovery, including dirty-page retention and corrupt/missing marker
cases. Audit lower-layer sticky fences and process-death recovery. Keep
ISO-BLOCK-07 unchecked.
