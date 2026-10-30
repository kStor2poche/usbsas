use crate::{Result, seccomp};
use std::os::unix::io::RawFd;
use syscallz::{Action, Cmp, Comparator, Syscall};

/// Communication with the parent, and file system syscalls (opening files is
/// restricted to the source directories with landlock).
pub fn seccomp(fd_read: RawFd, fd_write: RawFd) -> Result<()> {
    let mut ctx = seccomp::new_context_with_common_rules(vec![fd_read], vec![fd_write])?;

    #[cfg(not(target_arch = "aarch64"))]
    ctx.allow_syscall(Syscall::open)?;
    ctx.allow_syscall(Syscall::openat)?;
    ctx.allow_syscall(Syscall::read)?;
    ctx.allow_syscall(Syscall::close)?;
    ctx.allow_syscall(Syscall::lseek)?;
    #[cfg(not(target_arch = "aarch64"))]
    ctx.allow_syscall(Syscall::stat)?;
    ctx.allow_syscall(Syscall::fstat)?;
    ctx.allow_syscall(Syscall::statx)?;
    #[cfg(not(target_arch = "aarch64"))]
    ctx.allow_syscall(Syscall::lstat)?;
    ctx.allow_syscall(Syscall::newfstatat)?;
    ctx.allow_syscall(Syscall::getdents64)?;
    ctx.allow_syscall(Syscall::getrandom)?;

    ctx.allow_syscall(Syscall::landlock_create_ruleset)?;
    ctx.allow_syscall(Syscall::landlock_add_rule)?;
    ctx.allow_syscall(Syscall::landlock_restrict_self)?;
    ctx.set_rule_for_syscall(
        Action::Allow,
        Syscall::prctl,
        &[Comparator::new(
            0,
            Cmp::Eq,
            libc::PR_SET_NO_NEW_PRIVS as u64,
            None,
        )],
    )?;

    ctx.load()?;
    Ok(())
}
