use crate::{Result, seccomp};
use syscallz::{Action, Cmp, Comparator, Syscall};

/// landlock (see [`crate::landlock`]) and seccomp allowing network access.
/// TCP connections are restricted to `connect_ports` by landlock.
pub fn sandbox(
    paths_ro: Option<&[&str]>,
    paths_rw: Option<&[&str]>,
    paths_x: Option<&[&str]>,
    connect_ports: Option<&[u16]>,
) -> Result<()> {
    crate::landlock(paths_ro, paths_rw, paths_x, None, connect_ports)?;

    let mut ctx = seccomp::new_context_with_common_rules(vec![], vec![])?;

    #[cfg(not(target_arch = "aarch64"))]
    ctx.allow_syscall(Syscall::access)?;
    ctx.allow_syscall(Syscall::bind)?;
    ctx.allow_syscall(Syscall::clock_nanosleep)?;
    ctx.allow_syscall(Syscall::clone3)?;
    ctx.allow_syscall(Syscall::clone)?;
    ctx.allow_syscall(Syscall::close)?;
    ctx.allow_syscall(Syscall::connect)?;
    ctx.allow_syscall(Syscall::epoll_create1)?;
    ctx.allow_syscall(Syscall::epoll_ctl)?;

    #[cfg(not(target_arch = "aarch64"))]
    ctx.allow_syscall(Syscall::epoll_wait)?;
    #[cfg(target_arch = "aarch64")]
    ctx.allow_syscall(Syscall::epoll_pwait)?;

    ctx.allow_syscall(Syscall::eventfd2)?;
    ctx.allow_syscall(Syscall::exit)?;
    ctx.allow_syscall(Syscall::faccessat2)?;
    ctx.allow_syscall(Syscall::fcntl)?;
    ctx.allow_syscall(Syscall::fstat)?;

    #[cfg(not(target_arch = "aarch64"))]
    ctx.allow_syscall(Syscall::lstat)?;

    ctx.allow_syscall(Syscall::getdents64)?;
    ctx.allow_syscall(Syscall::geteuid)?;
    ctx.allow_syscall(Syscall::getpeername)?;
    ctx.allow_syscall(Syscall::getpid)?;
    ctx.allow_syscall(Syscall::getrandom)?;
    ctx.allow_syscall(Syscall::getsockname)?;
    ctx.allow_syscall(Syscall::getsockopt)?;
    ctx.allow_syscall(Syscall::ioctl)?;
    ctx.allow_syscall(Syscall::lseek)?;
    ctx.allow_syscall(Syscall::madvise)?;
    ctx.allow_syscall(Syscall::newfstatat)?;
    ctx.allow_syscall(Syscall::openat)?;

    #[cfg(not(target_arch = "aarch64"))]
    ctx.allow_syscall(Syscall::poll)?;
    #[cfg(target_arch = "aarch64")]
    ctx.allow_syscall(Syscall::ppoll)?;

    ctx.allow_syscall(Syscall::prctl)?;
    ctx.allow_syscall(Syscall::read)?;
    ctx.allow_syscall(Syscall::recvfrom)?;
    ctx.allow_syscall(Syscall::recvmsg)?;
    ctx.allow_syscall(Syscall::rseq)?;
    ctx.allow_syscall(Syscall::rt_sigaction)?;
    ctx.allow_syscall(Syscall::sched_getaffinity)?;
    ctx.allow_syscall(Syscall::sched_yield)?;
    ctx.allow_syscall(Syscall::sendmsg)?;
    ctx.allow_syscall(Syscall::sendto)?;
    ctx.allow_syscall(Syscall::set_robust_list)?;
    ctx.allow_syscall(Syscall::setsockopt)?;
    ctx.allow_syscall(Syscall::shutdown)?;
    ctx.allow_syscall(Syscall::socket)?;
    ctx.allow_syscall(Syscall::socketpair)?;
    ctx.allow_syscall(Syscall::statx)?;
    ctx.allow_syscall(Syscall::sysinfo)?;
    ctx.allow_syscall(Syscall::uname)?;
    ctx.allow_syscall(Syscall::write)?;
    ctx.allow_syscall(Syscall::writev)?;

    // With musl, reqwest/hyper/tokio seems to use membarrier, likely because of the pthread_create impl.
    // See https://git.musl-libc.org/cgit/musl/tree/src/linux/membarrier.c?h=v1.2.6
    //     https://git.musl-libc.org/cgit/musl/tree/src/thread/pthread_create.c?h=v1.2.6
    #[cfg(target_env = "musl")]
    ctx.set_rule_for_syscall(
        Action::Allow,
        Syscall::membarrier,
        &[
            Comparator::new(
            0,
            Cmp::MaskedEq,
            u64::from(u32::MAX),
            Some(libc::MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED as u64)),
            Comparator::new(
            1,
            Cmp::MaskedEq,
            u64::from(u32::MAX),
            Some(0)),
        ],
    )?;

    // Allow mprotect without PROT_EXEC
    ctx.allow_syscall(Syscall::mprotect)?;
    ctx.set_rule_for_syscall(
        Action::KillThread,
        Syscall::mprotect,
        &[Comparator::new(
            2,
            Cmp::MaskedEq,
            libc::PROT_EXEC as u64,
            Some(libc::PROT_EXEC as u64),
        )],
    )?;

    ctx.load()?;

    Ok(())
}
