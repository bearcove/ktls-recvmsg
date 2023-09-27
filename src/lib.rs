use cfg_if::cfg_if;
use libc::{c_int, timespec, timeval};
pub use libc::{cmsghdr, msghdr};
use std::os::unix::io::RawFd;

/// A type-safe wrapper around a single control message, as used with
/// [`recvmsg`](#fn.recvmsg).
///
/// [Further reading](https://man7.org/linux/man-pages/man3/cmsg.3.html)
//  Nix version 0.13.0 and earlier used ControlMessage for both recvmsg and
//  sendmsg.  However, on some platforms the messages returned by recvmsg may be
//  unaligned.  ControlMessageOwned takes those messages by copy, obviating any
//  alignment issues.
//
//  See https://github.com/nix-rust/nix/issues/999
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ControlMessageOwned {
    /// Received version of [`ControlMessage::ScmRights`]
    ScmRights(Vec<RawFd>),
    /// Received version of [`ControlMessage::ScmCredentials`]
    #[cfg(any(target_os = "android", target_os = "linux"))]
    #[cfg_attr(docsrs, doc(cfg(all())))]
    ScmCredentials(UnixCredentials),
    /// Received version of [`ControlMessage::ScmCreds`]
    #[cfg(any(target_os = "freebsd", target_os = "dragonfly"))]
    #[cfg_attr(docsrs, doc(cfg(all())))]
    ScmCreds(UnixCredentials),
    /// A message of type `SCM_TIMESTAMP`, containing the time the
    /// packet was received by the kernel.
    ///
    /// See the kernel's explanation in "SO_TIMESTAMP" of
    /// [networking/timestamping](https://www.kernel.org/doc/Documentation/networking/timestamping.txt).
    ///
    /// # Examples
    ///
    /// ```
    /// # #[macro_use] extern crate nix;
    /// # use nix::sys::socket::*;
    /// # use nix::sys::time::*;
    /// # use std::io::{IoSlice, IoSliceMut};
    /// # use std::time::*;
    /// # use std::str::FromStr;
    /// # use std::os::unix::io::AsRawFd;
    /// # fn main() {
    /// // Set up
    /// let message = "Ohayō!".as_bytes();
    /// let in_socket = socket(
    ///     AddressFamily::Inet,
    ///     SockType::Datagram,
    ///     SockFlag::empty(),
    ///     None).unwrap();
    /// setsockopt(&in_socket, sockopt::ReceiveTimestamp, &true).unwrap();
    /// let localhost = SockaddrIn::from_str("127.0.0.1:0").unwrap();
    /// bind(in_socket.as_raw_fd(), &localhost).unwrap();
    /// let address: SockaddrIn = getsockname(in_socket.as_raw_fd()).unwrap();
    /// // Get initial time
    /// let time0 = SystemTime::now();
    /// // Send the message
    /// let iov = [IoSlice::new(message)];
    /// let flags = MsgFlags::empty();
    /// let l = sendmsg(in_socket.as_raw_fd(), &iov, &[], flags, Some(&address)).unwrap();
    /// assert_eq!(message.len(), l);
    /// // Receive the message
    /// let mut buffer = vec![0u8; message.len()];
    /// let mut cmsgspace = cmsg_space!(TimeVal);
    /// let mut iov = [IoSliceMut::new(&mut buffer)];
    /// let r = recvmsg::<SockaddrIn>(in_socket.as_raw_fd(), &mut iov, Some(&mut cmsgspace), flags)
    ///     .unwrap();
    /// let rtime = match r.cmsgs().next() {
    ///     Some(ControlMessageOwned::ScmTimestamp(rtime)) => rtime,
    ///     Some(_) => panic!("Unexpected control message"),
    ///     None => panic!("No control message")
    /// };
    /// // Check the final time
    /// let time1 = SystemTime::now();
    /// // the packet's received timestamp should lie in-between the two system
    /// // times, unless the system clock was adjusted in the meantime.
    /// let rduration = Duration::new(rtime.tv_sec() as u64,
    ///                               rtime.tv_usec() as u32 * 1000);
    /// assert!(time0.duration_since(UNIX_EPOCH).unwrap() <= rduration);
    /// assert!(rduration <= time1.duration_since(UNIX_EPOCH).unwrap());
    /// // Close socket
    /// # }
    /// ```
    ScmTimestamp(TimeVal),
    /// A set of nanosecond resolution timestamps
    ///
    /// [Further reading](https://www.kernel.org/doc/html/latest/networking/timestamping.html)
    #[cfg(any(target_os = "android", target_os = "linux"))]
    ScmTimestampsns(Timestamps),
    /// Nanoseconds resolution timestamp
    ///
    /// [Further reading](https://www.kernel.org/doc/html/latest/networking/timestamping.html)
    #[cfg(any(target_os = "android", target_os = "linux"))]
    #[cfg_attr(docsrs, doc(cfg(all())))]
    ScmTimestampns(TimeSpec),
    #[cfg(any(
        target_os = "android",
        target_os = "ios",
        target_os = "linux",
        target_os = "macos",
        target_os = "netbsd",
    ))]
    #[cfg(feature = "net")]
    #[cfg_attr(docsrs, doc(cfg(feature = "net")))]
    Ipv4PacketInfo(libc::in_pktinfo),
    #[cfg(any(
        target_os = "android",
        target_os = "dragonfly",
        target_os = "freebsd",
        target_os = "ios",
        target_os = "linux",
        target_os = "macos",
        target_os = "openbsd",
        target_os = "netbsd",
    ))]
    #[cfg(feature = "net")]
    #[cfg_attr(docsrs, doc(cfg(feature = "net")))]
    Ipv6PacketInfo(libc::in6_pktinfo),
    #[cfg(any(
        target_os = "freebsd",
        target_os = "ios",
        target_os = "macos",
        target_os = "netbsd",
        target_os = "openbsd",
    ))]
    #[cfg(feature = "net")]
    #[cfg_attr(docsrs, doc(cfg(feature = "net")))]
    Ipv4RecvIf(libc::sockaddr_dl),
    #[cfg(any(
        target_os = "freebsd",
        target_os = "ios",
        target_os = "macos",
        target_os = "netbsd",
        target_os = "openbsd",
    ))]
    #[cfg(feature = "net")]
    #[cfg_attr(docsrs, doc(cfg(feature = "net")))]
    Ipv4RecvDstAddr(libc::in_addr),
    #[cfg(any(target_os = "android", target_os = "freebsd", target_os = "linux"))]
    #[cfg(feature = "net")]
    #[cfg_attr(docsrs, doc(cfg(feature = "net")))]
    Ipv4OrigDstAddr(libc::sockaddr_in),
    #[cfg(any(target_os = "android", target_os = "freebsd", target_os = "linux"))]
    #[cfg(feature = "net")]
    #[cfg_attr(docsrs, doc(cfg(feature = "net")))]
    Ipv6OrigDstAddr(libc::sockaddr_in6),

    /// UDP Generic Receive Offload (GRO) allows receiving multiple UDP
    /// packets from a single sender.
    /// Fixed-size payloads are following one by one in a receive buffer.
    /// This Control Message indicates the size of all smaller packets,
    /// except, maybe, the last one.
    ///
    /// `UdpGroSegment` socket option should be enabled on a socket
    /// to allow receiving GRO packets.
    #[cfg(target_os = "linux")]
    #[cfg(feature = "net")]
    #[cfg_attr(docsrs, doc(cfg(feature = "net")))]
    UdpGroSegments(u16),

    /// SO_RXQ_OVFL indicates that an unsigned 32 bit value
    /// ancilliary msg (cmsg) should be attached to recieved
    /// skbs indicating the number of packets dropped by the
    /// socket between the last recieved packet and this
    /// received packet.
    ///
    /// `RxqOvfl` socket option should be enabled on a socket
    /// to allow receiving the drop counter.
    #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
    #[cfg_attr(docsrs, doc(cfg(all())))]
    RxqOvfl(u32),

    /// Socket error queue control messages read with the `MSG_ERRQUEUE` flag.
    #[cfg(any(target_os = "android", target_os = "linux"))]
    #[cfg(feature = "net")]
    #[cfg_attr(docsrs, doc(cfg(feature = "net")))]
    Ipv4RecvErr(libc::sock_extended_err, Option<sockaddr_in>),
    /// Socket error queue control messages read with the `MSG_ERRQUEUE` flag.
    #[cfg(any(target_os = "android", target_os = "linux"))]
    #[cfg(feature = "net")]
    #[cfg_attr(docsrs, doc(cfg(feature = "net")))]
    Ipv6RecvErr(libc::sock_extended_err, Option<sockaddr_in6>),

    /// `SOL_TLS` messages of type `TLS_GET_RECORD_TYPE`, containing the TLS message content type,
    /// normally one of change_cipher_spec(20), alert(21), handshake(22) (for TLS 1.3
    /// resumption tickets), application_data(23)
    TlsGetRecordType(u8),

    /// Catch-all variant for unimplemented cmsg types.
    #[doc(hidden)]
    Unknown(UnknownCmsg),
}

cfg_if! {
    if #[cfg(any(target_os = "android", target_os = "linux"))] {
        /// Unix credentials of the sending process.
        ///
        /// This struct is used with the `SO_PEERCRED` ancillary message
        /// and the `SCM_CREDENTIALS` control message for UNIX sockets.
        #[repr(transparent)]
        #[derive(Clone, Copy, Debug, Eq, PartialEq)]
        pub struct UnixCredentials(libc::ucred);

        impl UnixCredentials {
            /// Creates a new instance with the credentials of the current process
            pub fn new() -> Self {
                // Safe because these FFI functions are inherently safe
                unsafe {
                    UnixCredentials(libc::ucred {
                        pid: libc::getpid(),
                        uid: libc::getuid(),
                        gid: libc::getgid()
                    })
                }
            }

            /// Returns the process identifier
            pub fn pid(&self) -> libc::pid_t {
                self.0.pid
            }

            /// Returns the user identifier
            pub fn uid(&self) -> libc::uid_t {
                self.0.uid
            }

            /// Returns the group identifier
            pub fn gid(&self) -> libc::gid_t {
                self.0.gid
            }
        }

        impl Default for UnixCredentials {
            fn default() -> Self {
                Self::new()
            }
        }

        impl From<libc::ucred> for UnixCredentials {
            fn from(cred: libc::ucred) -> Self {
                UnixCredentials(cred)
            }
        }

        impl From<UnixCredentials> for libc::ucred {
            fn from(uc: UnixCredentials) -> Self {
                uc.0
            }
        }
    } else if #[cfg(any(target_os = "freebsd", target_os = "dragonfly"))] {
        /// Unix credentials of the sending process.
        ///
        /// This struct is used with the `SCM_CREDS` ancillary message for UNIX sockets.
        #[repr(transparent)]
        #[derive(Clone, Copy, Debug, Eq, PartialEq)]
        pub struct UnixCredentials(libc::cmsgcred);

        impl UnixCredentials {
            /// Returns the process identifier
            pub fn pid(&self) -> libc::pid_t {
                self.0.cmcred_pid
            }

            /// Returns the real user identifier
            pub fn uid(&self) -> libc::uid_t {
                self.0.cmcred_uid
            }

            /// Returns the effective user identifier
            pub fn euid(&self) -> libc::uid_t {
                self.0.cmcred_euid
            }

            /// Returns the real group identifier
            pub fn gid(&self) -> libc::gid_t {
                self.0.cmcred_gid
            }

            /// Returns a list group identifiers (the first one being the effective GID)
            pub fn groups(&self) -> &[libc::gid_t] {
                unsafe {
                    std::slice::from_raw_parts(
                        self.0.cmcred_groups.as_ptr() as *const libc::gid_t,
                        self.0.cmcred_ngroups as _
                    )
                }
            }
        }

        impl From<libc::cmsgcred> for UnixCredentials {
            fn from(cred: libc::cmsgcred) -> Self {
                UnixCredentials(cred)
            }
        }
    }
}

#[repr(transparent)]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct TimeVal(timeval);

/// For representing packet timestamps via `SO_TIMESTAMPING` interface
#[cfg(target_os = "linux")]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Timestamps {
    /// software based timestamp, usually one containing data
    pub system: TimeSpec,
    /// legacy timestamp, usually empty
    pub hw_trans: TimeSpec,
    /// hardware based timestamp
    pub hw_raw: TimeSpec,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct TimeSpec(timespec);

// An opaque structure used to prevent cmsghdr from being a public type
#[doc(hidden)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UnknownCmsg(cmsghdr, Vec<u8>);

/// The `libc_bitflags!` macro helps with a common use case of defining a public bitflags type
/// with values from the libc crate. It is used the same way as the `bitflags!` macro, except
/// that only the name of the flag value has to be given.
///
/// The `libc` crate must be in scope with the name `libc`.
///
/// # Example
/// ```ignore
/// libc_bitflags!{
///     pub struct ProtFlags: libc::c_int {
///         PROT_NONE;
///         PROT_READ;
///         /// PROT_WRITE enables write protect
///         PROT_WRITE;
///         PROT_EXEC;
///         #[cfg(any(target_os = "linux", target_os = "android"))]
///         PROT_GROWSDOWN;
///         #[cfg(any(target_os = "linux", target_os = "android"))]
///         PROT_GROWSUP;
///     }
/// }
/// ```
///
/// Example with casting, due to a mistake in libc. In this example, the
/// various flags have different types, so we cast the broken ones to the right
/// type.
///
/// ```ignore
/// libc_bitflags!{
///     pub struct SaFlags: libc::c_ulong {
///         SA_NOCLDSTOP as libc::c_ulong;
///         SA_NOCLDWAIT;
///         SA_NODEFER as libc::c_ulong;
///         SA_ONSTACK;
///         SA_RESETHAND as libc::c_ulong;
///         SA_RESTART as libc::c_ulong;
///         SA_SIGINFO;
///     }
/// }
/// ```
macro_rules! libc_bitflags {
    (
        $(#[$outer:meta])*
        pub struct $BitFlags:ident: $T:ty {
            $(
                $(#[$inner:ident $($args:tt)*])*
                $Flag:ident $(as $cast:ty)*;
            )+
        }
    ) => {
        ::bitflags::bitflags! {
            $(#[$outer])*
            pub struct $BitFlags: $T {
                $(
                    $(#[$inner $($args)*])*
                    const $Flag = libc::$Flag $(as $cast)*;
                )+
            }
        }
    };
}

libc_bitflags! {
    /// Flags for send/recv and their relatives
    pub struct MsgFlags: c_int {
        /// Sends or requests out-of-band data on sockets that support this notion
        /// (e.g., of type [`Stream`](enum.SockType.html)); the underlying protocol must also
        /// support out-of-band data.
        MSG_OOB;
        /// Peeks at an incoming message. The data is treated as unread and the next
        /// [`recv()`](fn.recv.html)
        /// or similar function shall still return this data.
        MSG_PEEK;
        /// Receive operation blocks until the full amount of data can be
        /// returned. The function may return smaller amount of data if a signal
        /// is caught, an error or disconnect occurs.
        MSG_WAITALL;
        /// Enables nonblocking operation; if the operation would block,
        /// `EAGAIN` or `EWOULDBLOCK` is returned.  This provides similar
        /// behavior to setting the `O_NONBLOCK` flag
        /// (via the [`fcntl`](../../fcntl/fn.fcntl.html)
        /// `F_SETFL` operation), but differs in that `MSG_DONTWAIT` is a per-
        /// call option, whereas `O_NONBLOCK` is a setting on the open file
        /// description (see [open(2)](https://man7.org/linux/man-pages/man2/open.2.html)),
        /// which will affect all threads in
        /// the calling process and as well as other processes that hold
        /// file descriptors referring to the same open file description.
        MSG_DONTWAIT;
        /// Receive flags: Control Data was discarded (buffer too small)
        MSG_CTRUNC;
        /// For raw ([`Packet`](addr/enum.AddressFamily.html)), Internet datagram
        /// (since Linux 2.4.27/2.6.8),
        /// netlink (since Linux 2.6.22) and UNIX datagram (since Linux 3.4)
        /// sockets: return the real length of the packet or datagram, even
        /// when it was longer than the passed buffer. Not implemented for UNIX
        /// domain ([unix(7)](https://linux.die.net/man/7/unix)) sockets.
        ///
        /// For use with Internet stream sockets, see [tcp(7)](https://linux.die.net/man/7/tcp).
        MSG_TRUNC;
        /// Terminates a record (when this notion is supported, as for
        /// sockets of type [`SeqPacket`](enum.SockType.html)).
        MSG_EOR;
        /// This flag specifies that queued errors should be received from
        /// the socket error queue. (For more details, see
        /// [recvfrom(2)](https://linux.die.net/man/2/recvfrom))
        #[cfg(any(target_os = "android", target_os = "linux"))]
        #[cfg_attr(docsrs, doc(cfg(all())))]
        MSG_ERRQUEUE;
        /// Set the `close-on-exec` flag for the file descriptor received via a UNIX domain
        /// file descriptor using the `SCM_RIGHTS` operation (described in
        /// [unix(7)](https://linux.die.net/man/7/unix)).
        /// This flag is useful for the same reasons as the `O_CLOEXEC` flag of
        /// [open(2)](https://pubs.opengroup.org/onlinepubs/9699919799/functions/open.html).
        ///
        /// Only used in [`recvmsg`](fn.recvmsg.html) function.
        #[cfg(any(target_os = "android",
                  target_os = "dragonfly",
                  target_os = "freebsd",
                  target_os = "linux",
                  target_os = "netbsd",
                  target_os = "openbsd"))]
        #[cfg_attr(docsrs, doc(cfg(all())))]
        MSG_CMSG_CLOEXEC;
        /// Requests not to send `SIGPIPE` errors when the other end breaks the connection.
        /// (For more details, see [send(2)](https://linux.die.net/man/2/send)).
        #[cfg(any(target_os = "android",
                  target_os = "dragonfly",
                  target_os = "freebsd",
                  target_os = "fuchsia",
                  target_os = "haiku",
                  target_os = "illumos",
                  target_os = "linux",
                  target_os = "netbsd",
                  target_os = "openbsd",
                  target_os = "solaris"))]
        #[cfg_attr(docsrs, doc(cfg(all())))]
        MSG_NOSIGNAL;
    }
}

/// An IPv4 socket address
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct SockaddrIn(libc::sockaddr_in);
