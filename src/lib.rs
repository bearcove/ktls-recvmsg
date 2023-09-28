use libc::{c_void, iovec, CMSG_DATA, CMSG_FIRSTHDR, CMSG_NXTHDR};
pub use libc::{cmsghdr, msghdr};
pub use nix::{
    errno::Errno,
    sys::socket::{MsgFlags, SockaddrIn},
};
use nix::{
    sys::{
        socket::{SockaddrLike, Timestamps, UnixCredentials},
        time::{TimeSpec, TimeVal},
    },
    Result,
};
use std::{io::IoSliceMut, mem, os::unix::io::RawFd, ptr};

// An opaque structure used to prevent cmsghdr from being a public type
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UnknownCmsg(cmsghdr, Vec<u8>);

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

impl ControlMessageOwned {
    /// Decodes a `ControlMessageOwned` from raw bytes.
    ///
    /// This is only safe to call if the data is correct for the message type
    /// specified in the header. Normally, the kernel ensures that this is the
    /// case. "Correct" in this case includes correct length, alignment and
    /// actual content.
    // Clippy complains about the pointer alignment of `p`, not understanding
    // that it's being fed to a function that can handle that.
    #[allow(clippy::cast_ptr_alignment)]
    unsafe fn decode_from(header: &cmsghdr) -> ControlMessageOwned {
        let p = CMSG_DATA(header);
        // The cast is not unnecessary on all platforms.
        #[allow(clippy::unnecessary_cast)]
        let len = header as *const _ as usize + header.cmsg_len as usize - p as usize;
        match (header.cmsg_level, header.cmsg_type) {
            (libc::SOL_SOCKET, libc::SCM_RIGHTS) => {
                let n = len / mem::size_of::<RawFd>();
                let mut fds = Vec::with_capacity(n);
                for i in 0..n {
                    let fdp = (p as *const RawFd).add(i);
                    fds.push(ptr::read_unaligned(fdp));
                }
                ControlMessageOwned::ScmRights(fds)
            }
            #[cfg(any(target_os = "android", target_os = "linux"))]
            (libc::SOL_SOCKET, libc::SCM_CREDENTIALS) => {
                let cred: libc::ucred = ptr::read_unaligned(p as *const _);
                ControlMessageOwned::ScmCredentials(cred.into())
            }
            #[cfg(any(target_os = "freebsd", target_os = "dragonfly"))]
            (libc::SOL_SOCKET, libc::SCM_CREDS) => {
                let cred: libc::cmsgcred = ptr::read_unaligned(p as *const _);
                ControlMessageOwned::ScmCreds(cred.into())
            }
            #[cfg(not(any(target_os = "aix", target_os = "haiku")))]
            (libc::SOL_SOCKET, libc::SCM_TIMESTAMP) => {
                let tv: libc::timeval = ptr::read_unaligned(p as *const _);
                ControlMessageOwned::ScmTimestamp(TimeVal::from(tv))
            }
            #[cfg(any(target_os = "android", target_os = "linux"))]
            (libc::SOL_SOCKET, libc::SCM_TIMESTAMPNS) => {
                let ts: libc::timespec = ptr::read_unaligned(p as *const _);
                ControlMessageOwned::ScmTimestampns(TimeSpec::from(ts))
            }
            #[cfg(any(target_os = "android", target_os = "linux"))]
            (libc::SOL_SOCKET, libc::SCM_TIMESTAMPING) => {
                let tp = p as *const libc::timespec;
                let ts: libc::timespec = ptr::read_unaligned(tp);
                let system = TimeSpec::from(ts);
                let ts: libc::timespec = ptr::read_unaligned(tp.add(1));
                let hw_trans = TimeSpec::from(ts);
                let ts: libc::timespec = ptr::read_unaligned(tp.add(2));
                let hw_raw = TimeSpec::from(ts);
                let timestamping = Timestamps {
                    system,
                    hw_trans,
                    hw_raw,
                };
                ControlMessageOwned::ScmTimestampsns(timestamping)
            }
            #[cfg(any(
                target_os = "android",
                target_os = "freebsd",
                target_os = "ios",
                target_os = "linux",
                target_os = "macos"
            ))]
            #[cfg(feature = "net")]
            (libc::IPPROTO_IPV6, libc::IPV6_PKTINFO) => {
                let info = ptr::read_unaligned(p as *const libc::in6_pktinfo);
                ControlMessageOwned::Ipv6PacketInfo(info)
            }
            #[cfg(any(
                target_os = "android",
                target_os = "ios",
                target_os = "linux",
                target_os = "macos",
                target_os = "netbsd",
            ))]
            #[cfg(feature = "net")]
            (libc::IPPROTO_IP, libc::IP_PKTINFO) => {
                let info = ptr::read_unaligned(p as *const libc::in_pktinfo);
                ControlMessageOwned::Ipv4PacketInfo(info)
            }
            #[cfg(any(
                target_os = "freebsd",
                target_os = "ios",
                target_os = "macos",
                target_os = "netbsd",
                target_os = "openbsd",
            ))]
            #[cfg(feature = "net")]
            (libc::IPPROTO_IP, libc::IP_RECVIF) => {
                let dl = ptr::read_unaligned(p as *const libc::sockaddr_dl);
                ControlMessageOwned::Ipv4RecvIf(dl)
            }
            #[cfg(any(
                target_os = "freebsd",
                target_os = "ios",
                target_os = "macos",
                target_os = "netbsd",
                target_os = "openbsd",
            ))]
            #[cfg(feature = "net")]
            (libc::IPPROTO_IP, libc::IP_RECVDSTADDR) => {
                let dl = ptr::read_unaligned(p as *const libc::in_addr);
                ControlMessageOwned::Ipv4RecvDstAddr(dl)
            }
            #[cfg(any(target_os = "android", target_os = "freebsd", target_os = "linux"))]
            #[cfg(feature = "net")]
            (libc::IPPROTO_IP, libc::IP_ORIGDSTADDR) => {
                let dl = ptr::read_unaligned(p as *const libc::sockaddr_in);
                ControlMessageOwned::Ipv4OrigDstAddr(dl)
            }
            #[cfg(target_os = "linux")]
            #[cfg(feature = "net")]
            (libc::SOL_UDP, libc::UDP_GRO) => {
                let gso_size: u16 = ptr::read_unaligned(p as *const _);
                ControlMessageOwned::UdpGroSegments(gso_size)
            }
            #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
            (libc::SOL_SOCKET, libc::SO_RXQ_OVFL) => {
                let drop_counter = ptr::read_unaligned(p as *const u32);
                ControlMessageOwned::RxqOvfl(drop_counter)
            }
            #[cfg(any(target_os = "android", target_os = "linux"))]
            #[cfg(feature = "net")]
            (libc::IPPROTO_IP, libc::IP_RECVERR) => {
                let (err, addr) = Self::recv_err_helper::<sockaddr_in>(p, len);
                ControlMessageOwned::Ipv4RecvErr(err, addr)
            }
            #[cfg(any(target_os = "android", target_os = "linux"))]
            #[cfg(feature = "net")]
            (libc::IPPROTO_IPV6, libc::IPV6_RECVERR) => {
                let (err, addr) = Self::recv_err_helper::<sockaddr_in6>(p, len);
                ControlMessageOwned::Ipv6RecvErr(err, addr)
            }
            #[cfg(any(target_os = "android", target_os = "freebsd", target_os = "linux"))]
            #[cfg(feature = "net")]
            (libc::IPPROTO_IPV6, libc::IPV6_ORIGDSTADDR) => {
                let dl = ptr::read_unaligned(p as *const libc::sockaddr_in6);
                ControlMessageOwned::Ipv6OrigDstAddr(dl)
            }
            #[cfg(all(target_os = "linux"))]
            (libc::SOL_TLS, libc::TLS_GET_RECORD_TYPE) => {
                let content_type = ptr::read_unaligned(p as *const u8);
                ControlMessageOwned::TlsGetRecordType(content_type)
            }
            (_, _) => {
                let sl = std::slice::from_raw_parts(p, len);
                let ucmsg = UnknownCmsg(*header, Vec::<u8>::from(sl));
                ControlMessageOwned::Unknown(ucmsg)
            }
        }
    }

    #[cfg(any(target_os = "android", target_os = "linux"))]
    #[cfg(feature = "net")]
    #[allow(clippy::cast_ptr_alignment)] // False positive
    unsafe fn recv_err_helper<T>(
        p: *mut libc::c_uchar,
        len: usize,
    ) -> (libc::sock_extended_err, Option<T>) {
        let ee = p as *const libc::sock_extended_err;
        let err = ptr::read_unaligned(ee);

        // For errors originating on the network, SO_EE_OFFENDER(ee) points inside the p[..len]
        // CMSG_DATA buffer.  For local errors, there is no address included in the control
        // message, and SO_EE_OFFENDER(ee) points beyond the end of the buffer.  So, we need to
        // validate that the address object is in-bounds before we attempt to copy it.
        let addrp = libc::SO_EE_OFFENDER(ee) as *const T;

        if addrp.offset(1) as usize - (p as usize) > len {
            (err, None)
        } else {
            (err, Some(ptr::read_unaligned(addrp)))
        }
    }
}

/// Receive message in scatter-gather vectors from a socket, and
/// optionally receive ancillary data into the provided buffer.
/// If no ancillary data is desired, use () as the type parameter.
///
/// # Arguments
///
/// * `fd`:             Socket file descriptor
/// * `iov`:            Scatter-gather list of buffers to receive the message
/// * `cmsg_buffer`:    Space to receive ancillary data.  Should be created by
///                     [`cmsg_space!`](../../macro.cmsg_space.html)
/// * `flags`:          Optional flags passed directly to the operating system.
///
/// # References
/// [recvmsg(2)](https://pubs.opengroup.org/onlinepubs/9699919799/functions/recvmsg.html)
pub fn recvmsg<'a, 'outer, 'inner, S>(
    fd: RawFd,
    iov: &'outer mut [IoSliceMut<'inner>],
    mut cmsg_buffer: Option<&'a mut Vec<u8>>,
    flags: MsgFlags,
) -> Result<RecvMsg<'a, 'outer, S>>
where
    S: SockaddrLike + 'a,
    'inner: 'outer,
{
    let mut address = mem::MaybeUninit::uninit();

    let (msg_control, msg_controllen) = cmsg_buffer
        .as_mut()
        .map(|v| (v.as_mut_ptr(), v.capacity()))
        .unwrap_or((ptr::null_mut(), 0));
    let mut mhdr = unsafe {
        pack_mhdr_to_receive(
            iov.as_mut().as_mut_ptr(),
            iov.len(),
            msg_control,
            msg_controllen,
            address.as_mut_ptr(),
        )
    };

    let ret = unsafe { libc::recvmsg(fd, &mut mhdr, flags.bits()) };

    let r = Errno::result(ret)?;

    Ok(unsafe { read_mhdr(mhdr, r, msg_controllen, address.assume_init()) })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Contains outcome of sending or receiving a message
///
/// Use [`cmsgs`][RecvMsg::cmsgs] to access all the control messages present, and
/// [`iovs`][RecvMsg::iovs`] to access underlying io slices.
pub struct RecvMsg<'a, 's, S> {
    pub bytes: usize,
    cmsghdr: Option<&'a cmsghdr>,
    pub address: Option<S>,
    pub flags: MsgFlags,
    iobufs: std::marker::PhantomData<&'s ()>,
    mhdr: msghdr,
}

impl<'a, S> RecvMsg<'a, '_, S> {
    /// Iterate over the valid control messages pointed to by this
    /// msghdr.
    pub fn cmsgs(&self) -> CmsgIterator {
        CmsgIterator {
            cmsghdr: self.cmsghdr,
            mhdr: &self.mhdr,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CmsgIterator<'a> {
    /// Control message buffer to decode from. Must adhere to cmsg alignment.
    cmsghdr: Option<&'a cmsghdr>,
    mhdr: &'a msghdr,
}

impl<'a> Iterator for CmsgIterator<'a> {
    type Item = ControlMessageOwned;

    fn next(&mut self) -> Option<ControlMessageOwned> {
        match self.cmsghdr {
            None => None, // No more messages
            Some(hdr) => {
                // Get the data.
                // Safe if cmsghdr points to valid data returned by recvmsg(2)
                let cm = unsafe { Some(ControlMessageOwned::decode_from(hdr)) };
                // Advance the internal pointer.  Safe if mhdr and cmsghdr point
                // to valid data returned by recvmsg(2)
                self.cmsghdr = unsafe {
                    let p = CMSG_NXTHDR(self.mhdr as *const _, hdr as *const _);
                    p.as_ref()
                };
                cm
            }
        }
    }
}

/// Pack pointers to various structures into into msghdr
///
/// # Safety
/// `iov_buffer` and `iov_buffer_len` must point to a slice
/// of `IoSliceMut` and number of available elements or be a null pointer and 0
///
/// `cmsg_buffer` and `cmsg_capacity` must point to a byte buffer used
/// to store control headers later or be a null pointer and 0 if control
/// headers are not used
///
/// Buffers must remain valid for the whole lifetime of msghdr
unsafe fn pack_mhdr_to_receive<S>(
    iov_buffer: *mut IoSliceMut,
    iov_buffer_len: usize,
    cmsg_buffer: *mut u8,
    cmsg_capacity: usize,
    address: *mut S,
) -> msghdr
where
    S: SockaddrLike,
{
    // Musl's msghdr has private fields, so this is the only way to
    // initialize it.
    let mut mhdr = mem::MaybeUninit::<msghdr>::zeroed();
    let p = mhdr.as_mut_ptr();
    (*p).msg_name = address as *mut c_void;
    (*p).msg_namelen = S::size();
    (*p).msg_iov = iov_buffer as *mut iovec;
    (*p).msg_iovlen = iov_buffer_len as _;
    (*p).msg_control = cmsg_buffer as *mut c_void;
    (*p).msg_controllen = cmsg_capacity as _;
    (*p).msg_flags = 0;
    mhdr.assume_init()
}

unsafe fn read_mhdr<'a, 'i, S>(
    mhdr: msghdr,
    r: isize,
    msg_controllen: usize,
    mut address: S,
) -> RecvMsg<'a, 'i, S>
where
    S: SockaddrLike,
{
    // The cast is not unnecessary on all platforms.
    #[allow(clippy::unnecessary_cast)]
    let cmsghdr = {
        if mhdr.msg_controllen > 0 {
            debug_assert!(!mhdr.msg_control.is_null());
            debug_assert!(msg_controllen >= mhdr.msg_controllen as usize);
            CMSG_FIRSTHDR(&mhdr as *const msghdr)
        } else {
            ptr::null()
        }
        .as_ref()
    };

    // Ignore errors if this socket address has statically-known length
    //
    // This is to ensure that unix socket addresses have their length set appropriately.
    let _ = address.set_length(mhdr.msg_namelen as usize);

    RecvMsg {
        bytes: r as usize,
        cmsghdr,
        address: Some(address),
        flags: MsgFlags::from_bits_truncate(mhdr.msg_flags),
        mhdr,
        iobufs: std::marker::PhantomData,
    }
}
