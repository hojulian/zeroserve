use std::{
    collections::HashMap,
    io::ErrorKind,
    os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd},
    sync::Arc,
};

use futures::{StreamExt, channel::mpsc};
use parking_lot::Mutex;

pub struct HupWatcher {
    efd: OwnedFd,
    hooks: Mutex<HashMap<RawFd, mpsc::Sender<()>>>,
}

impl HupWatcher {
    pub fn new() -> Arc<Self> {
        let efd = unsafe { libc::epoll_create(1) };
        if efd < 0 {
            panic!("epoll_create: {:?}", std::io::Error::last_os_error());
        }
        let efd = unsafe { OwnedFd::from_raw_fd(efd) };
        let me = Arc::new(Self {
            efd,
            hooks: Mutex::new(HashMap::new()),
        });
        let me_clone = me.clone();
        std::thread::Builder::new()
            .name("zs-hupwatch".into())
            .spawn(move || {
                watcher(me_clone);
            })
            .unwrap();
        me
    }

    pub fn wait(
        self: &Arc<Self>,
        fd: RawFd,
    ) -> std::io::Result<impl Future<Output = ()> + Unpin + 'static> {
        let (tx, rx) = mpsc::channel(1);
        unsafe {
            let mut ev = libc::epoll_event {
                events: (libc::EPOLLHUP | libc::EPOLLRDHUP | libc::EPOLLET | libc::EPOLLONESHOT)
                    as _,
                u64: fd as _,
            };
            self.hooks.lock().insert(fd, tx);
            let ret = libc::epoll_ctl(self.efd.as_raw_fd(), libc::EPOLL_CTL_ADD, fd, &mut ev);
            if ret < 0 {
                return Err(std::io::Error::last_os_error());
            }
        }

        struct G(Arc<HupWatcher>, RawFd, mpsc::Receiver<()>);
        impl Drop for G {
            fn drop(&mut self) {
                let mut hooks = self.0.hooks.lock();
                if let Some(x) = hooks.get(&self.1) {
                    if x.is_connected_to(&self.2) {
                        hooks.remove(&self.1);
                    }
                }
            }
        }
        let mut g = G(self.clone(), fd, rx);

        Ok(Box::pin(async move {
            let _ = g.2.next().await;
        }))
    }
}

fn watcher(w: Arc<HupWatcher>) {
    const MAX_EVENTS: usize = 10;

    unsafe {
        let mut events: [libc::epoll_event; MAX_EVENTS] = core::mem::zeroed();
        loop {
            let nfds =
                libc::epoll_wait(w.efd.as_raw_fd(), events.as_mut_ptr(), MAX_EVENTS as _, -1);
            if nfds < 0 {
                let err = std::io::Error::last_os_error();
                if err.kind() == ErrorKind::Interrupted {
                    continue;
                }
                panic!("hupwatch: epoll_wait: {:?}", err);
            }

            for i in 0..nfds {
                let fd = events[i as usize].u64 as RawFd;
                let tx = w.hooks.lock().remove(&fd);
                if let Some(mut x) = tx {
                    let _ = x.try_send(());
                }
            }
        }
    }
}
