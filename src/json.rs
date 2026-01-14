use std::{cell::UnsafeCell, ptr::NonNull, rc::Rc};

#[derive(Clone)]
pub struct JsonRef {
    tree: Rc<UnsafeCell<Tree>>,
    node: NonNull<serde_json::Value>,
    epoch: u64,
}

struct Tree {
    root: serde_json::Value,
    latest_epoch: u64,
    readers: usize,
    writer: bool,
}

impl JsonRef {
    pub fn new(root: serde_json::Value) -> Self {
        let tree = Rc::new(UnsafeCell::new(Tree {
            root,
            latest_epoch: 0,
            readers: 0,
            writer: false,
        }));
        let node = NonNull::from(unsafe { &(*tree.get()).root });
        Self {
            tree,
            node,
            epoch: 0,
        }
    }

    pub fn root(&self) -> Self {
        let inner = unsafe { &*self.tree.get() };
        JsonRef {
            tree: self.tree.clone(),
            node: NonNull::from(&inner.root),
            epoch: inner.latest_epoch,
        }
    }

    pub fn get(
        &self,
        mapper: impl FnOnce(&serde_json::Value) -> Option<&serde_json::Value>,
    ) -> Result<Option<JsonRef>, ()> {
        unsafe {
            let latest_epoch = (*self.tree.get()).latest_epoch;
            if self.epoch != latest_epoch {
                return Err(());
            }
            if (*self.tree.get()).writer {
                panic!("JsonRef::get: writer active");
            }
            let node = self.node.as_ref();
            (*self.tree.get()).readers += 1;
            let node = mapper(node);
            (*self.tree.get()).readers -= 1;
            Ok(node.map(|node| JsonRef {
                tree: self.tree.clone(),
                node: NonNull::from(node),
                epoch: latest_epoch,
            }))
        }
    }

    pub fn view<R>(&self, view: impl FnOnce(&serde_json::Value) -> R) -> Result<R, ()> {
        unsafe {
            let latest_epoch = (*self.tree.get()).latest_epoch;
            if self.epoch != latest_epoch {
                return Err(());
            }
            if (*self.tree.get()).writer {
                panic!("JsonRef::view: writer active");
            }
            (*self.tree.get()).readers += 1;
            let ret = view(self.node.as_ref());
            (*self.tree.get()).readers -= 1;
            Ok(ret)
        }
    }

    pub fn modify<R>(&self, modify: impl FnOnce(&mut serde_json::Value) -> R) -> Result<R, ()> {
        unsafe {
            let latest_epoch = (*self.tree.get()).latest_epoch;
            if self.epoch != latest_epoch {
                return Err(());
            }
            if (*self.tree.get()).writer {
                panic!("JsonRef::modify: writer active");
            }
            if (*self.tree.get()).readers != 0 {
                panic!("JsonRef::modify: reader active");
            }
            (*self.tree.get()).latest_epoch += 1;
            let mut node = self.node;
            (*self.tree.get()).writer = true;
            let ret = modify(node.as_mut());
            (*self.tree.get()).writer = false;
            Ok(ret)
        }
    }
}
