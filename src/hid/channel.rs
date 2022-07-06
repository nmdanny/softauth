use std::collections::BTreeSet;

pub const BROADCAST_CHANNEL: u32 = 0xffffffff;
pub const RESERVED_CHANNEL: u32 = 0;

pub struct ChannelAllocator {
    used: BTreeSet<u32>
}

impl ChannelAllocator {
    pub fn new() -> Self {
       ChannelAllocator { used: BTreeSet::new() } 
    }

    pub fn is_allocated(&self, chan: u32) -> bool {
        self.used.contains(&chan)
    }

    pub fn allocate(&mut self) -> Option<u32> {
        for i in 1 .. BROADCAST_CHANNEL {
            if self.used.insert(i) {
                return Some(i);
            }
        }
        None
    }

    pub fn free(&mut self, chan: u32) {
        self.used.remove(&chan);
    }
}