// SPDX-License-Identifier: GPL-2.0-only

//! Stable built-in failure-class identities shared by policy metadata and placement.

use crate::FaultGroupClassId;

const MACHINE_CLASS_BYTES: [u8; 16] = [
    0x6d, 0x65, 0x73, 0x68, 0x73, 0x70, 0x81, 0x6e, 0xad, 0x6d, 0x61, 0x63, 0x68, 0x69, 0x6e, 0x65,
];
const STORAGE_DEVICE_CLASS_BYTES: [u8; 16] = [
    0x6d, 0x65, 0x73, 0x68, 0x73, 0x70, 0x82, 0x6e, 0xae, 0x64, 0x65, 0x76, 0x69, 0x63, 0x65, 0x21,
];

/// Returns the stable class for one physical or virtual machine becoming unavailable.
#[must_use]
pub fn machine_fault_class_id() -> FaultGroupClassId {
    identifier(MACHINE_CLASS_BYTES)
}

/// Returns the stable class for one independently addressable storage target becoming unavailable.
#[must_use]
pub fn storage_device_fault_class_id() -> FaultGroupClassId {
    identifier(STORAGE_DEVICE_CLASS_BYTES)
}

fn identifier(bytes: [u8; 16]) -> FaultGroupClassId {
    match FaultGroupClassId::from_bytes(bytes) {
        Ok(value) => value,
        Err(_) => unreachable!("built-in fault-class identity is statically non-nil"),
    }
}

#[cfg(test)]
mod tests {
    use super::{machine_fault_class_id, storage_device_fault_class_id};

    #[test]
    fn built_in_fault_classes_are_stable_distinct_uuid_v8_values() {
        let machine = machine_fault_class_id();
        let device = storage_device_fault_class_id();
        assert_ne!(machine, device);
        assert_eq!(machine.as_bytes()[6] >> 4, 8);
        assert_eq!(device.as_bytes()[6] >> 4, 8);
        assert_eq!(machine.as_bytes()[8] >> 6, 2);
        assert_eq!(device.as_bytes()[8] >> 6, 2);
    }
}
