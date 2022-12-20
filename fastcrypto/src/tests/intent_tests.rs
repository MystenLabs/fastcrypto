// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::intent::{Intent, IntentMessage, IntentScope};

#[test]
fn test_intent_msg_serde() {
    let msg = IntentMessage::new(Intent::default(), "test".to_string());
    let serialized = bcs::to_bytes(&msg).unwrap();
    assert_eq!(serialized[..3], [0, 0, 0]);

    let msg = IntentMessage::new(
        Intent::default().with_scope(IntentScope::PersonalMessage),
        "test".to_string(),
    );
    let serialized = bcs::to_bytes(&msg).unwrap();
    assert_eq!(serialized[..3], [2, 0, 0]);
}
