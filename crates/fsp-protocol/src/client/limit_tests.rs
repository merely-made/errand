use super::*;
use crate::wire::{EntryKind, RDTYPE_END, RDTYPE_FILE, RDTYPE_SKIP};

type Reply = (Command, u32, Vec<u8>, Vec<u8>);

async fn fixture(limits: Limits, replies: Vec<Reply>) -> (Session, tokio::task::JoinHandle<()>) {
    let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = server.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let mut buffer = vec![0; 65_536];
        for (index, (command, offset, data, extra)) in replies.into_iter().enumerate() {
            let (read, peer) =
                tokio::time::timeout(Duration::from_secs(3), server.recv_from(&mut buffer))
                    .await
                    .expect("fixture request deadline")
                    .unwrap();
            let request = decode(&buffer[..read], Direction::ClientToServer).unwrap();
            assert_eq!(request.header.command, command.code());
            assert_eq!(request.header.file_position, offset);
            assert_eq!(
                request.header.key, index as u16,
                "server key must be echoed"
            );
            let packet = Packet {
                header: Header {
                    command: command.code(),
                    key: (index + 1) as u16,
                    sequence: request.header.sequence,
                    data_length: u16::try_from(data.len()).unwrap(),
                    file_position: offset,
                },
                data,
                extra,
            };
            server
                .send_to(&encode(&packet, Direction::ServerToClient), peer)
                .await
                .unwrap();
        }
    });
    let session = Session::connect_with_limits("127.0.0.1", Some(address.port()), limits)
        .await
        .unwrap();
    (session, task)
}

fn entry(name: &str) -> Vec<u8> {
    let mut bytes = 123u32.to_be_bytes().to_vec();
    bytes.extend_from_slice(&u32::MAX.to_be_bytes());
    bytes.push(RDTYPE_FILE);
    bytes.extend_from_slice(name.as_bytes());
    bytes.push(0);
    bytes.resize(bytes.len().div_ceil(4) * 4, 0);
    bytes
}

fn marker(kind: u8) -> Vec<u8> {
    let mut bytes = vec![0; 12];
    bytes[8] = kind;
    bytes
}

#[test]
fn default_budgets_and_offset_arithmetic_are_explicit() {
    let limits = Limits::default();
    assert_eq!(limits.max_request_bytes, HEADER_LEN + MAX_PAYLOAD);
    assert_eq!(limits.max_datagram_bytes, HEADER_LEN + 2 * MAX_PAYLOAD);
    assert_eq!(limits.max_file_bytes, 64 * 1024 * 1024);
    assert_eq!(limits.max_directory_bytes, 8 * 1024 * 1024);
    assert_eq!(limits.max_directory_entries, 65_536);
    assert_eq!(advance_offset(u32::MAX - 2, 2), Ok(u32::MAX));
    assert_eq!(
        advance_offset(u32::MAX - 2, 3),
        Err(ClientError::OffsetOverflow)
    );
    assert_eq!(
        advance_offset(0, usize::MAX),
        Err(ClientError::OffsetOverflow)
    );
}

#[tokio::test]
async fn file_cap_accepts_full_block_then_eof_and_refuses_one_extra() {
    for extra in [false, true] {
        let replies = vec![
            (Command::GetFile, 0, vec![b'x'; MAX_PAYLOAD], vec![]),
            (
                Command::GetFile,
                MAX_PAYLOAD as u32,
                if extra { vec![b'y'] } else { vec![] },
                vec![],
            ),
        ];
        let limits = Limits {
            max_file_bytes: MAX_PAYLOAD,
            ..Default::default()
        };
        let (mut session, task) = fixture(limits, replies).await;
        assert_eq!(session.attempts, 3);
        assert_eq!(session.timeout, RESEND_AFTER);
        let result = session.get_file("/x").await;
        if extra {
            assert_eq!(
                result.unwrap_err(),
                ClientError::LimitExceeded {
                    what: "file bytes",
                    max: MAX_PAYLOAD
                }
            );
        } else {
            assert_eq!(result.unwrap(), vec![b'x'; MAX_PAYLOAD]);
        }
        task.await.unwrap();
    }
    for data in [vec![], vec![b'x']] {
        let empty = data.is_empty();
        let (mut session, task) = fixture(
            Limits {
                max_file_bytes: 0,
                ..Default::default()
            },
            vec![(Command::GetFile, 0, data, vec![])],
        )
        .await;
        let result = session.get_file("/").await;
        if empty {
            assert_eq!(result.unwrap(), b"");
        } else {
            assert!(matches!(
                result,
                Err(ClientError::LimitExceeded {
                    what: "file bytes",
                    ..
                })
            ));
        }
        task.await.unwrap();
    }
}

#[tokio::test]
async fn larger_than_minimum_blocks_remain_native_and_caller_bounded() {
    let size = MAX_PAYLOAD * 2;
    let (mut session, task) = fixture(
        Limits {
            max_file_bytes: size,
            ..Default::default()
        },
        vec![
            (Command::GetFile, 0, vec![b'x'; size], vec![]),
            (Command::GetFile, size as u32, vec![], vec![]),
        ],
    )
    .await;
    assert_eq!(session.get_file("/").await.unwrap().len(), size);
    task.await.unwrap();
}

#[tokio::test]
async fn directory_aggregate_bytes_and_entries_are_bounded_across_many_blocks() {
    let count = 32;
    let raw = entry("x");
    for max in [raw.len() * count, raw.len() * count - 1] {
        let mut replies = (0..count)
            .map(|index| {
                (
                    Command::GetDir,
                    (index * raw.len()) as u32,
                    raw.clone(),
                    vec![],
                )
            })
            .collect::<Vec<_>>();
        if max == raw.len() * count {
            replies.push((Command::GetDir, (count * raw.len()) as u32, vec![], vec![]));
        }
        let (mut session, task) = fixture(
            Limits {
                max_directory_bytes: max,
                max_directory_entries: count,
                ..Default::default()
            },
            replies,
        )
        .await;
        let result = session.list("/").await;
        if max == raw.len() * count {
            let entries = result.unwrap();
            assert_eq!(entries.len(), count);
            assert_eq!(
                entries[0].size,
                u32::MAX,
                "advertised file sizes remain inert metadata"
            );
            assert_eq!(entries[0].kind, EntryKind::File);
        } else {
            assert_eq!(
                result.unwrap_err(),
                ClientError::LimitExceeded {
                    what: "directory bytes",
                    max
                }
            );
        }
        task.await.unwrap();
    }
    let replies = (0..3)
        .map(|index| {
            (
                Command::GetDir,
                (index * raw.len()) as u32,
                raw.clone(),
                vec![],
            )
        })
        .collect();
    let (mut session, task) = fixture(
        Limits {
            max_directory_entries: 2,
            ..Default::default()
        },
        replies,
    )
    .await;
    assert_eq!(
        session.list("/").await.unwrap_err(),
        ClientError::LimitExceeded {
            what: "directory entries",
            max: 2
        }
    );
    task.await.unwrap();
}

#[tokio::test]
async fn directory_skip_advances_and_end_stops_even_after_entries() {
    let mut final_block = entry("saved");
    final_block.extend(marker(RDTYPE_END));
    final_block.extend(entry("ignored"));
    let (mut session, task) = fixture(
        Limits::default(),
        vec![
            (Command::GetDir, 0, marker(RDTYPE_SKIP), vec![]),
            (Command::GetDir, 12, final_block, vec![]),
        ],
    )
    .await;
    let entries = session.list("/").await.unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].name, "saved");
    task.await.unwrap();
}

#[tokio::test]
async fn reply_data_and_extra_caps_are_checked_without_flattening_native_packet() {
    for (data, extra, expected) in [
        (4, 4, None),
        (5, 0, Some("reply data")),
        (0, 5, Some("reply extra data")),
    ] {
        let limits = Limits {
            max_data_bytes: 4,
            max_extra_bytes: 4,
            ..Default::default()
        };
        let (mut session, task) = fixture(
            limits,
            vec![(
                Command::Version,
                u32::MAX,
                vec![b'd'; data],
                vec![b'e'; extra],
            )],
        )
        .await;
        let result = session.request(Command::Version, &[], u32::MAX).await;
        if let Some(what) = expected {
            assert_eq!(
                result.unwrap_err(),
                ClientError::LimitExceeded { what, max: 4 }
            );
        } else {
            let packet = result.unwrap();
            assert_eq!(packet.data, b"dddd");
            assert_eq!(packet.extra, b"eeee");
            assert_eq!(packet.header.file_position, u32::MAX);
        }
        task.await.unwrap();
    }
}

#[tokio::test]
async fn oversized_datagram_cannot_be_a_valid_prefix_success() {
    for extra in [0, 1, 32] {
        // Zero extra bytes preserve the checksum of the valid first16 bytes,
        // so truncation to the old receive budget would decode successfully.
        let limits = Limits {
            max_datagram_bytes: HEADER_LEN + 4,
            ..Default::default()
        };
        let (mut session, task) = fixture(
            limits,
            vec![(Command::GetFile, 0, b"data".to_vec(), vec![0; extra])],
        )
        .await;
        let result = session.get_file_block("/x", 0).await;
        if extra == 0 {
            assert_eq!(result.unwrap(), b"data");
        } else {
            assert!(
                matches!(
                    result,
                    Err(ClientError::LimitExceeded {
                        what: "reply datagram",
                        ..
                    })
                ),
                "{result:?}"
            );
        }
        task.await.unwrap();
    }
}

#[tokio::test]
async fn request_path_and_u16_data_limits_refuse_before_contact() {
    let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = server.local_addr().unwrap();
    let mut session = Session::connect_with_limits(
        "127.0.0.1",
        Some(address.port()),
        Limits {
            max_request_bytes: HEADER_LEN + 3,
            ..Default::default()
        },
    )
    .await
    .unwrap();
    assert_eq!(
        session.get_file_block("/xx", 0).await.unwrap_err(),
        ClientError::LimitExceeded {
            what: "request",
            max: HEADER_LEN + 3
        }
    );
    assert_eq!(
        session.sequence, 1,
        "local refusal must not consume a sequence"
    );
    let mut buffer = [0; 64];
    assert!(
        tokio::time::timeout(Duration::from_millis(30), server.recv_from(&mut buffer))
            .await
            .is_err()
    );
    let mut session = Session::connect_with_limits(
        "127.0.0.1",
        Some(address.port()),
        Limits {
            max_request_bytes: usize::MAX,
            ..Default::default()
        },
    )
    .await
    .unwrap();
    assert_eq!(
        session
            .request(Command::Version, &vec![0; usize::from(u16::MAX) + 1], 0)
            .await
            .unwrap_err(),
        ClientError::LimitExceeded {
            what: "request data",
            max: usize::from(u16::MAX)
        }
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(30), server.recv_from(&mut buffer))
            .await
            .is_err()
    );
    let (mut session, task) = fixture(
        Limits {
            max_request_bytes: HEADER_LEN + 3,
            ..Default::default()
        },
        vec![(Command::GetFile, 0, b"ok".to_vec(), vec![])],
    )
    .await;
    assert_eq!(session.get_file_block("/x", 0).await.unwrap(), b"ok");
    task.await.unwrap();
}
