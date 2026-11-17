use std::collections::HashSet;
use std::net::Ipv4Addr;

use super::*;

pub const OPCODE_EXTERNAL_RECEIVER_SUBSCRIPTION: u16 = 0x3201;
pub const EXTERNAL_RTP_DEFAULT_PORT: u16 = 4321;

const EXTERNAL_SUBSCRIPTION_PROTOCOL_CAP: u16 = 0x2809;
const DESTINATION_DESCRIPTOR_SIZE: usize = 8;
const IDENTITY_DESCRIPTOR_SIZE: usize = 0x20;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExternalRtpDestination {
    pub address: Ipv4Addr,
    pub port: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExternalFlowIdentity {
    pub source_address: Ipv4Addr,
    pub session_id: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExternalReceiverSubscription<'a> {
    pub device_protocol: u16,
    pub receiver_channel_ids: &'a [u16],
    pub flow_slot_assignments: &'a [u16],
    pub advertised_flow_slot_count: u16,
    pub flow_identity: ExternalFlowIdentity,
    pub clock_offset: u32,
    pub primary_destination: ExternalRtpDestination,
    pub secondary_destination: Option<ExternalRtpDestination>,
    pub advertisement_supports_multiple_interfaces: bool,
    pub receiver_supports_multiple_interfaces: bool,
}

fn checked_pointer(offset: usize) -> Result<u16, NetaudioError> {
    u16::try_from(offset).map_err(|_| NetaudioError::PacketTooLarge)
}

fn destination_descriptor(destination: ExternalRtpDestination) -> Result<[u8; 8], NetaudioError> {
    if destination.address.is_unspecified() {
        return Err(NetaudioError::InvalidDestination);
    }
    let port = if destination.port == 0 {
        EXTERNAL_RTP_DEFAULT_PORT
    } else {
        destination.port
    };
    let mut descriptor = [0u8; DESTINATION_DESCRIPTOR_SIZE];
    descriptor[0] = DESTINATION_DESCRIPTOR_SIZE as u8;
    descriptor[1] = 2;
    descriptor[2..4].copy_from_slice(&port.to_be_bytes());
    descriptor[4..8].copy_from_slice(&destination.address.octets());
    Ok(descriptor)
}

// Dante Controller's 0x3201 body (protocol 0x2809), decoded from a genuine Dante
// Controller capture of an AES67 subscription (receiver ch 8 <- slot 2 of a
// two-channel SAP stream) and checked against an AVIO-USB (Dante 4.2.4.1), which
// echoes the created flow in the same form. Offsets below are packet offsets
// (the 8-byte ARC header included); the body's pointers are packet offsets too.
//
//   0x08 u16 0             0x0a u16 0x0101         0x0c u16 0x0010
//   0x10 u16 flow id (0 = create a new receive flow)
//   0x12 u16 0x4202 (RTP/AES67 receive flow)
//   0x14 u32 sample rate, 0x18 u32 encoding (0: taken from the announcement)
//   0x1c u16 destination count, 0x22 u16 pointer to the first destination
//   0x2c u16 3, u16 pointer to the flow identity
//   0x30 u32 latency in ns (0: the device default, 2 ms on the AVIO-USB)
//   0x34 u16 2, u16 pointer to the channel map
//   identity (32 bytes): 0x10 0x00, u16 0x000B, source IPv4, u64 SDP session id, zeros
//   channel map: u16 first receiver channel, u16 byte count n (even),
//                u16 0, then n bytes: the flow slot (1-based, 0 = none) of
//                receiver channels first, first+1, ...
//   destination (8 bytes): 0x08 0x02, u16 port, IPv4 group
//
// The previous bitmap body (0x0000 0x0202 ...) was inferred without a capture:
// Dante 4.2.4.1 acknowledges it with a 16-byte stub and creates no flow.
const RTP_FLOW_FIXED_SIZE: usize = 0x40;

fn identity_descriptor(
    identity: ExternalFlowIdentity,
    clock_offset: u32,
) -> Result<[u8; IDENTITY_DESCRIPTOR_SIZE], NetaudioError> {
    if identity.source_address.is_unspecified() || identity.session_id == 0 {
        return Err(NetaudioError::InvalidFlowIdentity);
    }
    let mut descriptor = [0u8; IDENTITY_DESCRIPTOR_SIZE];
    descriptor[0] = 0x10;
    descriptor[2..4].copy_from_slice(&0x000Bu16.to_be_bytes());
    descriptor[4..8].copy_from_slice(&identity.source_address.octets());
    descriptor[8..16].copy_from_slice(&identity.session_id.to_be_bytes());
    // Dante Controller sends zeros here for a mediaclk:direct=0 stream; a
    // non-zero offset at this position is unverified.
    descriptor[24..28].copy_from_slice(&clock_offset.to_be_bytes());
    Ok(descriptor)
}

fn validated_destinations(
    specification: &ExternalReceiverSubscription<'_>,
) -> Result<Vec<[u8; DESTINATION_DESCRIPTOR_SIZE]>, NetaudioError> {
    let mut destinations = vec![destination_descriptor(specification.primary_destination)?];
    if let Some(secondary) = specification.secondary_destination {
        if !specification.advertisement_supports_multiple_interfaces
            || !specification.receiver_supports_multiple_interfaces
        {
            return Err(NetaudioError::InvalidDestination);
        }
        destinations.push(destination_descriptor(secondary)?);
    }
    Ok(destinations)
}

fn validate_mapping(specification: &ExternalReceiverSubscription<'_>) -> Result<(), NetaudioError> {
    if specification.receiver_channel_ids.is_empty()
        || specification.receiver_channel_ids.len() != specification.flow_slot_assignments.len()
        || specification.advertised_flow_slot_count == 0
    {
        return Err(NetaudioError::InvalidReceiverMapping);
    }
    let mut receiver_ids = HashSet::with_capacity(specification.receiver_channel_ids.len());
    for (&receiver_id, &slot) in specification
        .receiver_channel_ids
        .iter()
        .zip(specification.flow_slot_assignments)
    {
        if receiver_id == 0 || !receiver_ids.insert(receiver_id) {
            return Err(NetaudioError::InvalidReceiverMapping);
        }
        if slot > specification.advertised_flow_slot_count || slot > u16::from(u8::MAX) {
            return Err(NetaudioError::InvalidFlowSlot);
        }
    }
    // Removal is not expressed with this opcode (the device ignores an all-zero
    // map); receiver channels are cleared with the subscription-removal command.
    if specification
        .flow_slot_assignments
        .iter()
        .all(|&slot| slot == 0)
    {
        return Err(NetaudioError::InvalidReceiverMapping);
    }
    Ok(())
}

fn channel_map(specification: &ExternalReceiverSubscription<'_>) -> Result<Vec<u8>, NetaudioError> {
    let first = *specification
        .receiver_channel_ids
        .iter()
        .min()
        .ok_or(NetaudioError::InvalidReceiverMapping)?;
    let last = *specification
        .receiver_channel_ids
        .iter()
        .max()
        .ok_or(NetaudioError::InvalidReceiverMapping)?;
    let span = usize::from(last - first) + 1;
    let padded = span + (span & 1);
    let mut map = Vec::with_capacity(6 + padded);
    map.extend_from_slice(&first.to_be_bytes());
    map.extend_from_slice(
        &u16::try_from(padded)
            .map_err(|_| NetaudioError::PacketTooLarge)?
            .to_be_bytes(),
    );
    map.extend_from_slice(&0u16.to_be_bytes());
    let mut slots = vec![0u8; padded];
    for (&receiver_id, &slot) in specification
        .receiver_channel_ids
        .iter()
        .zip(specification.flow_slot_assignments)
    {
        slots[usize::from(receiver_id - first)] =
            u8::try_from(slot).map_err(|_| NetaudioError::InvalidFlowSlot)?;
    }
    map.extend_from_slice(&slots);
    Ok(map)
}

fn build_rtp_flow_payload(
    specification: &ExternalReceiverSubscription<'_>,
    destinations: &[[u8; DESTINATION_DESCRIPTOR_SIZE]],
    identity: &[u8; IDENTITY_DESCRIPTOR_SIZE],
) -> Result<Vec<u8>, NetaudioError> {
    const HEADER: usize = 8;
    let map = channel_map(specification)?;
    let identity_offset = RTP_FLOW_FIXED_SIZE;
    let map_offset = identity_offset + IDENTITY_DESCRIPTOR_SIZE;
    let destination_offset = map_offset + map.len();
    let total = destination_offset + destinations.len() * DESTINATION_DESCRIPTOR_SIZE;
    checked_pointer(total)?;

    let mut payload = vec![0u8; RTP_FLOW_FIXED_SIZE - HEADER];
    let mut put = |offset: usize, bytes: &[u8]| {
        payload[offset - HEADER..offset - HEADER + bytes.len()].copy_from_slice(bytes);
    };
    put(0x0a, &0x0101u16.to_be_bytes());
    put(0x0c, &0x0010u16.to_be_bytes());
    put(0x12, &0x4202u16.to_be_bytes());
    put(
        0x1c,
        &u16::try_from(destinations.len())
            .map_err(|_| NetaudioError::PacketTooLarge)?
            .to_be_bytes(),
    );
    // One pointer per destination from 0x22 on. Only the single-destination
    // form is confirmed by a capture; a secondary pointer at 0x24 is inferred.
    for index in 0..destinations.len() {
        let pointer = destination_offset + index * DESTINATION_DESCRIPTOR_SIZE;
        put(0x22 + 2 * index, &checked_pointer(pointer)?.to_be_bytes());
    }
    put(0x2c, &3u16.to_be_bytes());
    put(0x2e, &checked_pointer(identity_offset)?.to_be_bytes());
    put(0x34, &2u16.to_be_bytes());
    put(0x36, &checked_pointer(map_offset)?.to_be_bytes());

    payload.extend_from_slice(identity);
    payload.extend_from_slice(&map);
    for destination in destinations {
        payload.extend_from_slice(destination);
    }
    debug_assert_eq!(payload.len() + HEADER, total);
    Ok(payload)
}

pub fn build_external_receiver_subscription(
    specification: &ExternalReceiverSubscription<'_>,
    message_id: u16,
) -> Result<Vec<u8>, NetaudioError> {
    if !crate::protocol::is_supported_arc_protocol(specification.device_protocol) {
        return Err(NetaudioError::UnsupportedProtocolOperation);
    }

    validate_mapping(specification)?;
    let destinations = validated_destinations(specification)?;
    let identity = identity_descriptor(specification.flow_identity, specification.clock_offset)?;
    let payload = build_rtp_flow_payload(specification, &destinations, &identity)?;
    build_control_packet_for_protocol(
        specification
            .device_protocol
            .min(EXTERNAL_SUBSCRIPTION_PROTOCOL_CAP),
        OPCODE_EXTERNAL_RECEIVER_SUBSCRIPTION,
        &payload,
        message_id,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    // Genuine Dante Controller request (rgon/network-audio-controller#10,
    // connect-to-an-rtp-stream.pcapng frame 4170): X32 receiver channel 8 <-
    // slot 2 of "PipeWire RTP lappi-stream", o= session 3977036942 from
    // 169.254.184.43, c= 239.69.150.243, port 5004.
    const DANTE_CONTROLLER_3201: &str = "2809007000253201000001010010000000004202000000000000000000010000000000680000000000000000000300400000000000020060\
        00000000000000001000000ba9feb82b00000000ed0cc48e0000000000000000000000000000000000080002000002000802138cef4596f3";

    fn hex(text: &str) -> Vec<u8> {
        let text: String = text.split_whitespace().collect();
        (0..text.len())
            .step_by(2)
            .map(|index| u8::from_str_radix(&text[index..index + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn matches_dante_controller_capture() {
        let packet = build_external_receiver_subscription(
            &ExternalReceiverSubscription {
                device_protocol: 0x2809,
                receiver_channel_ids: &[8],
                flow_slot_assignments: &[2],
                advertised_flow_slot_count: 2,
                flow_identity: ExternalFlowIdentity {
                    source_address: Ipv4Addr::new(169, 254, 184, 43),
                    session_id: 3_977_036_942,
                },
                clock_offset: 0,
                primary_destination: ExternalRtpDestination {
                    address: Ipv4Addr::new(239, 69, 150, 243),
                    port: 5004,
                },
                secondary_destination: None,
                advertisement_supports_multiple_interfaces: false,
                receiver_supports_multiple_interfaces: false,
            },
            0x0025,
        )
        .unwrap();
        assert_eq!(packet, hex(DANTE_CONTROLLER_3201));
    }

    #[test]
    fn maps_each_receiver_channel_to_its_slot() {
        let packet = build_external_receiver_subscription(
            &ExternalReceiverSubscription {
                device_protocol: 0x2809,
                receiver_channel_ids: &[2, 1],
                flow_slot_assignments: &[2, 1],
                advertised_flow_slot_count: 2,
                flow_identity: ExternalFlowIdentity {
                    source_address: Ipv4Addr::new(192, 168, 10, 168),
                    session_id: 2_925_985_796,
                },
                clock_offset: 0,
                primary_destination: ExternalRtpDestination {
                    address: Ipv4Addr::new(239, 253, 116, 174),
                    port: 5004,
                },
                secondary_destination: None,
                advertisement_supports_multiple_interfaces: false,
                receiver_supports_multiple_interfaces: false,
            },
            1,
        )
        .unwrap();
        // first receiver 1, two map bytes, slots 1 and 2
        assert_eq!(&packet[0x60..0x68], &[0, 1, 0, 2, 0, 0, 1, 2]);
        assert_eq!(&packet[0x68..], &[8, 2, 0x13, 0x8C, 239, 253, 116, 174]);
    }
}
