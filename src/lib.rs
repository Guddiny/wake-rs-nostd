//! `no_std` encoder/decoder for the Wake (`FEND`/`FESC` byte-stuffed) packet format.
//!
//! All buffers are fixed-capacity [`heapless::Vec`]s, so an allocator is not required.`
#![cfg_attr(not(test), no_std)]

use core::error::Error;
use core::fmt::{Display, Formatter};
use heapless::Vec;

const FEND: u8 = 0xc0;
const FESC: u8 = 0xdb;
const TFEND: u8 = 0xdc;
const TFESC: u8 = 0xdd;

const ADDR_MASK: u8 = 0x80;
const CRC_INIT: u8 = 0xde;
const PACKET_MIN_LEN: usize = 4;

/// Maximum supported data length. Might be reduced depends on available resources.
pub const DATA_MAX_LEN: usize = 255;

/// Maximum size of a de-stuffed packet: `FEND` + address + command + length + data + CRC.
pub const PACKET_MAX_LEN: usize = DATA_MAX_LEN + 5;

/// Maximum size of a stuffed packet. Worst case every byte after `FEND` is escaped.
pub const ENCODED_MAX_LEN: usize = 1 + 2 * (PACKET_MAX_LEN - 1);

/// Buffer holding packet data.
pub type PacketData = Vec<u8, DATA_MAX_LEN>;

/// Buffer holding a de-stuffed (raw) packet.
pub type RawPacket = Vec<u8, PACKET_MAX_LEN>;

/// Buffer holding a stuffed packet, ready to be transmitted.
pub type EncodedPacket = Vec<u8, ENCODED_MAX_LEN>;

/// Wake decoder/encoder errors
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum WakeError {
    TooShortPacket,
    CannotFindStart,
    DestuffingFailed,
    WrongPacketLength,
    WrongPacketCrc,
    WrongAddrRange,
    WrongCmdRange,
}

impl Error for WakeError {}

impl Display for WakeError {
    fn fmt(&self, f: &mut Formatter) -> core::fmt::Result {
        f.write_str(match *self {
            WakeError::TooShortPacket => "Wake error: Too short packet",
            WakeError::CannotFindStart => "Wake error: Can't find a start of the packet",
            WakeError::DestuffingFailed => "Wake error: De-stuffing failed",
            WakeError::WrongPacketLength => "Wake error: Wrong packet length",
            WakeError::WrongPacketCrc => "Wake error: Wrong packet CRC",
            WakeError::WrongAddrRange => "Wake error: Address is out of range [0 - 127]",
            WakeError::WrongCmdRange => "Wake error: Command is out of range [0 - 127]",
        })
    }
}

/// Wake packet: address, command, and data
#[derive(Default, Debug)]
pub struct Packet {
    /// Device address (optional) [0 - 127]
    pub address: Option<u8>,
    /// Command [0 - 127]
    pub command: u8,
    /// Data load (optional)
    pub data: Option<PacketData>,
}

impl core::fmt::Display for Packet {
    /// Show error in human readable format
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self.address {
            Some(a) => writeln!(f, "ADDR: 0x{:02X}", a)?,
            None => f.write_str("ADDR: ----\n")?,
        }

        writeln!(f, "CMD:  0x{:02X}", self.command)?;

        match &self.data {
            Some(d) => {
                writeln!(f, "DATA: {} bytes", d.len())?;
                f.write_str("     0  1  2  3  4  5  6  7  8  9  a  b  c  d  e  f")?;
                for (i, item) in d.iter().enumerate() {
                    if i % 16 == 0 {
                        write!(f, "\n{:02x}: ", i)?;
                    }
                    write!(f, "{:02x} ", item)?;
                }
                writeln!(f)
            }
            None => writeln!(f, "DATA: none"),
        }
    }
}

#[cfg(feature = "defmt")]
impl defmt::Format for WakeError {
    fn format(&self, f: defmt::Formatter) {
        defmt::write!(f, "{}", defmt::Display2Format(self));
    }
}

#[cfg(feature = "defmt")]
impl defmt::Format for Packet {
    /// Show the packet in a human readable format, e.g.
    ///
    /// ```text
    /// {
    ///   ADDR: 0x11
    ///   CMD:  0x03
    ///   DATA: 2 bytes
    ///   00: 11 12
    /// }
    /// ```
    fn format(&self, f: defmt::Formatter) {
        /// Number of data bytes printed per row.
        const BYTES_PER_ROW: usize = 16;

        defmt::write!(f, "{{\n");
        match self.address {
            Some(a) => defmt::write!(f, "  ADDR: 0x{:02X}\n", a),
            None => defmt::write!(f, "  ADDR: ----\n"),
        }
        defmt::write!(f, "  CMD:  0x{:02X}\n", self.command);
        match &self.data {
            Some(d) => {
                defmt::write!(f, "  DATA: {} bytes\n", d.len());
                for (row, chunk) in d.chunks(BYTES_PER_ROW).enumerate() {
                    defmt::write!(f, "  {:02x}:", row * BYTES_PER_ROW);
                    for byte in chunk {
                        defmt::write!(f, " {:02x}", byte);
                    }
                    defmt::write!(f, "\n");
                }
            }
            None => defmt::write!(f, "  DATA: none\n"),
        }
        defmt::write!(f, "}}")
    }
}

trait Wake {
    fn crc(&self) -> u8;
    fn stuff(&self) -> Result<EncodedPacket, WakeError>;
    fn dry(&self) -> Result<RawPacket, WakeError>;
}

/// Calculate CRC sum of data in a byte slice
impl Wake for [u8] {
    /// # Input
    ///
    /// * `[u8]` - input data
    ///
    /// # Output
    ///
    /// * `u8` - Calculated CRC
    ///
    fn crc(&self) -> u8 {
        let mut crc: u8 = CRC_INIT;

        let mut crc8 = |data| {
            let mut b = data;
            for _ in 0..8 {
                crc = if (b ^ crc) & 1 == 1 {
                    ((crc ^ 0x18) >> 1) | 0x80
                } else {
                    (crc >> 1) & !0x80
                };
                b >>= 1;
            }
        };

        for n in self {
            crc8(*n);
        }
        crc
    }

    /// Byte stuffing in a buffer
    ///
    /// # Arguments
    ///
    /// * `data: &[u8]` - input data starting with `FEND`
    ///
    /// # Output
    ///
    /// * `Result<EncodedPacket, WakeError>` - output data
    ///
    fn stuff(&self) -> Result<EncodedPacket, WakeError> {
        // without CRC
        if self.len() < (PACKET_MIN_LEN - 1) {
            return Err(WakeError::TooShortPacket);
        }
        if self[0] != FEND {
            return Err(WakeError::CannotFindStart);
        }

        let mut stuffed = EncodedPacket::new();
        stuffed
            .push(FEND)
            .map_err(|_| WakeError::WrongPacketLength)?;
        for &x in &self[1..] {
            match x {
                FESC => {
                    stuffed
                        .push(FESC)
                        .map_err(|_| WakeError::WrongPacketLength)?;
                    stuffed
                        .push(TFESC)
                        .map_err(|_| WakeError::WrongPacketLength)?;
                }
                FEND => {
                    stuffed
                        .push(FESC)
                        .map_err(|_| WakeError::WrongPacketLength)?;
                    stuffed
                        .push(TFEND)
                        .map_err(|_| WakeError::WrongPacketLength)?;
                }
                _ => stuffed.push(x).map_err(|_| WakeError::WrongPacketLength)?,
            }
        }
        Ok(stuffed)
    }

    /// Byte destuffing in a buffer
    ///
    /// Translate stuffed bytes into normal data
    ///
    /// # Arguments
    ///
    /// * `data` - Input data
    ///
    /// # Output
    ///
    /// * `Result<RawPacket, WakeError>` - Destuffed data wrapped in Result
    ///
    fn dry(&self) -> Result<RawPacket, WakeError> {
        let mut output = RawPacket::new();
        let mut i = 0;
        while i < self.len() {
            match self[i] {
                FESC => {
                    if i + 1 >= self.len() {
                        return Err(WakeError::WrongPacketLength);
                    }
                    let byte = match self[i + 1] {
                        TFESC => FESC,
                        TFEND => FEND,
                        _ => return Err(WakeError::DestuffingFailed),
                    };
                    output
                        .push(byte)
                        .map_err(|_| WakeError::WrongPacketLength)?;
                    i += 1;
                }
                byte => output
                    .push(byte)
                    .map_err(|_| WakeError::WrongPacketLength)?,
            }
            i += 1;
        }
        Ok(output)
    }
}

/// Decode data from wake format to wake packet structure
pub trait Decode {
    fn decode(&self) -> Result<Packet, WakeError>;
}

/// Decode a byte slice from wake format to wake packet structure
impl Decode for [u8] {
    /// # Output
    ///
    /// * `Result<Packet, WakeError>` - command, data or error
    ///
    /// # Example
    ///
    /// ```
    /// use wake::{Decode, EncodedPacket};
    ///
    /// let mut encoded_packet = EncodedPacket::new();
    /// encoded_packet
    ///     .extend_from_slice(&[0xc0, 0x03, 0x05, 1, 2, 3, 4, 5, 0x6b])
    ///     .unwrap();
    /// let decoded = encoded_packet.decode().unwrap();
    /// assert_eq!(decoded.command, 0x03);
    /// ```
    ///
    fn decode(&self) -> Result<Packet, WakeError> {
        // 1: Check packet length
        if self.len() < PACKET_MIN_LEN {
            return Err(WakeError::TooShortPacket);
        }
        // 2: Check START symbol (FEND)
        if self[0] != FEND {
            return Err(WakeError::CannotFindStart);
        }
        // 3: Dry packet (remove stuffed bytes)
        let destuffed_pkt = self.dry()?;

        let mut idx = 1; // skip start symbol
        // 4: Get an address (if exists) and a command
        let mut decoded = Packet::default();
        let first = *destuffed_pkt.get(idx).ok_or(WakeError::TooShortPacket)?;
        idx += 1;
        if first & ADDR_MASK != 0 {
            decoded.address = Some(first & !ADDR_MASK);
            decoded.command = *destuffed_pkt.get(idx).ok_or(WakeError::TooShortPacket)?;
            idx += 1;
        } else {
            decoded.command = first;
        }
        // 5: Get data length
        let data_len = *destuffed_pkt.get(idx).ok_or(WakeError::TooShortPacket)? as usize;
        idx += 1;
        // 6: Check data length (a CRC byte must follow the data)
        if destuffed_pkt.len().checked_sub(idx + 1) != Some(data_len) {
            return Err(WakeError::WrongPacketLength);
        }
        // 7: Get data
        if data_len > 0 {
            decoded.data = Some(
                PacketData::from_slice(&destuffed_pkt[idx..idx + data_len])
                    .map_err(|_| WakeError::WrongPacketLength)?,
            );
        }
        // 8: Check CRC (calculated over the whole packet except the CRC byte itself)
        let received_crc = destuffed_pkt[destuffed_pkt.len() - 1];
        if received_crc != destuffed_pkt[..destuffed_pkt.len() - 1].crc() {
            Err(WakeError::WrongPacketCrc)
        } else {
            Ok(decoded)
        }
    }
}

/// Encode packet to wake format
pub trait Encode {
    fn encode(&self) -> Result<EncodedPacket, WakeError>;
}

/// Encode packet to wake format
impl Encode for Packet {
    /// # Input
    ///
    /// * Wake packet structure with address, command code and data. Address and data are optional.
    ///
    /// # Output
    ///
    /// * `EncodedPacket` - Encoded data in wake format
    ///
    /// # Example
    ///
    /// ```
    /// use wake::{Encode, Packet, PacketData};
    ///
    /// let p = Packet {
    ///     address: Some(0x12),
    ///     command: 3,
    ///     data: PacketData::from_slice(&[0x00, 0xeb]).ok(),
    /// };
    /// let encoded_packet = p.encode().unwrap();
    /// assert_eq!(encoded_packet.len(), 7);
    /// ```
    ///
    fn encode(&self) -> Result<EncodedPacket, WakeError> {
        let mut encoded_packet = RawPacket::new();
        // 1. FEND
        encoded_packet
            .push(FEND)
            .map_err(|_| WakeError::WrongPacketLength)?;
        // 2. Address, if exists
        if let Some(addr) = self.address {
            if addr > 0x7f {
                return Err(WakeError::WrongAddrRange);
            }
            encoded_packet
                .push(addr | ADDR_MASK)
                .map_err(|_| WakeError::WrongPacketLength)?;
        }
        // 3. Command
        if self.command > 0x7f {
            return Err(WakeError::WrongCmdRange);
        }
        encoded_packet
            .push(self.command)
            .map_err(|_| WakeError::WrongPacketLength)?;
        // 4. Data length; data, if exists
        match &self.data {
            Some(d) => {
                encoded_packet
                    .push(d.len() as u8)
                    .map_err(|_| WakeError::WrongPacketLength)?;
                encoded_packet
                    .extend_from_slice(d)
                    .map_err(|_| WakeError::WrongPacketLength)?;
            }
            None => encoded_packet
                .push(0)
                .map_err(|_| WakeError::WrongPacketLength)?,
        }
        // 5. CRC
        encoded_packet
            .push(encoded_packet.crc())
            .map_err(|_| WakeError::WrongPacketLength)?;
        // 6. Stuffing
        encoded_packet.stuff()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build an `EncodedPacket` from a byte array.
    fn enc(bytes: &[u8]) -> EncodedPacket {
        EncodedPacket::from_slice(bytes).unwrap()
    }

    /// Build a `RawPacket` from a byte array.
    fn raw(bytes: &[u8]) -> RawPacket {
        RawPacket::from_slice(bytes).unwrap()
    }

    /// Build a `PacketData` from a byte array.
    fn data(bytes: &[u8]) -> PacketData {
        PacketData::from_slice(bytes).unwrap()
    }

    #[test]
    fn crc_test() {
        assert_eq!([1u8, 2, 3, 4, 5].crc(), 0xd6);
        assert_eq!([0xc0u8, 0x03, 0x00].crc(), 0xeb);
        assert_eq!([0xc0u8, 0x89, 0x03, 0x05, 1, 2, 3, 4, 5].crc(), 0x69);
    }

    #[test]
    fn stuff_test() {
        // Regular packet
        let a = enc(&[FEND, FESC, 1, 2, 3, 4, 5, FEND]); // initial_data
        let b = enc(&[FEND, FESC, TFESC, 1, 2, 3, 4, 5, FESC, TFEND]); // stuffed_data
        assert_eq!(a.as_slice().stuff(), Ok(b));

        // packet with min len
        let a = enc(&[FEND, 3, 0]);
        assert_eq!(a.as_slice().stuff(), Ok(a));

        // empty packet, should fail
        assert_eq!([].as_slice().stuff(), Err(WakeError::TooShortPacket));

        // short packet, should fail
        assert_eq!([FEND, 3].as_slice().stuff(), Err(WakeError::TooShortPacket));

        // packet without start symbol, should fail
        assert_eq!(
            [3u8, 0, 1].as_slice().stuff(),
            Err(WakeError::CannotFindStart)
        );
    }

    #[test]
    fn dry_test() {
        let t0: &[u8] = &[]; // empty
        let t1: &[u8] = &[0x34]; // 1 byte
        let t2: &[u8] = &[1, 2, 3, 4, 5, FEND]; // stuffed data without first FEND
        let t3: &[u8] = &[FEND, FESC, TFESC, 1, 2, 3, 4, 5, FESC]; // stuffed data without last byte
        let t4: &[u8] = &[FEND, FESC, 1, 2, 3, 4, 5, FESC, TFEND]; // stuffed data with missed 3rd byte
        let t5: &[u8] = &[FEND, FESC, TFESC, 1, 2, 3, 4, 5, FESC, TFEND]; // well stuffed data
        let a5: &[u8] = &[FEND, FESC, 1, 2, 3, 4, 5, FEND]; // destuffed t5
        assert_eq!(t0.dry(), Ok(RawPacket::new()));
        assert_eq!(t1.dry(), Ok(raw(t1)));
        assert_eq!(t2.dry(), Ok(raw(t2)));
        assert_eq!(t3.dry(), Err(WakeError::WrongPacketLength));
        assert_eq!(t4.dry(), Err(WakeError::DestuffingFailed));
        assert_eq!(t5.dry(), Ok(raw(a5)));
    }

    #[test]
    fn encode_packet_test() {
        // address is out of range
        let wp = Packet {
            address: Some(128),
            command: 9,
            data: Some(data(&[0x12, 0x34])),
        };
        assert_eq!(wp.encode(), Err(WakeError::WrongAddrRange));
        // command is out of range
        let wp = Packet {
            address: None,
            command: 128,
            data: Some(data(&[0x12, 0x34])),
        };
        assert_eq!(wp.encode(), Err(WakeError::WrongCmdRange));
        // without address
        let wp = Packet {
            address: None,
            command: 9,
            data: Some(data(&[0x12, 0x34])),
        };
        assert_eq!(wp.encode(), Ok(enc(&[FEND, 0x09, 0x02, 0x12, 0x34, 160])));
        // with data
        let wp = Packet {
            address: Some(0x12),
            command: 3,
            data: Some(data(&[0x00, 0xeb])),
        };
        assert_eq!(
            wp.encode(),
            Ok(enc(&[FEND, 0x92, 0x03, 0x02, 0x00, 0xeb, 114]))
        );
        // empty packet
        let wp = Packet {
            address: Some(0x13),
            command: 4,
            data: None,
        };
        assert_eq!(wp.encode(), Ok(enc(&[FEND, 0x93, 0x04, 0x00, 218])));
        // empty packet with stuffing
        let wp = Packet {
            address: Some(0x40),
            command: 0x40,
            data: None,
        };
        assert_eq!(wp.encode(), Ok(enc(&[FEND, FESC, TFEND, 0x40, 0x00, 229])));
    }

    #[test]
    fn decode_wo_address_test() {
        let command = 0x03u8;
        let payload = [1, 2, 3, 4, 5];
        let n = payload.len() as u8;
        let crc = [0x6b];
        let wrong_crc = [0x6c];

        let mut good_packet = enc(&[FEND, command, n]);
        good_packet.extend_from_slice(&payload).unwrap();
        good_packet.extend_from_slice(&crc).unwrap();
        let decoded = good_packet.decode().unwrap();
        assert_eq!(decoded.command, command);
        assert_eq!(decoded.data.unwrap(), data(&payload));

        let bad_packet_too_short = enc(&[FEND, command, n]);
        assert_eq!(
            bad_packet_too_short.decode().err(),
            Some(WakeError::TooShortPacket)
        );

        let mut bad_packet_wo_start = enc(&[command, n]);
        bad_packet_wo_start.extend_from_slice(&payload).unwrap();
        bad_packet_wo_start.extend_from_slice(&crc).unwrap();
        assert_eq!(
            bad_packet_wo_start.decode().err(),
            Some(WakeError::CannotFindStart)
        );

        // stuffed packed with wrong 3rd byte
        let bad_packet_wrong_stuffing = enc(&[FEND, FESC, FESC, 1, 2, 3, 4, 5, FESC, TFEND]);
        assert_eq!(
            bad_packet_wrong_stuffing.decode().err(),
            Some(WakeError::DestuffingFailed)
        );

        let mut bad_packet_short_data_len = enc(&[FEND, command, n - 1]);
        bad_packet_short_data_len
            .extend_from_slice(&payload)
            .unwrap();
        bad_packet_short_data_len
            .extend_from_slice(&wrong_crc)
            .unwrap();
        assert_eq!(
            bad_packet_short_data_len.decode().err(),
            Some(WakeError::WrongPacketLength)
        );

        let mut bad_packet_long_data_len = enc(&[FEND, command, n + 1]);
        bad_packet_long_data_len
            .extend_from_slice(&payload)
            .unwrap();
        bad_packet_long_data_len
            .extend_from_slice(&wrong_crc)
            .unwrap();
        assert_eq!(
            bad_packet_long_data_len.decode().err(),
            Some(WakeError::WrongPacketLength)
        );

        let mut bad_packet_wrong_crc = enc(&[FEND, command, n]);
        bad_packet_wrong_crc.extend_from_slice(&payload).unwrap();
        bad_packet_wrong_crc.extend_from_slice(&wrong_crc).unwrap();
        assert_eq!(
            bad_packet_wrong_crc.decode().err(),
            Some(WakeError::WrongPacketCrc)
        );
    }

    #[test]
    fn decode_w_address_test() {
        let address = 0x09u8;
        let command = 0x03u8;
        let payload = [1, 2, 3, 4, 5];
        let n = payload.len() as u8;
        let crc = [0x69];

        let mut good_packet = enc(&[FEND, address | 0x80u8, command, n]);
        good_packet.extend_from_slice(&payload).unwrap();
        good_packet.extend_from_slice(&crc).unwrap();
        let decoded = good_packet.decode().unwrap();
        assert_eq!(decoded.address.unwrap(), address);
        assert_eq!(decoded.command, command);
        assert_eq!(decoded.data.unwrap(), data(&payload));

        // 0x40 test
        let good_packet = enc(&[FEND, FESC, TFEND, 0x40, 0x00, 229]);
        let decoded = good_packet.decode().unwrap();
        assert_eq!(decoded.address.unwrap(), 0x40);
        assert_eq!(decoded.command, 0x40);
        assert_eq!(decoded.data, None);
    }

    /// Simple xorshift generator, so the tests stay `no_std`/allocation free.
    struct XorShift(u32);

    impl XorShift {
        fn next(&mut self) -> u32 {
            let mut x = self.0;
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            self.0 = x;
            x
        }

        fn below(&mut self, bound: u32) -> u32 {
            self.next() % bound
        }
    }

    #[test]
    fn random_encode_decode_test() {
        let mut rng = XorShift(0x1234_5678);

        for _ in 0..100_000 {
            let address_exists = rng.below(2) == 1;
            let n = rng.below(DATA_MAX_LEN as u32 + 1) as usize;
            let mut d = PacketData::new();
            for _ in 0..n {
                d.push(rng.below(0x100) as u8).unwrap();
            }

            let wp = Packet {
                address: if address_exists {
                    Some(rng.below(0x80) as u8)
                } else {
                    None
                },
                command: rng.below(0x80) as u8,
                data: if d.is_empty() { None } else { Some(d) },
            };
            let encoded = wp.encode().unwrap();
            let decoded = encoded.decode().unwrap();
            assert_eq!(decoded.address, wp.address);
            assert_eq!(decoded.command, wp.command);
            assert_eq!(decoded.data, wp.data);
        }
    }
}
