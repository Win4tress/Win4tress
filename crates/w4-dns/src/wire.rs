//! DNS messages (RFC 1035), as much as the resolver needs: a query's header
//! and question, the records in an answer (with name compression), and the
//! answers win4tress writes itself (blocked, local records, errors). Queries
//! are otherwise forwarded as they came. Malformed input is an error, never a
//! panic (property-tested).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub const TYPE_A: u16 = 1;
pub const TYPE_CNAME: u16 = 5;
pub const TYPE_AAAA: u16 = 28;
pub const TYPE_HTTPS: u16 = 65;
pub const TYPE_OPT: u16 = 41;
pub const CLASS_IN: u16 = 1;

pub const RCODE_NOERROR: u8 = 0;
pub const RCODE_SERVFAIL: u8 = 2;
pub const RCODE_NXDOMAIN: u8 = 3;
pub const RCODE_REFUSED: u8 = 5;

const HEADER: usize = 12;
const MAX_JUMPS: usize = 64;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Question {
    /// Lower case, no trailing dot ("" for the root).
    pub name: String,
    pub qtype: u16,
    pub qclass: u16,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Query {
    pub id: u16,
    /// Recursion desired, copied into answers.
    pub rd: bool,
    /// Opcode 0 (a standard query).
    pub standard: bool,
    pub question: Question,
    /// Where the question ends: what an answer copies.
    pub question_end: usize,
    /// The UDP size the asker takes (EDNS), if it said.
    pub edns_size: Option<u16>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RData {
    A(Ipv4Addr),
    Aaaa(Ipv6Addr),
    Cname(String),
    Other,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Record {
    pub name: String,
    pub rtype: u16,
    pub ttl: u32,
    pub data: RData,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Answer {
    pub id: u16,
    pub rcode: u8,
    pub truncated: bool,
    pub question: Option<Question>,
    pub answers: Vec<Record>,
}

fn u16_at(b: &[u8], at: usize) -> Result<u16, String> {
    b.get(at..at + 2)
        .map(|s| u16::from_be_bytes([s[0], s[1]]))
        .ok_or_else(|| "message too short".into())
}

fn u32_at(b: &[u8], at: usize) -> Result<u32, String> {
    b.get(at..at + 4)
        .map(|s| u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
        .ok_or_else(|| "message too short".into())
}

/// A name at `at`, following compression pointers; returns it and where the
/// name ends in place (after the first pointer, if any).
pub fn read_name(b: &[u8], mut at: usize) -> Result<(String, usize), String> {
    let mut name = String::new();
    let mut end = None;
    let mut jumps = 0;
    loop {
        let len = *b.get(at).ok_or("name runs past the message")?;
        match len & 0xC0 {
            0x00 => {
                if len == 0 {
                    return Ok((name, end.unwrap_or(at + 1)));
                }
                let label = b
                    .get(at + 1..at + 1 + len as usize)
                    .ok_or("label runs past the message")?;
                if !name.is_empty() {
                    name.push('.');
                }
                for &c in label {
                    name.push(c.to_ascii_lowercase() as char);
                }
                if name.len() > 255 {
                    return Err("name longer than 255".into());
                }
                at += 1 + len as usize;
            }
            0xC0 => {
                let target = (u16_at(b, at)? & 0x3FFF) as usize;
                end.get_or_insert(at + 2);
                jumps += 1;
                if jumps > MAX_JUMPS {
                    return Err("compression loop".into());
                }
                at = target;
            }
            _ => return Err("unknown label type".into()),
        }
    }
}

/// Writes `name` uncompressed.
pub fn write_name(out: &mut Vec<u8>, name: &str) -> Result<(), String> {
    if !name.is_empty() {
        for label in name.split('.') {
            if label.is_empty() || label.len() > 63 {
                return Err(format!("bad label in {name:?}"));
            }
            out.push(label.len() as u8);
            out.extend_from_slice(label.as_bytes());
        }
    }
    out.push(0);
    Ok(())
}

/// A query's header and its one question.
pub fn parse_query(b: &[u8]) -> Result<Query, String> {
    if b.len() < HEADER {
        return Err("message too short".into());
    }
    let flags = u16_at(b, 2)?;
    if flags & 0x8000 != 0 {
        return Err("not a query".into());
    }
    if u16_at(b, 4)? != 1 {
        return Err("not one question".into());
    }
    let (name, end) = read_name(b, HEADER)?;
    let qtype = u16_at(b, end)?;
    let qclass = u16_at(b, end + 2)?;
    // An OPT record first among the additional ones: its class is the size.
    let edns_size = (u16_at(b, 10)? > 0 && u16_at(b, 6)? == 0 && u16_at(b, 8)? == 0)
        .then(|| {
            let (_, at) = read_name(b, end + 4).ok()?;
            (u16_at(b, at).ok()? == TYPE_OPT)
                .then(|| u16_at(b, at + 2).ok())
                .flatten()
        })
        .flatten();
    Ok(Query {
        id: u16_at(b, 0)?,
        rd: flags & 0x0100 != 0,
        standard: (flags >> 11) & 0xF == 0,
        question: Question {
            name,
            qtype,
            qclass,
        },
        question_end: end + 4,
        edns_size,
    })
}

/// An answer's header, question and answer records (authority and additional
/// records are skipped).
pub fn parse_answer(b: &[u8]) -> Result<Answer, String> {
    if b.len() < HEADER {
        return Err("message too short".into());
    }
    let flags = u16_at(b, 2)?;
    let qd = u16_at(b, 4)?;
    let an = u16_at(b, 6)?;
    let mut at = HEADER;
    let mut question = None;
    for i in 0..qd {
        let (name, end) = read_name(b, at)?;
        let q = Question {
            name,
            qtype: u16_at(b, end)?,
            qclass: u16_at(b, end + 2)?,
        };
        if i == 0 {
            question = Some(q);
        }
        at = end + 4;
    }
    let mut answers = Vec::with_capacity(an.min(64) as usize);
    for _ in 0..an {
        let (name, end) = read_name(b, at)?;
        let rtype = u16_at(b, end)?;
        let ttl = u32_at(b, end + 4)?;
        let len = u16_at(b, end + 8)? as usize;
        let start = end + 10;
        let rdata = b
            .get(start..start + len)
            .ok_or("record runs past the message")?;
        let data = match (rtype, len) {
            (TYPE_A, 4) => RData::A(Ipv4Addr::new(rdata[0], rdata[1], rdata[2], rdata[3])),
            (TYPE_AAAA, 16) => {
                let mut o = [0u8; 16];
                o.copy_from_slice(rdata);
                RData::Aaaa(Ipv6Addr::from(o))
            }
            (TYPE_CNAME, _) => RData::Cname(read_name(b, start)?.0),
            _ => RData::Other,
        };
        answers.push(Record {
            name,
            rtype,
            ttl,
            data,
        });
        at = start + len;
    }
    Ok(Answer {
        id: u16_at(b, 0)?,
        rcode: (flags & 0xF) as u8,
        truncated: flags & 0x0200 != 0,
        question,
        answers,
    })
}

/// An answer to `q`, from its own bytes: the header with QR and RA set, the
/// question as asked, then `records` for the question's name.
fn answer_with(query: &[u8], q: &Query, rcode: u8, records: &[(u16, u32, &[u8])]) -> Vec<u8> {
    let mut out = Vec::with_capacity(q.question_end + records.len() * 32);
    out.extend_from_slice(&q.id.to_be_bytes());
    let rd = if q.rd { 0x0100 } else { 0 };
    let flags: u16 = 0x8000 | rd | 0x0080 | u16::from(rcode & 0xF);
    out.extend_from_slice(&flags.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes());
    out.extend_from_slice(&(records.len() as u16).to_be_bytes());
    out.extend_from_slice(&[0, 0, 0, 0]);
    out.extend_from_slice(&query[HEADER..q.question_end]);
    for (rtype, ttl, data) in records {
        // A pointer to the question's name at offset 12.
        out.extend_from_slice(&[0xC0, 0x0C]);
        out.extend_from_slice(&rtype.to_be_bytes());
        out.extend_from_slice(&CLASS_IN.to_be_bytes());
        out.extend_from_slice(&ttl.to_be_bytes());
        out.extend_from_slice(&(data.len() as u16).to_be_bytes());
        out.extend_from_slice(data);
    }
    out
}

/// How blocked names are answered (SPEC §13).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlockAnswer {
    /// `0.0.0.0` for A, `::` for AAAA, no records for other types.
    NullIp,
    Nxdomain,
}

/// TTL of win4tress's own answers.
pub const OWN_TTL: u32 = 60;

pub fn blocked(query: &[u8], q: &Query, how: BlockAnswer) -> Vec<u8> {
    match (how, q.question.qtype) {
        (BlockAnswer::Nxdomain, _) => answer_with(query, q, RCODE_NXDOMAIN, &[]),
        (BlockAnswer::NullIp, TYPE_A) => {
            answer_with(query, q, RCODE_NOERROR, &[(TYPE_A, OWN_TTL, &[0, 0, 0, 0])])
        }
        (BlockAnswer::NullIp, TYPE_AAAA) => {
            answer_with(query, q, RCODE_NOERROR, &[(TYPE_AAAA, OWN_TTL, &[0; 16])])
        }
        (BlockAnswer::NullIp, _) => answer_with(query, q, RCODE_NOERROR, &[]),
    }
}

/// Local records: the addresses of the question's type (no records if none).
pub fn local(query: &[u8], q: &Query, addrs: &[IpAddr]) -> Vec<u8> {
    let data: Vec<(u16, Vec<u8>)> = addrs
        .iter()
        .filter_map(|a| match (a, q.question.qtype) {
            (IpAddr::V4(v4), TYPE_A) => Some((TYPE_A, v4.octets().to_vec())),
            (IpAddr::V6(v6), TYPE_AAAA) => Some((TYPE_AAAA, v6.octets().to_vec())),
            _ => None,
        })
        .collect();
    let records: Vec<(u16, u32, &[u8])> = data
        .iter()
        .map(|(t, d)| (*t, OWN_TTL, d.as_slice()))
        .collect();
    answer_with(query, q, RCODE_NOERROR, &records)
}

/// An error answer (SERVFAIL, REFUSED, NXDOMAIN) to a query.
pub fn error(query: &[u8], q: &Query, rcode: u8) -> Vec<u8> {
    answer_with(query, q, rcode, &[])
}

/// For an answer too large for UDP: just the question, with TC set, so the
/// asker comes back over TCP.
pub fn truncated(query: &[u8], q: &Query) -> Vec<u8> {
    let mut out = answer_with(query, q, RCODE_NOERROR, &[]);
    out[2] |= 0x02;
    out
}

/// Counts down every TTL in an answer by `elapsed` seconds (cached answers),
/// leaving EDNS's OPT record alone. Malformed messages are left as they are.
pub fn age_ttls(message: &mut [u8], elapsed: u32) {
    let Ok(counts) = (|| -> Result<[u16; 4], String> {
        Ok([
            u16_at(message, 4)?,
            u16_at(message, 6)?,
            u16_at(message, 8)?,
            u16_at(message, 10)?,
        ])
    })() else {
        return;
    };
    let mut at = HEADER;
    for _ in 0..counts[0] {
        let Ok((_, end)) = read_name(message, at) else {
            return;
        };
        at = end + 4;
    }
    let records = usize::from(counts[1]) + usize::from(counts[2]) + usize::from(counts[3]);
    for _ in 0..records {
        let Ok((_, end)) = read_name(message, at) else {
            return;
        };
        let (Ok(rtype), Ok(ttl), Ok(len)) = (
            u16_at(message, end),
            u32_at(message, end + 4),
            u16_at(message, end + 8),
        ) else {
            return;
        };
        if rtype != TYPE_OPT {
            let aged = ttl.saturating_sub(elapsed).max(1);
            message[end + 4..end + 8].copy_from_slice(&aged.to_be_bytes());
        }
        at = end + 10 + usize::from(len);
        if at > message.len() {
            return;
        }
    }
}

/// The smallest TTL among an answer's answer records, if it has any.
pub fn min_ttl(a: &Answer) -> Option<u32> {
    a.answers.iter().map(|r| r.ttl).min()
}

/// The query with a new id, for sending upstream.
pub fn with_id(message: &[u8], id: u16) -> Vec<u8> {
    let mut out = message.to_vec();
    if out.len() >= 2 {
        out[..2].copy_from_slice(&id.to_be_bytes());
    }
    out
}

/// A minimal standard query (recursion desired), e.g. for health checks.
pub fn query(id: u16, name: &str, qtype: u16) -> Result<Vec<u8>, String> {
    let mut out = Vec::with_capacity(HEADER + name.len() + 6);
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(&0x0100u16.to_be_bytes());
    out.extend_from_slice(&[0, 1, 0, 0, 0, 0, 0, 0]);
    write_name(&mut out, name)?;
    out.extend_from_slice(&qtype.to_be_bytes());
    out.extend_from_slice(&CLASS_IN.to_be_bytes());
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn queries_parse_and_blocked_answers_read_back() {
        let q = query(0xBEEF, "Ads.Example.com", TYPE_A).unwrap();
        let parsed = parse_query(&q).unwrap();
        assert_eq!(parsed.question.name, "ads.example.com");
        assert_eq!(
            (parsed.id, parsed.rd, parsed.standard),
            (0xBEEF, true, true)
        );
        let a = parse_answer(&blocked(&q, &parsed, BlockAnswer::NullIp)).unwrap();
        assert_eq!((a.id, a.rcode), (0xBEEF, RCODE_NOERROR));
        assert_eq!(a.answers[0].data, RData::A(Ipv4Addr::UNSPECIFIED));
        assert_eq!(a.answers[0].name, "ads.example.com");
        let nx = parse_answer(&blocked(&q, &parsed, BlockAnswer::Nxdomain)).unwrap();
        assert_eq!((nx.rcode, nx.answers.len()), (RCODE_NXDOMAIN, 0));

        let q6 = query(1, "ads.example.com", TYPE_AAAA).unwrap();
        let p6 = parse_query(&q6).unwrap();
        let a6 = parse_answer(&blocked(&q6, &p6, BlockAnswer::NullIp)).unwrap();
        assert_eq!(a6.answers[0].data, RData::Aaaa(Ipv6Addr::UNSPECIFIED));
        let qh = query(2, "ads.example.com", TYPE_HTTPS).unwrap();
        let ph = parse_query(&qh).unwrap();
        assert!(
            parse_answer(&blocked(&qh, &ph, BlockAnswer::NullIp))
                .unwrap()
                .answers
                .is_empty()
        );
    }

    #[test]
    fn edns_size_truncation_and_aging() {
        let mut q = query(5, "example.com", TYPE_A).unwrap();
        assert_eq!(parse_query(&q).unwrap().edns_size, None);
        // Add an OPT record: root name, type 41, class 1232.
        q[11] = 1;
        q.extend_from_slice(&[0, 0, 41, 0x04, 0xD0, 0, 0, 0, 0, 0, 0]);
        let p = parse_query(&q).unwrap();
        assert_eq!(p.edns_size, Some(1232));
        let t = parse_answer(&truncated(&q, &p)).unwrap();
        assert!(t.truncated);
        assert!(t.answers.is_empty());

        let mut blocked_answer = blocked(&q, &p, BlockAnswer::NullIp);
        age_ttls(&mut blocked_answer, 25);
        let a = parse_answer(&blocked_answer).unwrap();
        assert_eq!(a.answers[0].ttl, OWN_TTL - 25);
        assert_eq!(min_ttl(&a), Some(OWN_TTL - 25));
        age_ttls(&mut blocked_answer, 1_000);
        assert_eq!(parse_answer(&blocked_answer).unwrap().answers[0].ttl, 1);
    }

    #[test]
    fn local_records_answer_by_type() {
        let q = query(9, "nas.home", TYPE_A).unwrap();
        let p = parse_query(&q).unwrap();
        let addrs: Vec<IpAddr> = vec!["192.168.1.20".parse().unwrap(), "fd00::20".parse().unwrap()];
        let a = parse_answer(&local(&q, &p, &addrs)).unwrap();
        assert_eq!(a.answers.len(), 1);
        assert_eq!(a.answers[0].data, RData::A("192.168.1.20".parse().unwrap()));
    }

    #[test]
    fn compressed_cname_chains_are_read() {
        // www.example.com CNAME cdn.example.net, cdn.example.net A 1.2.3.4,
        // the second name compressed against the first record's data.
        let mut m = vec![0x12, 0x34, 0x81, 0x80, 0, 1, 0, 2, 0, 0, 0, 0];
        write_name(&mut m, "www.example.com").unwrap();
        m.extend_from_slice(&[0, 1, 0, 1]);
        m.extend_from_slice(&[0xC0, 0x0C, 0, 5, 0, 1, 0, 0, 0, 30]);
        let cname_at = m.len() + 2;
        let mut target = Vec::new();
        write_name(&mut target, "cdn.example.net").unwrap();
        m.extend_from_slice(&(target.len() as u16).to_be_bytes());
        m.extend_from_slice(&target);
        m.extend_from_slice(&[
            0xC0 | (cname_at >> 8) as u8,
            cname_at as u8,
            0,
            1,
            0,
            1,
            0,
            0,
            0,
            20,
            0,
            4,
            1,
            2,
            3,
            4,
        ]);
        let a = parse_answer(&m).unwrap();
        assert_eq!(a.answers[0].data, RData::Cname("cdn.example.net".into()));
        assert_eq!(a.answers[1].name, "cdn.example.net");
        assert_eq!(a.answers[1].data, RData::A(Ipv4Addr::new(1, 2, 3, 4)));
    }

    #[test]
    fn compression_loops_are_errors() {
        let mut m = vec![0, 0, 0x81, 0x80, 0, 1, 0, 0, 0, 0, 0, 0];
        m.extend_from_slice(&[0xC0, 0x0C, 0, 1, 0, 1]);
        assert!(parse_answer(&m).is_err());
    }

    proptest! {
        #[test]
        fn random_bytes_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..600)) {
            let _ = parse_query(&bytes);
            let _ = parse_answer(&bytes);
            let mut copy = bytes.clone();
            age_ttls(&mut copy, 30);
            if let Ok(q) = parse_query(&bytes) {
                let _ = parse_answer(&blocked(&bytes, &q, BlockAnswer::NullIp));
                let _ = parse_answer(&error(&bytes, &q, RCODE_SERVFAIL));
            }
        }

        #[test]
        fn names_round_trip(labels in proptest::collection::vec("[a-z0-9-]{1,20}", 1..6), qtype in any::<u16>()) {
            let name = labels.join(".");
            let q = query(7, &name, qtype).unwrap();
            let p = parse_query(&q).unwrap();
            prop_assert_eq!(&p.question.name, &name);
            prop_assert_eq!(p.question.qtype, qtype);
            let a = parse_answer(&error(&q, &p, RCODE_SERVFAIL)).unwrap();
            prop_assert_eq!(a.rcode, RCODE_SERVFAIL);
            prop_assert_eq!(a.question.unwrap().name, name);
        }
    }
}
