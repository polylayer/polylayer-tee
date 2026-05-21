//! Minimal BER → DER normalizer for ASN.1 byte streams.
//!
//! KMS Decrypt-with-Recipient returns PKCS#7 EnvelopedData using BER
//! (Basic Encoding Rules), which permits **indefinite-length** encoding
//! on constructed values: the length byte is `0x80` and the content
//! runs until an explicit end-of-contents marker (`00 00`). The cms /
//! der crates only consume DER (Distinguished Encoding Rules), which
//! forbids that form. We rewrite the bytes in place into DER so the
//! rest of the parser doesn't need to know.
//!
//! Scope: just the bits PKCS#7 producers emit in practice — multi-byte
//! tags, short + long + indefinite length forms, recursion into
//! constructed values. Doesn't handle OCTET STRING value-fragmentation
//! beyond just concatenating the children (which is what the spec
//! requires anyway when reconstituting DER from BER).

use super::CmsError;

const EOC: [u8; 2] = [0x00, 0x00];

pub(super) fn normalize(input: &[u8]) -> Result<Vec<u8>, CmsError> {
    let mut out = Vec::with_capacity(input.len());
    let mut cur = input;
    while !cur.is_empty() {
        let consumed = rewrite_one(cur, &mut out)?;
        cur = &cur[consumed..];
    }
    Ok(out)
}

/// Rewrite one TLV from `input` into DER, append to `out`. Returns
/// how many bytes of `input` were consumed.
fn rewrite_one(input: &[u8], out: &mut Vec<u8>) -> Result<usize, CmsError> {
    if input.is_empty() {
        return Err(CmsError::Der(der::Error::incomplete(der::Length::ZERO)));
    }
    // End-of-contents marker: not a "real" TLV, just propagate.
    if input.len() >= 2 && input[0] == 0 && input[1] == 0 {
        return Ok(2);
    }

    let (tag_bytes, after_tag) = read_tag(input)?;
    let is_constructed = (tag_bytes[0] & 0b0010_0000) != 0;
    let class = tag_bytes[0] & 0b1100_0000;
    let tag_number = tag_bytes[0] & 0b0001_1111;

    // BER allows certain UNIVERSAL primitive types (OCTET STRING tag 0x04,
    // BIT STRING tag 0x03) to be encoded as constructed, with each child
    // being a primitive value whose bytes get concatenated. DER requires
    // the primitive form. Detect this and flatten.
    let is_primitive_as_constructed =
        is_constructed && class == 0 && (tag_number == 0x04 || tag_number == 0x03);

    // CMS additionally encodes some context-specific implicitly-tagged
    // OCTET STRINGs as constructed (most notably
    // `EncryptedContentInfo.encryptedContent [0] IMPLICIT OCTET STRING`).
    // In DER these must be primitive. Heuristic: a context-specific
    // constructed value all of whose immediate children are primitive
    // OCTET STRINGs is an IMPLICIT-tagged segmented OCTET STRING — flatten
    // and re-emit with the constructed bit cleared. EXPLICIT context-
    // specific wrappers (like ContentInfo.content) have a single SEQUENCE
    // child instead, so the heuristic doesn't fire on them.

    let (length_info, after_length) = read_length(after_tag)?;
    let (content_slice, consumed_after_length) = match length_info {
        LengthInfo::Definite(len) => {
            if after_length.len() < len {
                return Err(CmsError::Der(der::Error::incomplete(der::Length::ZERO)));
            }
            (&after_length[..len], len)
        }
        LengthInfo::Indefinite => {
            // Find the EOC marker by walking children.
            let mut cur = after_length;
            let mut total = 0;
            loop {
                if cur.len() >= 2 && cur[..2] == EOC {
                    total += 2;
                    break;
                }
                let n = rewrite_one(cur, &mut Vec::new())?;
                cur = &cur[n..];
                total += n;
            }
            (&after_length[..total - 2], total)
        }
    };

    if is_primitive_as_constructed {
        let flat = flatten_primitive(content_slice, tag_number)?;
        out.push(tag_bytes[0] & !0b0010_0000); // clear constructed bit
        write_definite_length(out, flat.len());
        out.extend_from_slice(&flat);
    } else if is_constructed && class == 0x80 && all_children_are_octet_strings(content_slice) {
        // IMPLICIT-tagged segmented OCTET STRING. Flatten + clear the
        // constructed bit on the outer context-specific tag.
        let flat = flatten_primitive(content_slice, 0x04)?;
        out.push(tag_bytes[0] & !0b0010_0000);
        write_definite_length(out, flat.len());
        out.extend_from_slice(&flat);
    } else if is_constructed {
        let inner = normalize(content_slice)?;
        out.extend_from_slice(tag_bytes);
        write_definite_length(out, inner.len());
        out.extend_from_slice(&inner);
    } else {
        out.extend_from_slice(tag_bytes);
        write_definite_length(out, content_slice.len());
        out.extend_from_slice(content_slice);
    }

    let after_length_offset = after_length.as_ptr() as usize - input.as_ptr() as usize;
    Ok(after_length_offset + consumed_after_length)
}

/// Is every immediate child of this constructed value a primitive
/// universal OCTET STRING (tag `0x04`)?
fn all_children_are_octet_strings(input: &[u8]) -> bool {
    let mut cur = input;
    let mut count = 0;
    while !cur.is_empty() {
        let Ok((tag_bytes, after_tag)) = read_tag(cur) else { return false };
        // Must be UNIVERSAL primitive OCTET STRING.
        if tag_bytes[0] != 0x04 {
            return false;
        }
        let Ok((li, after_len)) = read_length(after_tag) else { return false };
        let len = match li {
            LengthInfo::Definite(n) => n,
            LengthInfo::Indefinite => return false,
        };
        if after_len.len() < len {
            return false;
        }
        let consumed = (after_len.as_ptr() as usize - cur.as_ptr() as usize) + len;
        cur = &cur[consumed..];
        count += 1;
    }
    count > 0
}

/// Flatten a constructed-form primitive type (OCTET STRING / BIT
/// STRING) into the concatenation of its children's content bytes.
/// Children themselves may be constructed; we recurse.
fn flatten_primitive(input: &[u8], expected_tag_num: u8) -> Result<Vec<u8>, CmsError> {
    let mut out = Vec::with_capacity(input.len());
    let mut cur = input;
    while !cur.is_empty() {
        let (child_tag_bytes, after_tag) = read_tag(cur)?;
        let child_tag_num = child_tag_bytes[0] & 0b0001_1111;
        let child_class = child_tag_bytes[0] & 0b1100_0000;
        let child_is_constructed = child_tag_bytes[0] & 0b0010_0000 != 0;
        if child_class != 0 || child_tag_num != expected_tag_num {
            return Err(CmsError::Der(der::Error::incomplete(der::Length::ZERO)));
        }
        let (li, after_len) = read_length(after_tag)?;
        let (child_content, child_consumed) = match li {
            LengthInfo::Definite(n) => (&after_len[..n], n),
            LengthInfo::Indefinite => {
                let mut walk = after_len;
                let mut total = 0;
                loop {
                    if walk.len() >= 2 && walk[..2] == EOC {
                        total += 2;
                        break;
                    }
                    let n = rewrite_one(walk, &mut Vec::new())?;
                    walk = &walk[n..];
                    total += n;
                }
                (&after_len[..total - 2], total)
            }
        };
        if child_is_constructed {
            out.extend_from_slice(&flatten_primitive(child_content, expected_tag_num)?);
        } else {
            out.extend_from_slice(child_content);
        }
        let consumed = (after_len.as_ptr() as usize - cur.as_ptr() as usize) + child_consumed;
        cur = &cur[consumed..];
    }
    Ok(out)
}

fn read_tag(input: &[u8]) -> Result<(&[u8], &[u8]), CmsError> {
    if input.is_empty() {
        return Err(CmsError::Der(der::Error::incomplete(der::Length::ZERO)));
    }
    // High-tag-number form: bottom 5 bits of byte 0 are all 1s, then
    // 7-bit chunks until a byte with MSB cleared. We don't see this
    // in PKCS#7 from KMS but it's cheap to support.
    if input[0] & 0b0001_1111 != 0b0001_1111 {
        return Ok((&input[..1], &input[1..]));
    }
    let mut end = 1;
    while end < input.len() && (input[end] & 0x80) != 0 {
        end += 1;
    }
    if end >= input.len() {
        return Err(CmsError::Der(der::Error::incomplete(der::Length::ZERO)));
    }
    end += 1; // include the byte with MSB=0
    Ok((&input[..end], &input[end..]))
}

enum LengthInfo {
    Definite(usize),
    Indefinite,
}

fn read_length(input: &[u8]) -> Result<(LengthInfo, &[u8]), CmsError> {
    if input.is_empty() {
        return Err(CmsError::Der(der::Error::incomplete(der::Length::ZERO)));
    }
    let b = input[0];
    if b == 0x80 {
        return Ok((LengthInfo::Indefinite, &input[1..]));
    }
    if b & 0x80 == 0 {
        return Ok((LengthInfo::Definite(b as usize), &input[1..]));
    }
    let nbytes = (b & 0x7f) as usize;
    if input.len() < 1 + nbytes || nbytes == 0 || nbytes > 8 {
        return Err(CmsError::Der(der::Error::incomplete(der::Length::ZERO)));
    }
    let mut len: usize = 0;
    for &byte in &input[1..1 + nbytes] {
        len = (len << 8) | (byte as usize);
    }
    Ok((LengthInfo::Definite(len), &input[1 + nbytes..]))
}

fn write_definite_length(out: &mut Vec<u8>, len: usize) {
    if len < 0x80 {
        out.push(len as u8);
        return;
    }
    let mut buf = [0u8; 8];
    let mut i = 0;
    let mut x = len;
    while x > 0 {
        buf[i] = (x & 0xff) as u8;
        x >>= 8;
        i += 1;
    }
    out.push(0x80 | i as u8);
    for j in (0..i).rev() {
        out.push(buf[j]);
    }
}
