//! The recovery kit on paper (study section 12): the pages of the three
//! sheets and the card, printed from memory or, only when asked, written as
//! a PDF to a place the person chooses.
//!
//! Each sheet also carries, in the clear, its root key's fingerprint and
//! its share commitment. Neither is secret: typed into any device of the
//! vault they show the sheet belongs to it, with nothing secret on that
//! device.

// Only page, line and object numbers of a four-page document are added
// here, never anything near an integer's limit.
#![allow(clippy::arithmetic_side_effects)]

use anyhow::Result;

use crate::vault::authority::RootSet;
use crate::vault::slip39;
use crate::vault::synced::Kit;

/// A short, grouped fingerprint of bytes, as printed on a sheet.
fn grouped(bytes: &[u8]) -> String {
    data_encoding::HEXLOWER
        .encode(bytes)
        .as_bytes()
        .chunks(4)
        .map(|chunk| String::from_utf8_lossy(chunk).into_owned())
        .collect::<Vec<_>>()
        .join("-")
}

/// The root fingerprint and share commitment printed on sheet `index`.
#[must_use]
pub fn marks(set: &RootSet, index: usize) -> Option<(String, String)> {
    let root = set.roots.get(index)?;
    let commitment = set.commitments.get(index)?;
    let digest = crate::vault::crypto::sha256(&[&root.to_bytes()]);
    Some((grouped(&digest[..6]), grouped(&commitment[..6])))
}

/// Which sheet, if any, the printed marks name.
#[must_use]
pub fn sheet_of(set: &RootSet, root: &str, share: &str) -> Option<usize> {
    let clean = |text: &str| -> String {
        text.chars()
            .filter(char::is_ascii_hexdigit)
            .map(|c| c.to_ascii_lowercase())
            .collect()
    };
    let (root, share) = (clean(root), clean(share));
    (0..set.roots.len()).find(|index| {
        marks(set, *index).is_some_and(|(printed_root, printed_share)| {
            clean(&printed_root) == root && clean(&printed_share) == share
        })
    })
}

/// The lines of each page: one per sheet, then the card.
///
/// # Errors
///
/// Returns an error when a sheet is not a SLIP-39 share.
pub fn pages(vault: &str, kit: &Kit, set: &RootSet) -> Result<Vec<Vec<String>>> {
    let mut out = Vec::new();
    let total = kit.sheets.len();
    for (number, sheet) in kit.sheets.iter().enumerate() {
        let index = usize::from(slip39::share_index(sheet)?);
        let mut lines = vec![
            format!(
                "txc recovery sheet {} of {total}, vault \"{vault}\"",
                number + 1
            ),
            String::new(),
            "Any two sheets and the card recover the vault. Keep the three sheets in".to_owned(),
            "three places, and the card with you. Seal this sheet in an envelope.".to_owned(),
            String::new(),
        ];
        let words: Vec<&str> = sheet.split_whitespace().collect();
        for (row, chunk) in words.chunks(6).enumerate() {
            lines.push(
                chunk
                    .iter()
                    .enumerate()
                    .map(|(column, word)| format!("{:>2}. {word:<10}", row * 6 + column + 1))
                    .collect::<Vec<_>>()
                    .join(" "),
            );
        }
        if let Some((root, share)) = marks(set, index) {
            lines.push(String::new());
            lines.push(format!(
                "Not secret, to check this sheet: root {root}  share {share}"
            ));
        }
        out.push(lines);
    }
    out.push(vec![
        format!("txc recovery card, vault \"{vault}\""),
        String::new(),
        "The card goes with any two sheets. Keep it apart from them.".to_owned(),
        String::new(),
        kit.card.to_string(),
    ]);
    Ok(out)
}

/// The pages as plain text, a form feed between them, for a printer.
#[must_use]
pub fn text(pages: &[Vec<String>]) -> String {
    pages
        .iter()
        .map(|lines| lines.join("\n"))
        .collect::<Vec<_>>()
        .join("\n\x0c")
}

fn escape(line: &str) -> String {
    line.chars()
        .filter(char::is_ascii)
        .flat_map(|c| match c {
            '(' | ')' | '\\' => vec!['\\', c],
            c => vec![c],
        })
        .collect()
}

/// The pages as a small PDF: one A4 page each, in a fixed-width font.
#[must_use]
pub fn pdf(pages: &[Vec<String>]) -> Vec<u8> {
    let count = pages.len();
    // Objects: 1 catalog, 2 page tree, 3 font, then a page and its content
    // stream for each page.
    let mut objects: Vec<String> = vec![
        "<< /Type /Catalog /Pages 2 0 R >>".to_owned(),
        format!(
            "<< /Type /Pages /Kids [{}] /Count {count} >>",
            (0..count)
                .map(|page| format!("{} 0 R", 4 + page * 2))
                .collect::<Vec<_>>()
                .join(" ")
        ),
        "<< /Type /Font /Subtype /Type1 /BaseFont /Courier >>".to_owned(),
    ];
    for (page, lines) in pages.iter().enumerate() {
        let mut stream = String::from("BT /F1 11 Tf 14 TL 56 780 Td\n");
        for line in lines {
            stream.push('(');
            stream.push_str(&escape(line));
            stream.push_str(") Tj T*\n");
        }
        stream.push_str("ET");
        objects.push(format!(
            "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Resources << /Font << /F1 3 0 R >> >> /Contents {} 0 R >>",
            5 + page * 2
        ));
        objects.push(format!(
            "<< /Length {} >>\nstream\n{stream}\nendstream",
            stream.len()
        ));
    }
    let mut out = b"%PDF-1.4\n".to_vec();
    let mut offsets = Vec::with_capacity(objects.len());
    for (number, object) in objects.iter().enumerate() {
        offsets.push(out.len());
        out.extend_from_slice(format!("{} 0 obj\n{object}\nendobj\n", number + 1).as_bytes());
    }
    let xref = out.len();
    out.extend_from_slice(
        format!("xref\n0 {}\n0000000000 65535 f \n", objects.len() + 1).as_bytes(),
    );
    for offset in offsets {
        out.extend_from_slice(format!("{offset:010} 00000 n \n").as_bytes());
    }
    out.extend_from_slice(
        format!(
            "trailer\n<< /Size {} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n",
            objects.len() + 1
        )
        .as_bytes(),
    );
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_pdf_has_one_page_per_sheet_and_a_sound_cross_reference() {
        let pages = vec![
            vec!["sheet (one)".to_owned(), "words".to_owned()],
            vec!["card".to_owned()],
        ];
        let bytes = pdf(&pages);
        let text = String::from_utf8(bytes.clone()).unwrap();
        assert!(text.starts_with("%PDF-1.4"));
        assert!(text.contains("/Count 2"));
        assert!(text.contains("(sheet \\(one\\)) Tj"));
        // Every offset in the table points at its object.
        let xref = text.find("xref\n").unwrap();
        for (number, line) in text[xref..].lines().skip(3).take(7).enumerate() {
            let offset: usize = line[..10].parse().unwrap();
            assert!(
                text[offset..].starts_with(&format!("{} 0 obj", number + 1)),
                "object {}",
                number + 1
            );
        }
    }
}
