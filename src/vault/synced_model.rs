//! A synced vault's entries in the shape of today's entry model, so the
//! interface that shows and edits today's vaults shows and edits synced ones
//! the same way. Secret fields come through sealed: listing decrypts none,
//! and a secret is revealed only by name, one at a time.

use age::secrecy::ExposeSecret;
use anyhow::{Result, bail, ensure};

use crate::vault::entries::{Changes, EntryView, FieldKind, FieldView};
use crate::vault::model::{Entry, Field, Kind, Value};
use crate::vault::synced::{Synced, now};
use crate::vault::{Change, NewEntry};

/// What a sealed value is shown as in the model; never decrypted to list.
const SEALED: &str = "synced";

fn stamp(at: Option<u64>) -> String {
    at.and_then(|at| i64::try_from(at).ok())
        .and_then(|at| chrono::DateTime::from_timestamp(at, 0))
        .map_or_else(String::new, |at| {
            at.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
        })
}

fn plain_kind(label: &str) -> FieldKind {
    match label {
        "username" => FieldKind::Username,
        "url" => FieldKind::Origin,
        _ => FieldKind::Note,
    }
}

/// Every entry of a synced vault, as today's model, without a secret in it.
///
/// # Errors
///
/// Returns an error when an object is malformed.
pub fn entries(vault: &Synced) -> Result<Vec<Entry>> {
    let entries = vault.entries()?;
    let mut out = Vec::new();
    for view in entries.list() {
        let kind = view
            .kinds
            .first()
            .and_then(|kind| Kind::from_id(kind))
            .unwrap_or(Kind::Secret);
        let times: Vec<u64> = view
            .fields
            .iter()
            .filter_map(|field| entries.written_at(&view.id, &field.id))
            .collect();
        let fields = view
            .fields
            .iter()
            .map(|field| Field {
                name: field.label.clone(),
                value: match &field.shown {
                    Some(values) => Value::Plain(values.join(" / ")),
                    None => Value::Sealed(SEALED.to_owned()),
                },
            })
            .collect();
        out.push(Entry {
            name: view.names.first().cloned().unwrap_or_default(),
            kind,
            fields,
            tags: view.tags.clone(),
            favourite: view.starred,
            created: stamp(times.iter().min().copied()),
            updated: stamp(times.iter().max().copied()),
        });
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(out)
}

/// The entries that are not normal, by name: `protected` for high and
/// root-grade ones, `operation-only` for keys used only inside txc.
///
/// # Errors
///
/// Returns an error when an object is malformed.
pub fn classes(vault: &Synced) -> Result<Vec<(String, String)>> {
    use crate::vault::entries::Sensitivity;
    Ok(vault
        .entries()?
        .list()
        .into_iter()
        .filter_map(|view| {
            let class = match view.sensitivity {
                Sensitivity::Normal => return None,
                Sensitivity::OperationOnly => "operation-only",
                Sensitivity::High | Sensitivity::RootGrade => "protected",
            };
            Some((
                view.names.first().cloned().unwrap_or_default(),
                class.to_owned(),
            ))
        })
        .collect())
}

fn find<'a>(views: &'a [EntryView], name: &str) -> Result<&'a EntryView> {
    let found: Vec<&EntryView> = views
        .iter()
        .filter(|view| view.names.iter().any(|candidate| candidate == name))
        .collect();
    match found.as_slice() {
        [one] => Ok(one),
        [] => bail!("there is no entry named {name:?}"),
        _ => bail!("{} entries are named {name:?}; rename one", found.len()),
    }
}

fn field<'a>(view: &'a EntryView, label: &str) -> Option<&'a FieldView> {
    view.fields.iter().find(|field| field.label == label)
}

/// Adds an entry.
///
/// # Errors
///
/// Returns an error when the name is taken, tags or a star are asked for,
/// or the write fails.
pub fn add(vault: &mut Synced, new: &NewEntry) -> Result<()> {
    let entries = vault.entries()?;
    ensure!(
        !entries
            .list()
            .iter()
            .any(|view| view.names.contains(&new.name)),
        "there is already an entry named {:?}",
        new.name
    );
    let mut changes = Changes::new(&entries, now());
    let entry = changes.create(&new.name)?;
    changes.set_kind(&entry, new.kind.id())?;
    if !new.tags.is_empty() {
        changes.set_tags(&entry, &new.tags)?;
    }
    if new.favourite {
        changes.set_star(&entry, true)?;
    }
    for (label, secret) in &new.secrets {
        changes.add_field(
            &entry,
            FieldKind::Secret,
            label,
            secret.expose_secret().as_bytes(),
        )?;
    }
    for (label, value) in &new.plain {
        changes.add_field(&entry, plain_kind(label), label, value.as_bytes())?;
    }
    vault.write(changes)?;
    Ok(())
}

/// Adds several entries as one object, as an import does (rule 18). A name
/// already in the vault gets the next free number. Returns how many.
///
/// # Errors
///
/// Returns an error when the write fails.
pub fn add_all(vault: &mut Synced, new: &[NewEntry]) -> Result<usize> {
    let entries = vault.entries()?;
    let mut taken: Vec<String> = entries
        .list()
        .into_iter()
        .flat_map(|view| view.names)
        .collect();
    let mut changes = Changes::new(&entries, now());
    for entry in new {
        let mut name = entry.name.clone();
        let mut number = 2_usize;
        while taken.contains(&name) {
            name = format!("{} ({number})", entry.name);
            number = number.saturating_add(1);
        }
        taken.push(name.clone());
        let id = changes.create(&name)?;
        changes.set_kind(&id, entry.kind.id())?;
        if !entry.tags.is_empty() {
            changes.set_tags(&id, &entry.tags)?;
        }
        if entry.favourite {
            changes.set_star(&id, true)?;
        }
        for (label, secret) in &entry.secrets {
            changes.add_field(
                &id,
                FieldKind::Secret,
                label,
                secret.expose_secret().as_bytes(),
            )?;
        }
        for (label, value) in &entry.plain {
            changes.add_field(&id, plain_kind(label), label, value.as_bytes())?;
        }
    }
    vault.write(changes)?;
    Ok(new.len())
}

/// Changes an entry, all or nothing: the changes are one object.
///
/// # Errors
///
/// Returns an error when the entry or a field to remove does not exist,
/// tags or a star are asked for, or the write fails.
pub fn change(vault: &mut Synced, name: &str, change: &Change) -> Result<()> {
    let entries = vault.entries()?;
    let views = entries.list();
    let view = find(&views, name)?;
    let mut changes = Changes::new(&entries, now());
    if let Some(new_name) = &change.rename {
        changes.rename(&view.id, new_name)?;
    }
    if !change.tag.is_empty() || !change.untag.is_empty() {
        let mut tags: Vec<String> = view
            .tags
            .iter()
            .filter(|tag| !change.untag.contains(tag))
            .cloned()
            .collect();
        for tag in &change.tag {
            if !tags.contains(tag) {
                tags.push(tag.clone());
            }
        }
        tags.sort();
        changes.set_tags(&view.id, &tags)?;
    }
    if let Some(starred) = change.favourite {
        changes.set_star(&view.id, starred)?;
    }
    let set =
        |changes: &mut Changes<'_>, label: &str, kind: FieldKind, value: &[u8]| -> Result<()> {
            match field(view, label) {
                Some(existing) => changes.set_field(&view.id, &existing.id, existing.kind, value),
                None => changes.add_field(&view.id, kind, label, value).map(|_| ()),
            }
        };
    for (label, value) in &change.plain {
        set(&mut changes, label, plain_kind(label), value.as_bytes())?;
    }
    for (label, secret) in &change.secrets {
        set(
            &mut changes,
            label,
            FieldKind::Secret,
            secret.expose_secret().as_bytes(),
        )?;
    }
    for label in &change.remove {
        let existing =
            field(view, label).ok_or_else(|| anyhow::anyhow!("{name} has no field {label}"))?;
        changes.delete_field(&view.id, &existing.id)?;
    }
    vault.write(changes)?;
    Ok(())
}

/// Removes an entry; its tombstones keep its values for the retention
/// window.
///
/// # Errors
///
/// Returns an error when the entry does not exist or the write fails.
pub fn remove(vault: &mut Synced, name: &str) -> Result<()> {
    let entries = vault.entries()?;
    let views = entries.list();
    let id = find(&views, name)?.id;
    let mut changes = Changes::new(&entries, now());
    changes.delete_entry(&id)?;
    vault.write(changes)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use age::secrecy::SecretString;

    use super::*;

    #[test]
    fn a_synced_entry_reads_as_a_model_entry_without_its_secret() {
        let setup = crate::vault::synced::tests::created("synced-model");
        let mut vault = setup.vault;
        add(
            &mut vault,
            &NewEntry {
                name: "github".into(),
                kind: Kind::Login,
                plain: vec![("username".into(), "octocat".into())],
                secrets: vec![("password".into(), SecretString::from("hunter2".to_owned()))],
                tags: Vec::new(),
                favourite: false,
            },
        )
        .unwrap();
        crate::vault::entries::OPENED.with(|opened| opened.set(0));
        let listed = entries(&vault).unwrap();
        let _ = classes(&vault).unwrap();
        assert_eq!(
            crate::vault::entries::OPENED.with(std::cell::Cell::get),
            0,
            "the interface lists without decrypting a secret"
        );
        assert_eq!(listed.len(), 1);
        let entry = &listed[0];
        assert_eq!((entry.name.as_str(), entry.kind), ("github", Kind::Login));
        assert_eq!(entry.plain("username"), Some("octocat"));
        assert!(entry.field("password").is_some_and(Field::is_sealed));
        assert!(!entry.updated.is_empty());

        change(
            &mut vault,
            "github",
            &Change {
                rename: Some("gitlab".into()),
                remove: vec!["username".into()],
                ..Change::default()
            },
        )
        .unwrap();
        let listed = entries(&vault).unwrap();
        assert_eq!(listed[0].name, "gitlab");
        assert!(listed[0].plain("username").is_none());
        change(
            &mut vault,
            "gitlab",
            &Change {
                tag: vec!["work".into(), "git".into()],
                favourite: Some(true),
                ..Change::default()
            },
        )
        .unwrap();
        let listed = entries(&vault).unwrap();
        assert_eq!(listed[0].tags, vec!["git".to_owned(), "work".to_owned()]);
        assert!(listed[0].favourite);
        change(
            &mut vault,
            "gitlab",
            &Change {
                untag: vec!["git".into()],
                ..Change::default()
            },
        )
        .unwrap();
        assert_eq!(entries(&vault).unwrap()[0].tags, vec!["work".to_owned()]);

        remove(&mut vault, "gitlab").unwrap();
        assert!(entries(&vault).unwrap().is_empty());
    }
}
