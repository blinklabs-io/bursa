import { useState } from "react";
import type { Contact } from "../api/types";
import { useContacts } from "../api/hooks";
import { upsertContact, deleteContact } from "../api/client";
import { Card } from "../components/Card";
import { Input } from "../components/Input";
import { Button } from "../components/Button";
import { CopyButton } from "../components/CopyButton";
import { errorMessage } from "../errorMessage";

interface ContactFormProps {
  // null = new contact; otherwise the contact being edited.
  initial: Contact | null;
  onSaved: (contact: Contact) => void;
  onCancel: () => void;
}

// Per-field byte caps mirror the backend's ui/internal/contacts constants
// (maxNameLen / maxAddressLen / maxNoteLen). Browser maxLength counts UTF-16
// code units, so onChange clamps UTF-8 bytes and handleSave validates the
// trimmed payload as a final guard.
const MAX_NAME_BYTES = 256;
const MAX_ADDRESS_BYTES = 256;
const MAX_NOTE_BYTES = 1024;

const utf8Encoder = new TextEncoder();

function byteLength(value: string): number {
  return utf8Encoder.encode(value).length;
}

function truncateUtf8(value: string, maxBytes: number): string {
  if (byteLength(value) <= maxBytes) return value;

  let bytes = 0;
  let out = "";
  for (const char of value) {
    const charBytes = byteLength(char);
    if (bytes + charBytes > maxBytes) break;
    out += char;
    bytes += charBytes;
  }
  return out;
}

function byteLimitError(field: string, value: string, maxBytes: number): string | null {
  if (byteLength(value) <= maxBytes) return null;
  return `${field} exceeds ${maxBytes} bytes`;
}

// The add/edit form is the same component either way — a supplied `initial`
// seeds the fields and its id is carried through as an update; omitting it
// creates a new contact.
function ContactForm({ initial, onSaved, onCancel }: ContactFormProps) {
  const [name, setName] = useState(initial?.name ?? "");
  const [address, setAddress] = useState(initial?.address ?? "");
  const [note, setNote] = useState(initial?.note ?? "");
  const [error, setError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);

  async function handleSave() {
    setError(null);
    const trimmedName = name.trim();
    const trimmedAddress = address.trim();
    const trimmedNote = note.trim();
    const lengthError =
      byteLimitError("name", trimmedName, MAX_NAME_BYTES) ??
      byteLimitError("address", trimmedAddress, MAX_ADDRESS_BYTES) ??
      byteLimitError("note", trimmedNote, MAX_NOTE_BYTES);
    if (lengthError) {
      setError(lengthError);
      return;
    }

    setSaving(true);
    try {
      const saved = await upsertContact({
        ...(initial ? { id: initial.id } : {}),
        name: trimmedName,
        address: trimmedAddress,
        ...(trimmedNote ? { note: trimmedNote } : {}),
      });
      onSaved(saved);
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setSaving(false);
    }
  }

  return (
    <Card title={initial ? "Edit Contact" : "Add Contact"}>
      <div className="send-form">
        <label htmlFor="contact-name">Name</label>
        <Input
          id="contact-name"
          type="text"
          placeholder="e.g. Alice"
          value={name}
          onChange={(e) => setName(truncateUtf8(e.target.value, MAX_NAME_BYTES))}
          disabled={saving}
          maxLength={MAX_NAME_BYTES}
        />

        <label htmlFor="contact-address">Address</label>
        <Input
          id="contact-address"
          type="text"
          placeholder="addr1..."
          value={address}
          onChange={(e) => setAddress(truncateUtf8(e.target.value, MAX_ADDRESS_BYTES))}
          disabled={saving}
          maxLength={MAX_ADDRESS_BYTES}
        />

        <label htmlFor="contact-note">Note (optional)</label>
        <Input
          id="contact-note"
          type="text"
          placeholder="optional note"
          value={note}
          onChange={(e) => setNote(truncateUtf8(e.target.value, MAX_NOTE_BYTES))}
          disabled={saving}
          maxLength={MAX_NOTE_BYTES}
        />

        {error && (
          <p role="alert" className="error-text">
            {error}
          </p>
        )}

        <div className="row-actions">
          <Button onClick={handleSave} disabled={saving || !name.trim() || !address.trim()}>
            {saving ? "Saving…" : "Save"}
          </Button>
          <Button variant="ghost" onClick={onCancel} disabled={saving}>
            Cancel
          </Button>
        </div>
      </div>
    </Card>
  );
}

// Contacts is the address-book screen: a local-only, per-instance list of
// saved recipient addresses. It never reaches out to any external service —
// purely on-device CRUD storage, matching the wallet's consent law.
export function Contacts() {
  const contacts = useContacts();
  const [editing, setEditing] = useState<Contact | "new" | null>(null);
  const [deleteError, setDeleteError] = useState<string | null>(null);
  const [busyId, setBusyId] = useState<string | null>(null);

  // Apply the saved contact to the in-memory list immediately (append for a
  // new contact, replace-by-id for an edit) instead of waiting on the
  // follow-up refresh() GET, so the list can't appear to have lost the just-
  // saved contact if that GET fails. refresh() still runs as a background
  // reconciliation against the server's canonical (sorted) order.
  function handleSaved(saved: Contact) {
    setEditing(null);
    const current = contacts.data ?? [];
    const idx = current.findIndex((c) => c.id === saved.id);
    contacts.setData(idx >= 0 ? current.map((c, i) => (i === idx ? saved : c)) : [...current, saved]);
    contacts.refresh();
  }

  async function handleDelete(id: string) {
    setDeleteError(null);
    setBusyId(id);
    try {
      await deleteContact(id);
      // Remove locally right away — otherwise a successful delete whose
      // follow-up refresh() fails would leave the deleted contact visible,
      // looking like the delete itself failed.
      contacts.setData((contacts.data ?? []).filter((c) => c.id !== id));
      contacts.refresh();
    } catch (e) {
      setDeleteError(errorMessage(e));
    } finally {
      setBusyId(null);
    }
  }

  if (editing !== null) {
    return (
      <ContactForm
        initial={editing === "new" ? null : editing}
        onSaved={handleSaved}
        onCancel={() => setEditing(null)}
      />
    );
  }

  const list = contacts.data ?? [];
  const hasLoaded = contacts.data !== null;

  return (
    <div className="screen-contacts">
      <Card title="Address Book">
        {!hasLoaded && contacts.loading ? (
          <p className="muted">Loading…</p>
        ) : hasLoaded && list.length === 0 ? (
          <p className="muted">No saved contacts yet.</p>
        ) : hasLoaded ? (
          <ul className="contact-list" aria-label="Contacts">
            {list.map((c) => (
              <li key={c.id} className="contact-row">
                <div className="contact-info">
                  <span className="contact-name">{c.name}</span>
                  <code className="contact-address mono">{c.address}</code>
                  {c.note && <span className="contact-note helper-text">{c.note}</span>}
                </div>
                <div className="contact-row-actions">
                  <CopyButton value={c.address} ariaLabel={`Copy ${c.name}'s address`} />
                  <Button variant="ghost" onClick={() => setEditing(c)} disabled={busyId !== null}>
                    Edit
                  </Button>
                  <Button
                    variant="ghost"
                    onClick={() => handleDelete(c.id)}
                    disabled={busyId !== null}
                  >
                    {busyId === c.id ? "Removing…" : "Delete"}
                  </Button>
                </div>
              </li>
            ))}
          </ul>
        ) : null}

        {deleteError && (
          <p role="alert" className="error-text">
            {deleteError}
          </p>
        )}
        {contacts.error && !contacts.loading && (
          <p role="alert" className="error-text">
            {contacts.error.message}
          </p>
        )}

        <Button onClick={() => setEditing("new")}>+ Add contact</Button>
      </Card>
    </div>
  );
}
