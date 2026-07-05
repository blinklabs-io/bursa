import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { Contacts } from "./Contacts";
import * as client from "../api/client";
import { mockContacts } from "../test/mockContacts";
import type { Contact } from "../api/types";

const ALICE: Contact = { id: "c1", name: "Alice", address: "addr_test1alice", note: "friend" };
const BOB: Contact = { id: "c2", name: "Bob", address: "addr_test1bob" };

afterEach(() => {
  vi.restoreAllMocks();
});

test("(a) renders saved contacts with name, address, and note", () => {
  mockContacts([ALICE, BOB]);
  render(<Contacts />);
  expect(screen.getByText("Alice")).toBeInTheDocument();
  expect(screen.getByText("addr_test1alice")).toBeInTheDocument();
  expect(screen.getByText("friend")).toBeInTheDocument();
  expect(screen.getByText("Bob")).toBeInTheDocument();
  expect(screen.getByText("addr_test1bob")).toBeInTheDocument();
});

test("(b) empty address book shows a helpful empty state", () => {
  mockContacts([]);
  render(<Contacts />);
  expect(screen.getByText(/no saved contacts yet/i)).toBeInTheDocument();
});

test("(c) loading state renders gracefully before data arrives", () => {
  mockContacts(null, { loading: true });
  render(<Contacts />);
  expect(screen.getByText(/loading/i)).toBeInTheDocument();
});

test("(d) 'Add contact' opens the create form, and saving calls upsertContact without an id", async () => {
  mockContacts([]);
  const upsertSpy = vi.spyOn(client, "upsertContact").mockResolvedValue({
    id: "new1",
    name: "Carol",
    address: "addr_test1carol",
  });

  render(<Contacts />);
  fireEvent.click(screen.getByRole("button", { name: /\+ add contact/i }));

  fireEvent.change(screen.getByLabelText(/^name$/i), { target: { value: "Carol" } });
  fireEvent.change(screen.getByLabelText(/^address$/i), { target: { value: "addr_test1carol" } });
  fireEvent.click(screen.getByRole("button", { name: /^save$/i }));

  await waitFor(() => {
    expect(upsertSpy).toHaveBeenCalledWith({ name: "Carol", address: "addr_test1carol" });
  });
});

test("(e) editing an existing contact pre-fills the form and calls upsertContact with its id", async () => {
  mockContacts([ALICE]);
  const upsertSpy = vi.spyOn(client, "upsertContact").mockResolvedValue({
    ...ALICE,
    name: "Alice Updated",
  });

  render(<Contacts />);
  fireEvent.click(screen.getByRole("button", { name: /^edit$/i }));

  const nameInput = screen.getByLabelText(/^name$/i) as HTMLInputElement;
  expect(nameInput.value).toBe("Alice");
  const addressInput = screen.getByLabelText(/^address$/i) as HTMLInputElement;
  expect(addressInput.value).toBe("addr_test1alice");

  fireEvent.change(nameInput, { target: { value: "Alice Updated" } });
  fireEvent.click(screen.getByRole("button", { name: /^save$/i }));

  await waitFor(() => {
    expect(upsertSpy).toHaveBeenCalledWith({
      id: "c1",
      name: "Alice Updated",
      address: "addr_test1alice",
      note: "friend",
    });
  });
});

test("(f) a failed save surfaces the error and keeps the form open", async () => {
  mockContacts([]);
  vi.spyOn(client, "upsertContact").mockRejectedValue(
    new client.ApiError(400, "invalid contact: invalid address")
  );

  render(<Contacts />);
  fireEvent.click(screen.getByRole("button", { name: /\+ add contact/i }));
  fireEvent.change(screen.getByLabelText(/^name$/i), { target: { value: "Dave" } });
  fireEvent.change(screen.getByLabelText(/^address$/i), { target: { value: "not-an-address" } });
  fireEvent.click(screen.getByRole("button", { name: /^save$/i }));

  expect(await screen.findByRole("alert")).toHaveTextContent(/invalid address/i);
  // Still showing the form (Save button still present).
  expect(screen.getByRole("button", { name: /^save$/i })).toBeInTheDocument();
});

test("(g) deleting a contact calls deleteContact with its id and refreshes the list", async () => {
  const refresh = mockContacts([ALICE, BOB]);
  const deleteSpy = vi.spyOn(client, "deleteContact").mockResolvedValue({ removed: true });

  render(<Contacts />);
  const deleteButtons = screen.getAllByRole("button", { name: /^delete$/i });
  fireEvent.click(deleteButtons[0]);

  await waitFor(() => {
    expect(deleteSpy).toHaveBeenCalledWith("c1");
  });
  await waitFor(() => {
    expect(refresh).toHaveBeenCalled();
  });
});

test("(h) a failed delete surfaces an inline error", async () => {
  mockContacts([ALICE]);
  vi.spyOn(client, "deleteContact").mockRejectedValue(new client.ApiError(500, "disk full"));

  render(<Contacts />);
  fireEvent.click(screen.getByRole("button", { name: /^delete$/i }));

  expect(await screen.findByRole("alert")).toHaveTextContent(/disk full/i);
});

test("(j) the add form caps Name/Address/Note input length to match the backend's per-field limits", () => {
  mockContacts([]);
  render(<Contacts />);
  fireEvent.click(screen.getByRole("button", { name: /\+ add contact/i }));

  expect(screen.getByLabelText(/^name$/i)).toHaveAttribute("maxLength", "256");
  expect(screen.getByLabelText(/^address$/i)).toHaveAttribute("maxLength", "256");
  expect(screen.getByLabelText(/note/i)).toHaveAttribute("maxLength", "1024");
});

test("(l) the add form enforces backend UTF-8 byte limits while typing", async () => {
  mockContacts([]);
  const upsertSpy = vi.spyOn(client, "upsertContact").mockResolvedValue({
    id: "new1",
    name: "ok",
    address: "addr_test1carol",
  });

  render(<Contacts />);
  fireEvent.click(screen.getByRole("button", { name: /\+ add contact/i }));

  const nameInput = screen.getByLabelText(/^name$/i);
  const addressInput = screen.getByLabelText(/^address$/i);
  const noteInput = screen.getByLabelText(/note/i);
  const maxName = "\u00e9".repeat(128);
  const maxAddress = "\u754c".repeat(85);
  const maxNote = "\ud83d\ude00".repeat(256);

  fireEvent.change(nameInput, { target: { value: "\u00e9".repeat(129) } });
  fireEvent.change(addressInput, { target: { value: "\u754c".repeat(86) } });
  fireEvent.change(noteInput, { target: { value: "\ud83d\ude00".repeat(257) } });

  expect(nameInput).toHaveValue(maxName);
  expect(addressInput).toHaveValue(maxAddress);
  expect(noteInput).toHaveValue(maxNote);

  fireEvent.change(addressInput, { target: { value: "addr_test1carol" } });
  fireEvent.click(screen.getByRole("button", { name: /^save$/i }));

  await waitFor(() => {
    expect(upsertSpy).toHaveBeenCalledWith({
      name: maxName,
      address: "addr_test1carol",
      note: maxNote,
    });
  });
  expect(screen.queryByRole("alert")).not.toBeInTheDocument();
});

test("(k) a failed initial fetch shows only the error, not the empty-state text", () => {
  mockContacts(null, { error: new Error("network down") });
  render(<Contacts />);
  expect(screen.getByRole("alert")).toHaveTextContent(/network down/i);
  expect(screen.queryByText(/no saved contacts yet/i)).not.toBeInTheDocument();
});

test("(i) 'Cancel' in the add form returns to the list without saving", () => {
  mockContacts([ALICE]);
  const upsertSpy = vi.spyOn(client, "upsertContact");

  render(<Contacts />);
  fireEvent.click(screen.getByRole("button", { name: /\+ add contact/i }));
  fireEvent.click(screen.getByRole("button", { name: /cancel/i }));

  expect(screen.getByText("Alice")).toBeInTheDocument();
  expect(upsertSpy).not.toHaveBeenCalled();
});
