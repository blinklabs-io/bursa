import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { MetadataBuilder } from "./MetadataBuilder";
import * as client from "../../api/client";
import type { PoolMetadataResult } from "../../api/types";

const RESULT: PoolMetadataResult = {
  json: '{"name":"My Pool","ticker":"POOL"}',
  hash_hex: "feedface",
};

afterEach(() => {
  vi.restoreAllMocks();
});

test("builds canonical JSON + hash, trimming each field before sending", async () => {
  const build = vi.spyOn(client, "poolBuildMetadata").mockResolvedValue(RESULT);
  render(<MetadataBuilder />);

  fireEvent.change(screen.getByLabelText(/^name$/i), { target: { value: "  My Pool  " } });
  fireEvent.change(screen.getByLabelText(/^ticker$/i), { target: { value: " POOL " } });
  fireEvent.change(screen.getByLabelText(/^homepage$/i), {
    target: { value: " https://pool.example " },
  });
  fireEvent.change(screen.getByLabelText(/^description$/i), { target: { value: " hi " } });
  fireEvent.click(screen.getByRole("button", { name: /build metadata/i }));

  await waitFor(() =>
    expect(build).toHaveBeenCalledWith({
      name: "My Pool",
      ticker: "POOL",
      homepage: "https://pool.example",
      description: "hi",
    }),
  );
  expect(await screen.findByText("feedface")).toBeInTheDocument();
  expect(screen.getByText(RESULT.json)).toBeInTheDocument();
});

test("the build button requires both a name and a ticker", () => {
  render(<MetadataBuilder />);
  const button = screen.getByRole("button", { name: /build metadata/i });
  expect(button).toBeDisabled();

  fireEvent.change(screen.getByLabelText(/^name$/i), { target: { value: "My Pool" } });
  expect(button).toBeDisabled(); // ticker still missing

  fireEvent.change(screen.getByLabelText(/^ticker$/i), { target: { value: "POOL" } });
  expect(button).not.toBeDisabled();
});

test("a whitespace-only ticker keeps the build button disabled", () => {
  render(<MetadataBuilder />);
  fireEvent.change(screen.getByLabelText(/^name$/i), { target: { value: "My Pool" } });
  fireEvent.change(screen.getByLabelText(/^ticker$/i), { target: { value: "   " } });
  expect(screen.getByRole("button", { name: /build metadata/i })).toBeDisabled();
});

test("surfaces an ApiError from the backend", async () => {
  vi.spyOn(client, "poolBuildMetadata").mockRejectedValue(
    new client.ApiError(400, "ticker too long"),
  );
  render(<MetadataBuilder />);

  fireEvent.change(screen.getByLabelText(/^name$/i), { target: { value: "My Pool" } });
  fireEvent.change(screen.getByLabelText(/^ticker$/i), { target: { value: "TOOLONG" } });
  fireEvent.click(screen.getByRole("button", { name: /build metadata/i }));

  await waitFor(() => expect(screen.getByRole("alert")).toHaveTextContent(/ticker too long/i));
});
