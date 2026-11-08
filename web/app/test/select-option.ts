// SPDX-License-Identifier: Apache-2.0
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

export async function selectOption(trigger: HTMLElement, label: string | RegExp) {
  await userEvent.click(trigger);
  const list = await screen.findByRole("listbox");
  await userEvent.click(within(list).getByRole("option", { name: label }));
  await waitFor(() => expect(screen.queryByRole("listbox")).toBeNull());
  await waitFor(() => expect(document.activeElement).toBe(trigger));
}
