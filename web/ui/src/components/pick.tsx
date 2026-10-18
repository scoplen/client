// SPDX-License-Identifier: Apache-2.0

/**
 * The mark's open eye marking the selected item: a short upright pill on the
 * item's left edge that grows in and blinks once when it appears. Place it
 * inside a relatively positioned element. It is decorative, so the element
 * itself must convey selection to assistive technology (`aria-selected`,
 * `aria-current`).
 */
export function Pick({ className }: { className?: string }) {
  return <span aria-hidden="true" className={["scoplen-pick", className].filter(Boolean).join(" ")} />;
}
