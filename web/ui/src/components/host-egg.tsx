// SPDX-License-Identifier: Apache-2.0
import { Mark, type MarkMood } from "./mark";

/** A small stable number from a string, for choosing a host's pose. */
function hash(value: string): number {
  let h = 2166136261;
  for (let i = 0; i < value.length; i++) h = Math.imul(h ^ value.charCodeAt(i), 16777619);
  return h >>> 0;
}

const poses: { tilt: number; look: { x: number; y: number }; mood: MarkMood }[] = [
  { tilt: 0, look: { x: 0, y: 0 }, mood: "rest" },
  { tilt: 12, look: { x: 0.6, y: -0.3 }, mood: "awake" },
  { tilt: -6, look: { x: -0.7, y: 0.2 }, mood: "awake" },
  { tilt: 18, look: { x: 0.3, y: 0.5 }, mood: "rest" },
  { tilt: -12, look: { x: 0.8, y: 0 }, mood: "awake" },
  { tilt: 6, look: { x: -0.4, y: -0.6 }, mood: "rest" },
];

export interface HostEggProps {
  /** A stable identifier; the same host always gets the same pose. */
  seed: string;
  /** Selected or connected hosts take the accent; the rest are quiet. */
  active?: boolean;
  /** Something is wrong with this host (a failed session, a changed key). */
  attention?: boolean;
  size?: string;
  className?: string;
  /** Change to blink once. */
  blink?: unknown;
  /** A face for the moment, such as eyes wide open while connecting; else the host's own. */
  mood?: MarkMood;
}

/**
 * Each host's own little egg: the mark in one of a few poses chosen from the
 * host's identifier, so a list of hosts reads as a crowd of individuals
 * rather than identical icons. It is always decorative; the host's name
 * carries its meaning.
 */
export function HostEgg({ seed, active, attention, size = "1.75rem", className, blink, mood }: HostEggProps) {
  const pose = poses[hash(seed) % poses.length]!;
  const tone = attention ? "text-attention" : active ? "text-primary" : "text-egg";
  return (
    <Mark
      size={size}
      tilt={pose.tilt}
      look={pose.look}
      mood={mood ?? (attention ? "low" : pose.mood)}
      blink={blink}
      className={["shrink-0 transition-colors duration-(--duration-state)", tone, className].filter(Boolean).join(" ")}
    />
  );
}
