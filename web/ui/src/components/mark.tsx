// SPDX-License-Identifier: Apache-2.0
import { useEffect, useId, useRef } from "react";
import geometry from "../brand/geometry.json";

const round = (n: number) => Number(n.toFixed(2));

/** The egg outline in mark units, before the tilt (`scoplen-docs/18-visual-identity.md`). */
export function bodyPath(): string {
  const { top, bottom, halfWidth: w, centerX: cx, waist } = geometry.body;
  const mid = top + (bottom - top) * waist;
  const ht = mid - top;
  const hb = bottom - mid;
  const k = 0.56;
  const p = (x: number, y: number) => `${round(x)} ${round(y)}`;
  return (
    `M${p(cx, top)}` +
    `C${p(cx + w * k, top)} ${p(cx + w, mid - ht * 0.55)} ${p(cx + w, mid)}` +
    `C${p(cx + w, mid + hb * k)} ${p(cx + w * k, bottom)} ${p(cx, bottom)}` +
    `C${p(cx - w * k, bottom)} ${p(cx - w, mid + hb * k)} ${p(cx - w, mid)}` +
    `C${p(cx - w, mid - ht * 0.55)} ${p(cx - w * k, top)} ${p(cx, top)}Z`
  );
}

/**
 * What the mark's face shows. `rest` is the brand face: a cursor eye and a
 * wink. `awake` opens both eyes (paying attention), `closed` shuts both (not
 * looking, as while a secret is typed, or asleep), and `low` opens both eyes
 * a little lower and smaller (something is wrong).
 */
export type MarkMood = "rest" | "awake" | "closed" | "low";

/** One-shot movements: a hop, a rock back to upright, a shake of the head. */
export type MarkGesture = "hop" | "rock" | "shake";

export interface MarkProps {
  /** Rendered height and width in CSS units. */
  size?: string;
  /** Accessible name; omit when the mark is decorative next to the name. */
  title?: string;
  className?: string;
  mood?: MarkMood;
  /** Where the eyes look, each from -1 to 1 (left/up to right/down). */
  look?: { x: number; y: number };
  /** Extra tilt in degrees, added to the mark's own. */
  tilt?: number;
  /** Change this value to blink once. */
  blink?: unknown;
  /** Change `gesture.at` to play `gesture.name` once. */
  gesture?: { name: MarkGesture; at: unknown };
}

const { tilt: baseTilt, eyes } = geometry;
const reducedMotion = () =>
  typeof window !== "undefined" && window.matchMedia?.("(prefers-reduced-motion: reduce)").matches === true;

/** Web Animations, where the environment has them (not in every test DOM). */
function animate(element: Element | null, frames: Keyframe[], options: KeyframeAnimationOptions) {
  if (element && typeof element.animate === "function") element.animate(frames, options);
}

const gestures: Record<MarkGesture, { frames: Keyframe[]; duration: number }> = {
  hop: {
    frames: [
      { transform: "translateY(0)" },
      { transform: "translateY(-14%)", offset: 0.35 },
      { transform: "translateY(0)", offset: 0.7 },
      { transform: "translateY(-3%)", offset: 0.85 },
      { transform: "translateY(0)" },
    ],
    duration: 420,
  },
  rock: {
    frames: [
      { transform: "rotate(0)" },
      { transform: "rotate(14deg)", offset: 0.2 },
      { transform: "rotate(-8deg)", offset: 0.5 },
      { transform: "rotate(3deg)", offset: 0.78 },
      { transform: "rotate(0)" },
    ],
    duration: 620,
  },
  shake: {
    frames: [
      { transform: "rotate(0)" },
      { transform: "rotate(-9deg)", offset: 0.2 },
      { transform: "rotate(8deg)", offset: 0.45 },
      { transform: "rotate(-5deg)", offset: 0.7 },
      { transform: "rotate(0)" },
    ],
    duration: 460,
  },
};

/**
 * The Scoplen mark: a small tilted egg whose eyes are a text cursor and a
 * wink, in the current text color. Its face can change (`mood`), its eyes can
 * look somewhere (`look`), and it can blink or move once when something
 * happens. It never moves on its own, and with reduced motion its face
 * changes without animating.
 */
export function Mark({ size = "1em", title, className, mood = "rest", look, tilt = 0, blink, gesture }: MarkProps) {
  const mask = `scoplen-eyes-${useId().replace(/:/g, "")}`;
  const body = useRef<SVGGElement>(null);
  const face = useRef<SVGGElement>(null);
  const first = useRef(true);

  useEffect(() => {
    if (first.current || reducedMotion()) return;
    animate(
      face.current,
      [{ transform: "scaleY(1)" }, { transform: "scaleY(0.1)", offset: 0.45 }, { transform: "scaleY(1)" }],
      { duration: 260, easing: "ease-in-out" },
    );
  }, [blink]);

  useEffect(() => {
    if (first.current || !gesture || reducedMotion()) return;
    const { frames, duration } = gestures[gesture.name];
    animate(body.current, frames, { duration, easing: "cubic-bezier(.3,.7,.4,1)" });
    // Only the moment matters; the gesture name is read when it changes.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [gesture?.at]);

  useEffect(() => {
    first.current = false;
  }, []);

  const dx = (look?.x ?? 0) * 3.5;
  const dy = (look?.y ?? 0) * 3;

  return (
    <svg
      viewBox="0 0 64 64"
      width={size}
      height={size}
      className={["scoplen-mark", className].filter(Boolean).join(" ")}
      data-mood={mood}
      role={title ? "img" : undefined}
      aria-hidden={title ? undefined : true}
      aria-label={title}
      focusable="false"
      overflow="visible"
    >
      <g transform={`rotate(${baseTilt.angle} ${baseTilt.x} ${baseTilt.y})`}>
        <g className="scoplen-mark-tilt" style={{ transform: `rotate(${tilt}deg)` }}>
          <g ref={body} className="scoplen-mark-body">
            <mask id={mask} maskUnits="userSpaceOnUse" x="-16" y="-16" width="96" height="96">
              <rect x="-16" y="-16" width="96" height="96" fill="#fff" />
              <g ref={face} className="scoplen-mark-face">
                <g className="scoplen-mark-look" style={{ transform: `translate(${dx}px, ${dy}px)` }}>
                  {(["open", "wink"] as const).map((eye) => {
                    const e = eyes[eye];
                    return (
                      <rect
                        key={eye}
                        data-eye={eye}
                        x={e.x}
                        y={e.y}
                        width={e.width}
                        height={e.height}
                        rx={Math.min(e.width, e.height) / 2}
                        fill="#000"
                      />
                    );
                  })}
                </g>
              </g>
            </mask>
            <path fill="currentColor" mask={`url(#${mask})`} d={bodyPath()} />
          </g>
        </g>
      </g>
    </svg>
  );
}
