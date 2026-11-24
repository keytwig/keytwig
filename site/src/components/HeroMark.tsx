import * as React from "react";
import { MotionConfig, motion, useReducedMotion } from "motion/react";

const INK = "#141415";
const EASE = [0.22, 1, 0.36, 1] as const;

/**
 * The keytwig mark drawn inline: the bow closes, the shaft drops, the two bits cut in,
 * then the pin lands in the bow. On hover a signal runs down the shaft into the bits,
 * the same path a secret takes from the vault into a child process.
 */
export function HeroKeyBadge() {
  const prefersReduced = useReducedMotion();
  const [signal, setSignal] = React.useState(0);
  const fire = () => {
    if (!prefersReduced) setSignal((n) => n + 1);
  };

  return (
    <MotionConfig reducedMotion="user">
      <motion.span
        whileHover={{ scale: 1.05, rotate: 4 }}
        whileTap={{ scale: 0.97 }}
        transition={{ type: "spring", stiffness: 340, damping: 20 }}
        onHoverStart={fire}
        onTap={fire}
        className="mx-1.5 inline-block size-11 cursor-pointer rounded-2xl align-[-0.14em] shadow-[0_12px_36px_rgba(235,184,94,0.3)] sm:mx-2.5 sm:size-16 xl:size-[4.25rem]"
        aria-hidden="true"
        tabIndex={-1}
      >
        <svg viewBox="0 0 32 32" className="block size-full" fill="none">
          <rect width="32" height="32" rx="8" fill="#ebb85e" />
          <circle className="twig-stroke" pathLength={1} cx="16" cy="10.6" r="4.2" stroke={INK} strokeWidth="2.6" style={{ ["--d" as string]: "0.15s" }} />
          <path className="twig-stroke" pathLength={1} d="M16 14.8V25" stroke={INK} strokeWidth="2.6" strokeLinecap="round" style={{ ["--d" as string]: "0.5s" }} />
          <path className="twig-stroke" pathLength={1} d="M16 20.6H20.6" stroke={INK} strokeWidth="2.6" strokeLinecap="round" style={{ ["--d" as string]: "0.72s" }} />
          <path className="twig-stroke" pathLength={1} d="M16 24.4H19.4" stroke={INK} strokeWidth="2.6" strokeLinecap="round" style={{ ["--d" as string]: "0.82s" }} />
          <circle className="twig-bud" cx="16" cy="10.6" r="1.35" fill={INK} />
          {signal > 0 && (
            <motion.path
              key={signal}
              d="M16 12V20.6H20.6"
              pathLength={1}
              stroke="#fff6e3"
              strokeWidth="1.3"
              strokeLinecap="round"
              strokeLinejoin="round"
              strokeDasharray="0.28 1.4"
              initial={{ strokeDashoffset: 0.28, opacity: 1 }}
              animate={{ strokeDashoffset: -1, opacity: [1, 1, 0] }}
              transition={{ duration: 0.75, ease: EASE, times: [0, 0.8, 1] }}
            />
          )}
        </svg>
      </motion.span>
    </MotionConfig>
  );
}
