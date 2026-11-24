import * as React from "react";
import { MotionConfig, motion, useInView, useReducedMotion } from "motion/react";
import { ArrowCounterClockwise } from "@phosphor-icons/react";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Button } from "@/components/ui/button";

/*
 * Transcript recorded with keytwig v0.1.0 in a sandbox (KEYTWIG_HOME, dummy key) on 2026-11-24.
 * Only the project path was shortened to ~/code/shop. Segment kinds:
 * "" plain output, dim = table headers, ok = added, mask = ‹keytwig:NAME›.
 */
type Seg = [string, ("" | "dim" | "ok" | "mask")?];
type Step = { id: string; label: string; cmd: string[]; out: Seg[][] };

const M: Seg = ["‹keytwig:STRIPE_SECRET_KEY›", "mask"];

const steps: Step[] = [
  {
    id: "scan",
    label: "scan",
    cmd: ["keytwig scan ~/code"],
    out: [
      [["env files: 1 — project 1, harness 0, app 0, backup 0"]],
      [["secret entries: 2 → unique values: 2 → from project files, not yet in keytwig: 2"]],
      [["tool credential files: 0"]],
      [],
      [["CLASS    ENV FILE           SECRETS  OTHER", "dim"]],
      [["project  ~/code/shop/.env   2        0"]],
    ],
  },
  {
    id: "import",
    label: "import",
    cmd: ["keytwig import --scan ~/code"],
    out: [
      [["reading 1 project env files (harness, app and backup files are left alone)"]],
      [],
      [["DATABASE_URL       "], ["added", "ok"]],
      [["STRIPE_SECRET_KEY  "], ["added", "ok"]],
      [],
      [["added 2, aliases (same value, stored once) 0, updated 0, unchanged 0, conflicts 0"]],
    ],
  },
  {
    id: "run",
    label: "run",
    cmd: [
      "keytwig run -k STRIPE_SECRET_KEY -- sh -c \\",
      `  'curl -s https://httpbin.org/bearer -H "Authorization: Bearer $STRIPE_SECRET_KEY"'`,
    ],
    out: [[["{"]], [['  "authenticated": true,']], [['  "token": "'], M, ['"']], [["}"]]],
  },
  {
    id: "log",
    label: "log",
    cmd: ["keytwig log --limit 1"],
    out: [
      [["TIME                 MODE  AGENT  EXIT  REDACT  INJECTED           COMMAND", "dim"]],
      [["2026-11-24 19:32:34  cli   —      0     1       STRIPE_SECRET_KEY  sh -c curl -s https://httpbin.org/bearer -H \"Authorization: Bearer $STRIPE_SECRET_KEY\""]],
    ],
  },
];

const TYPE_MS = 18;
const LINE_MS = 70;
const HOLD_MS = 2200;

const segClass: Record<string, string> = {
  "": "text-zinc-300",
  dim: "text-zinc-500",
  ok: "text-[#8be3a6]",
  mask: "tok-mask px-0.5",
};

function CommandLine({ text, first }: { text: string; first: boolean }) {
  // keytwig in amber, flags in sky, the rest plain: same tokens as the code blocks.
  const parts = text.split(/(\s+)/);
  return (
    <span>
      <span className="text-zinc-500 select-none">{first ? "$ " : "  "}</span>
      {parts.map((p, i) => {
        const cls = p === "keytwig" ? "tok-cmd" : /^-{1,2}[\w-]+$/.test(p) ? "tok-flag" : "text-zinc-100";
        return (
          <span key={i} className={cls}>
            {p}
          </span>
        );
      })}
    </span>
  );
}

export function TerminalShowcase() {
  const rootRef = React.useRef<HTMLDivElement>(null);
  const inView = useInView(rootRef, { amount: 0.35 });
  const reduced = useReducedMotion();
  const [index, setIndex] = React.useState(0);
  const [typed, setTyped] = React.useState(0); // characters of the command shown
  const [lines, setLines] = React.useState(0); // output lines shown
  const [auto, setAuto] = React.useState(true);

  const step = steps[index];
  const cmdText = step.cmd.join("\n");
  const doneTyping = typed >= cmdText.length;
  const doneOutput = lines >= step.out.length;

  // Show everything at once when motion is reduced or before the first frame of the animation.
  React.useEffect(() => {
    if (reduced) {
      setTyped(Number.MAX_SAFE_INTEGER);
      setLines(Number.MAX_SAFE_INTEGER);
    }
  }, [reduced, index]);

  React.useEffect(() => {
    if (reduced || !inView) return;
    let t: number | undefined;
    if (!doneTyping) {
      t = window.setTimeout(() => setTyped((n) => Math.min(cmdText.length, n + 2)), TYPE_MS);
    } else if (!doneOutput) {
      t = window.setTimeout(() => setLines((n) => n + 1), lines === 0 ? 260 : LINE_MS);
    } else if (auto) {
      t = window.setTimeout(() => {
        setIndex((i) => (i + 1) % steps.length);
        setTyped(0);
        setLines(0);
      }, HOLD_MS);
    }
    return () => window.clearTimeout(t);
  }, [reduced, inView, doneTyping, doneOutput, typed, lines, auto, cmdText.length]);

  const select = (id: string) => {
    const i = steps.findIndex((s) => s.id === id);
    setAuto(false);
    setIndex(i);
    setTyped(reduced ? Number.MAX_SAFE_INTEGER : 0);
    setLines(reduced ? Number.MAX_SAFE_INTEGER : 0);
  };

  const replay = () => {
    setAuto(true);
    setIndex(0);
    setTyped(reduced ? Number.MAX_SAFE_INTEGER : 0);
    setLines(reduced ? Number.MAX_SAFE_INTEGER : 0);
  };

  // Split the typed prefix back into the command's visual lines.
  const shown = cmdText.slice(0, typed).split("\n");

  return (
    <MotionConfig reducedMotion="user">
      <div ref={rootRef} className="min-w-0">
        <Tabs value={step.id} onValueChange={select} className="min-w-0">
          <figure className="min-w-0 overflow-hidden rounded-[20px] border border-white/[0.08] bg-[#111113] shadow-[inset_0_1px_0_rgba(255,255,255,0.04),0_30px_80px_-40px_rgba(0,0,0,0.95)]">
            <figcaption className="flex min-h-12 items-center justify-between gap-3 border-b border-white/[0.06] bg-[#18181b] py-2 pr-2 pl-4 sm:pl-5">
              <div className="flex min-w-0 items-center gap-3">
                <span className="flex shrink-0 items-center gap-1.5" aria-hidden="true">
                  <span className="size-2 rounded-full bg-white/[0.12]" />
                  <span className="size-2 rounded-full bg-white/[0.12]" />
                  <span className="size-2 rounded-full bg-white/[0.12]" />
                </span>
                <span className="truncate text-sm font-medium text-zinc-200">~/code/shop</span>
              </div>
              <Button
                type="button"
                variant="outline"
                size="icon"
                onClick={replay}
                aria-label="Replay the session"
                className="inline-flex size-8 shrink-0 cursor-pointer items-center justify-center rounded-full border border-white/[0.09] bg-white/[0.03] text-zinc-400 transition-colors hover:border-white/20 hover:bg-white/[0.07] hover:text-white focus-visible:ring-2 focus-visible:ring-[#ebb85e]/60 focus-visible:outline-none"
              >
                <ArrowCounterClockwise size={15} aria-hidden="true" />
              </Button>
            </figcaption>

            {steps.map((s) => (
              <TabsContent key={s.id} value={s.id} className="mt-0">
                <pre className="code-surface m-0 h-[13.5rem] overflow-auto px-4 py-4 text-[12px] leading-[1.75] whitespace-pre sm:h-[14.5rem] sm:px-5 sm:text-[12.5px]">
                  <code>
                    {shown.map((line, i) => (
                      <React.Fragment key={`c${i}`}>
                        <CommandLine text={line} first={i === 0} />
                        {!doneTyping && i === shown.length - 1 && <span className="term-caret ml-px" aria-hidden="true" />}
                        {"\n"}
                      </React.Fragment>
                    ))}
                    {s.out.slice(0, lines).map((segs, li) => (
                      <motion.span
                        key={`o${li}`}
                        initial={{ opacity: 0 }}
                        animate={{ opacity: 1 }}
                        transition={{ duration: 0.18 }}
                      >
                        {segs.map(([text, kind = ""], si) => (
                          <span key={si} className={segClass[kind]}>
                            {text}
                          </span>
                        ))}
                        {"\n"}
                      </motion.span>
                    ))}
                    {doneTyping && doneOutput && (
                      <span>
                        <span className="text-zinc-500 select-none">$ </span>
                        <span className="term-caret" aria-hidden="true" />
                      </span>
                    )}
                  </code>
                </pre>
              </TabsContent>
            ))}
          </figure>

          <TabsList aria-label="Session step" className="mt-3 w-full justify-between sm:w-auto sm:justify-start">
            {steps.map((s, i) => (
              <TabsTrigger
                key={s.id}
                value={s.id}
                className="relative z-10 flex-1 gap-2 px-3 text-xs text-zinc-400 transition-colors hover:text-zinc-200 data-[state=active]:bg-transparent data-[state=active]:text-white sm:flex-none sm:px-4 sm:text-sm"
              >
                {step.id === s.id && (
                  <motion.span
                    layoutId="terminal-step-pill"
                    transition={{ type: "spring", stiffness: 420, damping: 32 }}
                    className="absolute inset-0 -z-10 rounded-full bg-white/[0.1]"
                    aria-hidden="true"
                  />
                )}
                <span className="text-zinc-500 tabular-nums">{i + 1}</span>
                {s.label}
              </TabsTrigger>
            ))}
          </TabsList>
        </Tabs>
      </div>
    </MotionConfig>
  );
}
