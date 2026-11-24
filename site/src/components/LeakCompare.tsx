import * as React from "react";
import { AnimatePresence, MotionConfig, motion } from "motion/react";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogTrigger } from "@/components/ui/dialog";
import { Tabs, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { TerminalShowcase } from "@/components/TerminalShowcase";

/*
 * Hero visual: the same request to httpbin.org/bearer, without and with keytwig.
 * Both outputs recorded with keytwig v0.2.0 and a dummy key (sk_test_demo…) on 2026-11-24;
 * the full session (scan, import, run, log) opens in a dialog.
 */
type Mode = "without" | "with";

const VALUE: Record<Mode, string> = {
  without: "sk_test_demo4f9a8b7c6d5e",
  with: "‹keytwig:STRIPE_SECRET_KEY›",
};

export function LeakCompare() {
  const [mode, setMode] = React.useState<Mode>("with");
  const leak = mode === "without";

  return (
    <MotionConfig reducedMotion="user">
      <div
        className={`relative min-w-0 overflow-hidden rounded-[28px] border bg-[#111113] transition-[border-color,box-shadow] duration-500 ${
          leak
            ? "border-[#f09a7a]/35 shadow-[0_40px_120px_-40px_rgba(240,154,122,0.35)]"
            : "border-[#58cc7d]/30 shadow-[0_40px_120px_-40px_rgba(88,204,125,0.3)]"
        }`}
      >
        <div className="flex flex-wrap items-center justify-between gap-3 border-b border-white/[0.06] bg-[#18181b] px-4 py-3 sm:px-6">
          <span className="text-sm font-medium text-zinc-300">What the model sees</span>
          <Tabs value={mode} onValueChange={(v) => setMode(v as Mode)}>
            <TabsList aria-label="Compare" className="bg-[#111113]">
              {(["without", "with"] as const).map((m) => (
                <TabsTrigger
                  key={m}
                  value={m}
                  className={`relative z-10 px-3 text-xs text-zinc-400 hover:text-zinc-200 data-[state=active]:bg-transparent sm:px-4 sm:text-sm ${
                    m === "with" ? "data-[state=active]:text-[#0f2417]" : "data-[state=active]:text-[#2a130b]"
                  }`}
                >
                  {mode === m && (
                    <motion.span
                      layoutId="hero-mode-pill"
                      transition={{ type: "spring", stiffness: 420, damping: 32 }}
                      className={`absolute inset-0 -z-10 rounded-full ${m === "with" ? "bg-[#58cc7d]" : "bg-[#f09a7a]"}`}
                      aria-hidden="true"
                    />
                  )}
                  {m === "with" ? "With Keytwig" : "Without Keytwig"}
                </TabsTrigger>
              ))}
            </TabsList>
          </Tabs>
        </div>

        <div className="px-5 py-8 sm:px-10 sm:py-12">
          <pre className="code-surface m-0 overflow-x-auto text-[12px] leading-[1.9] text-zinc-300 min-[400px]:text-[13px] sm:text-lg" aria-live="polite">
            <code>
              {"{\n"}
              {'  "authenticated": true,\n'}
              {'  "token": "'}
              <AnimatePresence mode="wait" initial={false}>
                <motion.span
                  key={mode}
                  initial={{ opacity: 0, filter: "blur(6px)" }}
                  animate={{ opacity: 1, filter: "blur(0px)" }}
                  exit={{ opacity: 0, filter: "blur(6px)" }}
                  transition={{ duration: 0.22 }}
                  className={leak ? "tok-leak px-1" : "tok-mask px-1"}
                >
                  {VALUE[mode]}
                </motion.span>
              </AnimatePresence>
              {'"\n}'}
            </code>
          </pre>

          <div className="mt-8 flex flex-wrap items-center justify-between gap-4">
            <p className={`flex items-center gap-2.5 text-base font-medium sm:text-lg ${leak ? "text-[#f4a493]" : "text-[#8be3a6]"}`}>
              <span className={`size-2 rounded-full ${leak ? "bg-[#f09a7a]" : "bg-[#58cc7d] shadow-[0_0_10px_#58cc7d]"}`} aria-hidden="true" />
              {leak ? "Your live key, now in the prompt" : "The agent used the key. The model never saw it."}
            </p>
            <Dialog>
              <DialogTrigger asChild>
                <Button variant="ghost" size="sm" className="text-zinc-400">
                  See full terminal session
                </Button>
              </DialogTrigger>
              <DialogContent title="Full terminal session" size="lg">
                <TerminalShowcase />
              </DialogContent>
            </Dialog>
          </div>
        </div>
      </div>
    </MotionConfig>
  );
}
