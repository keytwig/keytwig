import * as React from "react";
import { MotionConfig, motion } from "motion/react";
import { Robot } from "@phosphor-icons/react";
import { CodeBlock } from "@/components/CodeBlock";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { auditPrompt, projectPrompt } from "@/data/prompts";

// The install prompt lives in the hero's "Prompt" tab; these are the next two jobs.
const prompts = [
  { id: "project", label: "Move a project", prompt: projectPrompt },
  { id: "audit", label: "Scope my agents", prompt: auditPrompt },
];

export function AgentPromptBox() {
  const [activeId, setActiveId] = React.useState(prompts[0].id);
  const active = prompts.find((p) => p.id === activeId) ?? prompts[0];

  return (
    <MotionConfig reducedMotion="user">
      <Tabs value={activeId} onValueChange={setActiveId} className="rounded-[24px] border border-white/[0.08] bg-[#161619] p-5 sm:p-7">
        <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
          <div className="flex min-w-0 items-center gap-3">
            <span className="inline-flex size-9 shrink-0 items-center justify-center rounded-full border border-white/[0.1] bg-[#1f2024] text-[#ebb85e]">
              <Robot size={18} aria-hidden="true" />
            </span>
            <p className="text-sm text-zinc-300">Claude Code · Codex · Cursor · Windsurf · Antigravity · Hermes</p>
          </div>

          <TabsList aria-label="Prompt" className="self-start bg-[#111113] sm:self-auto">
            {prompts.map((item) => (
              <TabsTrigger
                key={item.id}
                value={item.id}
                className="relative z-10 px-3.5 text-xs text-zinc-400 hover:text-zinc-200 data-[state=active]:bg-transparent data-[state=active]:text-[#141415]"
              >
                {item.id === active.id && (
                  <motion.span
                    layoutId="agent-prompt-pill"
                    transition={{ type: "spring", stiffness: 420, damping: 32 }}
                    className="absolute inset-0 -z-10 rounded-full bg-[#ebb85e]"
                    aria-hidden="true"
                  />
                )}
                {item.label}
              </TabsTrigger>
            ))}
          </TabsList>
        </div>

        {prompts.map((item) => (
          <TabsContent key={item.id} value={item.id} className="mt-4">
            <CodeBlock code={item.prompt} lang="prompt" wrap title={item.label} meta="prompt" copyLabel="Copy prompt" />
          </TabsContent>
        ))}
      </Tabs>
    </MotionConfig>
  );
}
