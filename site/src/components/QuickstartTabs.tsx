import * as React from "react";
import { MotionConfig, motion } from "motion/react";
import { CodeBlock } from "@/components/CodeBlock";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { installPrompt } from "@/data/prompts";

type Snippet = {
  id: string;
  label: string;
  title: string;
  code: string;
  lang: "bash" | "prompt";
};

const after = `

keytwig init
keytwig install all`;

const snippets: Snippet[] = [
  {
    id: "curl",
    label: "curl",
    title: "Linux or macOS",
    lang: "bash",
    code: `curl -fsSL https://raw.githubusercontent.com/keytwig/keytwig/main/scripts/install.sh \\
  | sh${after}`,
  },
  {
    id: "brew",
    label: "Homebrew",
    title: "Homebrew",
    lang: "bash",
    code: `brew install memtwig/tap/keytwig${after}`,
  },
  {
    id: "go",
    label: "Go",
    title: "Build with Go",
    lang: "bash",
    code: `go install github.com/keytwig/keytwig/cmd/keytwig@latest${after}`,
  },
  {
    id: "prompt",
    label: "Prompt",
    title: "Paste into your agent",
    lang: "prompt",
    code: installPrompt,
  },
];

export function QuickstartTabs() {
  const [activeTab, setActiveTab] = React.useState(snippets[0].id);

  return (
    <MotionConfig reducedMotion="user">
      <Tabs value={activeTab} onValueChange={setActiveTab} className="w-full min-w-0">
        <TabsList aria-label="Install method" className="w-full justify-between sm:w-auto sm:justify-start">
          {snippets.map((s) => (
            <TabsTrigger
              key={s.id}
              value={s.id}
              className="relative z-10 flex-1 px-3 text-xs text-zinc-400 transition-colors hover:text-zinc-200 data-[state=active]:bg-transparent data-[state=active]:text-[#141415] sm:flex-none sm:px-4 sm:text-sm"
            >
              {activeTab === s.id && (
                <motion.span
                  layoutId="quickstart-tab-pill"
                  transition={{ type: "spring", stiffness: 420, damping: 32 }}
                  className="absolute inset-0 -z-10 rounded-full bg-[#ebb85e]"
                  aria-hidden="true"
                />
              )}
              {s.label}
            </TabsTrigger>
          ))}
        </TabsList>

        {snippets.map((s) => (
          <TabsContent key={s.id} value={s.id} className="mt-4">
            <motion.div initial={{ opacity: 0, y: 6 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.2 }}>
              <CodeBlock
                code={s.code}
                lang={s.lang}
                title={s.title}
                meta={s.lang === "prompt" ? "prompt" : "sh"}
                wrap={s.lang === "prompt"}
                copyLabel={s.lang === "prompt" ? "Copy prompt" : undefined}
                bodyClassName={s.lang === "prompt" ? "max-h-[19rem] overflow-y-auto" : undefined}
              />
            </motion.div>
          </TabsContent>
        ))}
      </Tabs>
    </MotionConfig>
  );
}
