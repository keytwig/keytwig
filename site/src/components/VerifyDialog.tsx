import * as React from "react";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogTrigger } from "@/components/ui/dialog";
import { CodeBlock } from "@/components/CodeBlock";
import { GO_MOD_URL, RELEASE_DOWNLOAD, checksums, goDeps, verifyCode } from "@/data/release";

// Dependencies and checksums of the current release, with a copyable check. Full hashes, wrapped.
export function VerifyDialog() {
  return (
    <Dialog>
      <DialogTrigger asChild>
        <Button variant="outline" size="lg">
          Verify checksums &amp; dependencies
        </Button>
      </DialogTrigger>
      <DialogContent title="Verify checksums & dependencies" size="lg">
        <div className="grid gap-10">
          <section className="min-w-0">
            <div className="flex items-baseline justify-between gap-4">
              <h3 className="text-base font-medium text-white sm:text-lg">5 direct Go dependencies</h3>
              <a href={GO_MOD_URL} target="_blank" rel="noreferrer" className="shrink-0 text-sm text-zinc-400 transition-colors hover:text-white">
                go.mod ↗
              </a>
            </div>
            <ul className="mt-4 divide-y divide-white/[0.06]" role="list">
              {goDeps.map(([mod, ver, role]) => (
                <li key={mod} className="flex items-baseline justify-between gap-4 py-2.5">
                  <span className="code-surface min-w-0 truncate text-sm text-zinc-200">{mod}</span>
                  <span className="flex shrink-0 items-baseline gap-3">
                    <span className="hidden text-sm text-zinc-500 sm:inline">{role}</span>
                    <span className="code-surface text-xs text-zinc-400">{ver}</span>
                  </span>
                </li>
              ))}
            </ul>
          </section>

          <section className="min-w-0">
            <div className="flex items-baseline justify-between gap-4">
              <h3 className="text-base font-medium text-white sm:text-lg">SHA-256 of every archive</h3>
              <a
                href={`${RELEASE_DOWNLOAD}/checksums.txt`}
                target="_blank"
                rel="noreferrer"
                className="shrink-0 text-sm text-zinc-400 transition-colors hover:text-white"
              >
                checksums.txt ↗
              </a>
            </div>
            <ul className="mt-4 divide-y divide-white/[0.06]" role="list">
              {checksums.map(([file, sum]) => (
                <li key={file} className="grid gap-1 py-3 sm:grid-cols-[11rem_minmax(0,1fr)] sm:gap-4">
                  <span className="code-surface text-sm text-zinc-200">{file}</span>
                  <span className="code-surface text-xs leading-relaxed break-all text-zinc-400">{sum}</span>
                </li>
              ))}
            </ul>
          </section>

          <CodeBlock code={verifyCode} lang="bash" title="Check an archive" meta="sh" />
        </div>
      </DialogContent>
    </Dialog>
  );
}
