// Copyright 2026 Christopher Shaiman
// SPDX-License-Identifier: Apache-2.0
//
// A single chat message in the investigation panel. User messages render as
// plain text bubbles; assistant messages render as sanitized markdown via the
// shared MarkdownProse component (rehype-sanitize). Assistant output can echo
// malware-derived strings, so it MUST go through the same sanitization path
// as the analysis narrative — never raw HTML.

import { MarkdownProse } from "#components/shared/markdown-prose";

interface InvestigationMessageProps {
  role: "user" | "assistant";
  content: string;
  /** True while tokens are still streaming in — shows a blinking cursor. */
  streaming?: boolean;
}

export function InvestigationMessage({ role, content, streaming }: InvestigationMessageProps) {
  if (role === "user") {
    return (
      <div className="flex justify-end">
        <div className="max-w-[85%] rounded-md border border-[var(--color-border-light)] bg-[var(--color-surface-hover)] px-3 py-2 text-sm whitespace-pre-wrap break-words text-[var(--color-text-primary)]">
          {content}
        </div>
      </div>
    );
  }

  return (
    <div className="min-w-0">
      {content && <MarkdownProse>{content}</MarkdownProse>}
      {streaming && (
        <span
          className="animate-pulse text-sm text-[var(--color-accent)]"
          aria-label="Assistant is responding"
        >
          {"▋"}
        </span>
      )}
    </div>
  );
}
