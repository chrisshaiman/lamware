// Copyright 2026 Christopher Shaiman
// SPDX-License-Identifier: Apache-2.0

import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";
import { cn } from "#lib/utils";

interface MarkdownProseProps {
  children: string;
  className?: string;
}

export function MarkdownProse({ children, className }: MarkdownProseProps) {
  return (
    <div
      className={cn(
        "prose prose-invert max-w-none text-sm leading-relaxed",
        "prose-headings:text-[var(--color-text-primary)] prose-headings:font-semibold",
        "prose-p:text-[var(--color-text-secondary)]",
        "prose-a:text-[var(--color-accent)] prose-a:no-underline hover:prose-a:underline",
        "prose-code:rounded prose-code:bg-[var(--color-surface)] prose-code:px-1.5 prose-code:py-0.5 prose-code:font-mono prose-code:text-xs prose-code:text-[var(--color-text-secondary)]",
        "prose-pre:bg-[var(--color-surface)] prose-pre:border prose-pre:border-[var(--color-border)]",
        "prose-li:text-[var(--color-text-secondary)]",
        "prose-strong:text-[var(--color-text-primary)]",
        "prose-table:border-collapse",
        "prose-th:border prose-th:border-[var(--color-border)] prose-th:bg-[var(--color-surface)] prose-th:px-3 prose-th:py-2",
        "prose-td:border prose-td:border-[var(--color-border)] prose-td:px-3 prose-td:py-2",
        className,
      )}
    >
      <ReactMarkdown remarkPlugins={[remarkGfm]}>{children}</ReactMarkdown>
    </div>
  );
}
