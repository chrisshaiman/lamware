// Copyright 2026 Christopher Shaiman
// SPDX-License-Identifier: Apache-2.0

import { cn } from "#lib/utils";

interface MonoTextProps {
  children: React.ReactNode;
  className?: string;
  truncate?: number;
}

/** Monospace text for hashes, IOC values, technique IDs. */
export function MonoText({ children, className, truncate: maxLen }: MonoTextProps) {
  let text = String(children);
  if (maxLen && text.length > maxLen) {
    text = text.slice(0, maxLen) + "\u2026";
  }

  return (
    <span
      className={cn("font-mono text-xs text-[var(--color-text-secondary)]", className)}
      title={String(children)}
    >
      {text}
    </span>
  );
}
