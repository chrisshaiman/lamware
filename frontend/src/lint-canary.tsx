// TEMPORARY (#233 acceptance): a lint error that tsc and vite accept, to prove CI's
// Lint step fails. Removed before merge.
import { useState } from "react";

export function LintCanary({ on }: { on: boolean }) {
  if (on) {
    useState(0);
  }
  return null;
}
