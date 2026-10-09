// Copyright 2026 Christopher Shaiman
// SPDX-License-Identifier: Apache-2.0

import ReactMarkdown from "react-markdown";
import rehypeSanitize from "rehype-sanitize";
import remarkGfm from "remark-gfm";
import { cn } from "#lib/utils";
import { defang, isInAppHref } from "#lib/defang";

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
      <ReactMarkdown
        remarkPlugins={[remarkGfm]}
        rehypePlugins={[rehypeSanitize]}
        components={{ a: DefangedAnchor, img: InertImage }}
      >
        {defang(children)}
      </ReactMarkdown>
    </div>
  );
}

/**
 * Render links from model prose as inert text.
 *
 * Both defences are needed, and neither is sufficient alone:
 *
 *   defang(children)  kills bare URLs, which remark-gfm would otherwise autolink —
 *                     but an explicit `[click here](http://evil.com)` hides the
 *                     indicator in the href where the text pass never sees it.
 *   DefangedAnchor    kills explicit markdown links — but leaves the visible text
 *                     copy-pasteable as a live URL if it was never defanged.
 *
 * Only `#fragment` and root-relative `/path` stay clickable — an ALLOWLIST. The first
 * version asked "is this a known-navigable scheme?" and rendered anything unmatched as a
 * live anchor, so `//evil.com/x` (no scheme colon) fell straight through and the browser
 * resolved it to `https://evil.com/x`. `rehype-sanitize` allows it for the same reason.
 * On a security boundary the deny-list has to enumerate every way of writing "off-site";
 * the allowlist enumerates the two ways of writing "in-app".
 */
function DefangedAnchor({
  href,
  children,
  // react-markdown passes its hast `node`; spread onto <a> it renders as a
  // bogus DOM attribute. Taken out here so `rest` holds HTML attributes only.
  // eslint-disable-next-line @typescript-eslint/no-unused-vars -- removed, not used
  node: _node,
  ...rest
}: React.AnchorHTMLAttributes<HTMLAnchorElement> & { node?: unknown }) {
  if (isInAppHref(href)) {
    return (
      <a href={href} {...rest}>
        {children}
      </a>
    );
  }
  return (
    <span
      data-defanged-link="true"
      title={`Link neutralised: ${defang(href ?? "")}`}
      className="break-all text-[var(--color-text-secondary)] underline decoration-dotted"
    >
      {children}
    </span>
  );
}

/**
 * Never render an image from model prose (#731).
 *
 * An <img> fetches as soon as it renders: no click needed. A scheme-less,
 * non-TLD or numeric-IP src (`//host/x.png`, `http://3232235777/x`, a bare
 * single-label host) passes defang()'s TLD allowlist and rehype-sanitize's
 * protocol check, so the analyst's browser would request it from wherever the
 * model echoed it, beaconing that this report was opened. Production's CSP
 * (`img-src 'self' data:`) happens to block most of that; the dev server has no
 * CSP, and a same-origin `/api/...` src is not blocked by it at all. Analysis
 * prose has no legitimate images, so none are rendered: the alt text is shown,
 * and the source only as defanged text in a tooltip.
 */
function InertImage({ src, alt }: React.ImgHTMLAttributes<HTMLImageElement>) {
  const source = typeof src === "string" ? src : "";
  return (
    <span
      data-neutralised-image="true"
      title={`Image not loaded: ${defang(source)}`}
      className="text-[var(--color-text-secondary)] italic"
    >
      [image{alt ? `: ${alt}` : ""}]
    </span>
  );
}
