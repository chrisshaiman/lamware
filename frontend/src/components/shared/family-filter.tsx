// Copyright 2026 Christopher Shaiman
// SPDX-License-Identifier: Apache-2.0

import * as Select from "@radix-ui/react-select";
import { ChevronDown, Check } from "lucide-react";
import { useFamiliesList } from "#hooks/use-families";
import { cn } from "#lib/utils";

interface FamilyFilterProps {
  /** Current value — "all" means no filter active. */
  value: string;
  onChange: (val: string) => void;
}

/**
 * Dropdown filter for malware family. Fetches the families list from the
 * API and renders a Radix Select. Parent should treat "all" as no-filter.
 */
export function FamilyFilter({ value, onChange }: FamilyFilterProps) {
  const { data: families } = useFamiliesList({ limit: 200 });

  return (
    <Select.Root value={value} onValueChange={onChange}>
      <Select.Trigger
        className={cn(
          "inline-flex items-center justify-between gap-2 rounded-md border border-border",
          "bg-background px-3 py-1.5 text-sm text-foreground",
          "hover:bg-muted focus:outline-none focus:ring-2 focus:ring-ring",
          "min-w-[180px]",
        )}
      >
        <Select.Value placeholder="All families" />
        <Select.Icon>
          <ChevronDown className="h-4 w-4 opacity-50" />
        </Select.Icon>
      </Select.Trigger>

      <Select.Portal>
        <Select.Content
          className={cn(
            "z-50 overflow-hidden rounded-md border border-border bg-popover shadow-md",
            "animate-in fade-in-0 zoom-in-95",
          )}
          position="popper"
          sideOffset={4}
        >
          <Select.Viewport className="p-1 max-h-60">
            <SelectItem value="all">All families</SelectItem>
            {families?.map((f) => (
              <SelectItem key={f.family} value={f.family}>
                {f.family} ({f.count})
              </SelectItem>
            ))}
          </Select.Viewport>
        </Select.Content>
      </Select.Portal>
    </Select.Root>
  );
}

/** Styled select item matching the project's dark theme. */
function SelectItem({
  children,
  value,
}: {
  children: React.ReactNode;
  value: string;
}) {
  return (
    <Select.Item
      value={value}
      className={cn(
        "relative flex cursor-pointer select-none items-center rounded-sm",
        "px-2 py-1.5 pl-8 text-sm text-popover-foreground outline-none",
        "data-[highlighted]:bg-accent data-[highlighted]:text-accent-foreground",
      )}
    >
      <Select.ItemIndicator className="absolute left-2 inline-flex items-center">
        <Check className="h-4 w-4" />
      </Select.ItemIndicator>
      <Select.ItemText>{children}</Select.ItemText>
    </Select.Item>
  );
}
