// Copyright 2026 Christopher Shaiman
// SPDX-License-Identifier: Apache-2.0

import { NavLink } from "react-router-dom";
import {
  FileSearch,
  Shield,
  Network,
  BarChart3,
  Activity,
  AlertTriangle,
  ShieldAlert,
  Upload,
  X,
} from "lucide-react";
import { cn } from "#lib/utils";
import { SecurityCat } from "./security-cat";

const NAV_ITEMS = [
  { to: "/analyses", label: "Analyses", icon: FileSearch },
  { to: "/iocs", label: "IOCs", icon: Network },
  { to: "/techniques", label: "Techniques", icon: Shield },
  { to: "/stats", label: "Statistics", icon: BarChart3 },
  { to: "/pipeline", label: "Pipeline", icon: Activity },
  { to: "/alerts", label: "Alerts", icon: AlertTriangle },
  { to: "/evasions", label: "Evasions", icon: ShieldAlert },
  { to: "/submit", label: "Submit", icon: Upload },
] as const;

interface SidebarProps {
  open: boolean;
  onClose: () => void;
}

export function Sidebar({ open, onClose }: SidebarProps) {
  return (
    <aside
      className={cn(
        "fixed inset-y-0 left-0 z-30 flex w-56 shrink-0 flex-col border-r border-[var(--color-border)] bg-[var(--color-surface)] transition-transform duration-200 md:static md:translate-x-0",
        open ? "translate-x-0" : "-translate-x-full",
      )}
    >
      {/* Logo */}
      <div className="flex items-center justify-between border-b border-[var(--color-border)] px-4 py-4">
        <div>
          <div className="text-lg font-bold tracking-tight text-[var(--color-text-primary)]">
            lamware
          </div>
          <div className="text-xs text-[var(--color-text-muted)]">
            Malware Analysis Platform
          </div>
        </div>
        <button
          onClick={onClose}
          className="rounded-md p-1 text-[var(--color-text-secondary)] hover:bg-[var(--color-surface-hover)] hover:text-[var(--color-text-primary)] md:hidden"
        >
          <X className="h-5 w-5" />
        </button>
      </div>

      {/* Navigation */}
      <nav className="flex-1 space-y-0.5 px-2 py-3">
        {NAV_ITEMS.map(({ to, label, icon: Icon }) => (
          <NavLink
            key={to}
            to={to}
            className={({ isActive }) =>
              cn(
                "flex items-center gap-2.5 rounded-md px-3 py-2 text-sm font-medium transition-colors",
                isActive
                  ? "bg-[var(--color-surface-hover)] text-[var(--color-text-primary)]"
                  : "text-[var(--color-text-secondary)] hover:bg-[var(--color-surface-hover)] hover:text-[var(--color-text-primary)]",
              )
            }
          >
            <Icon className="h-4 w-4" />
            {label}
          </NavLink>
        ))}
      </nav>

      {/* Security Cat footer */}
      <div className="border-t border-[var(--color-border)] px-4 py-4">
        <SecurityCat />
      </div>
    </aside>
  );
}
