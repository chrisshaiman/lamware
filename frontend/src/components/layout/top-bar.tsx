// Copyright 2026 Christopher Shaiman
// SPDX-License-Identifier: Apache-2.0

import { useLocation } from "react-router-dom";
import { LogOut, Menu } from "lucide-react";
import { useAlerts } from "#hooks/use-alerts";
import { useAuth } from "#contexts/auth-context";

const PAGE_TITLES: Record<string, string> = {
  "/analyses": "Analyses",
  "/iocs": "IOC Browser",
  "/techniques": "MITRE ATT&CK",
  "/stats": "Statistics",
  "/pipeline": "Pipeline Status",
  "/alerts": "Operational Health",
  "/evasions": "Evasion Dashboard",
  "/submit": "Submit Sample",
};

interface TopBarProps {
  onToggleSidebar: () => void;
}

export function TopBar({ onToggleSidebar }: TopBarProps) {
  const location = useLocation();
  const { data: alerts } = useAlerts();
  const { user, roles, logout } = useAuth();

  // Match the longest prefix for nested routes like /analyses/123
  const matchedPath = Object.keys(PAGE_TITLES)
    .sort((a, b) => b.length - a.length)
    .find((path) => location.pathname.startsWith(path));

  const title = matchedPath ? PAGE_TITLES[matchedPath] : "lamware";
  const isDetailView = location.pathname.match(/^\/analyses\/\d+/);

  // Health indicator: green = ok, yellow = paused, red = alert
  let healthColor = "bg-green-500";
  let healthTitle = "All systems operational";
  if (alerts?.paused) {
    healthColor = "bg-yellow-500";
    healthTitle = "Auto-feeder paused";
  }
  if (alerts?.network_monitor) {
    const nm = alerts.network_monitor as Record<string, unknown>;
    if (nm.status === "alert") {
      healthColor = "bg-red-500";
      healthTitle = "Network alert active";
    }
  }

  return (
    <header className="flex h-12 items-center justify-between border-b border-[var(--color-border)] bg-[var(--color-surface)] px-4 md:px-6">
      <div className="flex items-center gap-3">
        <button
          onClick={onToggleSidebar}
          className="rounded-md p-1 text-[var(--color-text-secondary)] hover:bg-[var(--color-surface-hover)] hover:text-[var(--color-text-primary)] md:hidden"
        >
          <Menu className="h-5 w-5" />
        </button>
        <h1 className="text-sm font-semibold text-[var(--color-text-primary)]">
          {isDetailView ? "Analysis Detail" : title}
        </h1>
      </div>
      <div className="flex items-center gap-3">
        <div className="flex items-center gap-2 text-xs text-[var(--color-text-secondary)]">
          <div
            className={`h-2 w-2 rounded-full ${healthColor}`}
            title={healthTitle}
          />
          <span className="hidden sm:inline">{healthTitle}</span>
        </div>
        {user && (
          <div className="flex items-center gap-2 border-l border-[var(--color-border)] pl-3">
            <div className="hidden text-right text-xs sm:block">
              <div className="text-[var(--color-text-primary)]">{user.name}</div>
              <div className="text-[var(--color-text-muted)]">
                {roles.includes("admin") ? "admin" : roles.includes("analyst") ? "analyst" : "viewer"}
              </div>
            </div>
            <button
              onClick={logout}
              title="Sign out"
              className="rounded-md p-1 text-[var(--color-text-secondary)] hover:bg-[var(--color-surface-hover)] hover:text-[var(--color-text-primary)]"
            >
              <LogOut className="h-4 w-4" />
            </button>
          </div>
        )}
      </div>
    </header>
  );
}
