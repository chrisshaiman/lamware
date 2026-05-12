// Copyright 2026 Christopher Shaiman
// SPDX-License-Identifier: Apache-2.0

import { useLocation } from "react-router-dom";
import { useAlerts } from "#hooks/use-alerts";

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

export function TopBar() {
  const location = useLocation();
  const { data: alerts } = useAlerts();

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
    <header className="flex h-12 items-center justify-between border-b border-[var(--color-border)] bg-[var(--color-surface)] px-6">
      <div className="flex items-center gap-2">
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
          {healthTitle}
        </div>
      </div>
    </header>
  );
}
