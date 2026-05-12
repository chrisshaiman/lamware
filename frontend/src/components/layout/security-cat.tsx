// Copyright 2026 Christopher Shaiman
// SPDX-License-Identifier: Apache-2.0
//
// Security cat — the lamware mascot. Lives in the sidebar footer.
// Mood states driven by platform health. Turns orange on hover.

import { useAlerts } from "#hooks/use-alerts";
import { usePipelineStatus } from "#hooks/use-pipeline";

type CatMood = "watching" | "analyzing" | "alarmed" | "napping" | "pleased";

interface MoodConfig {
  face: string;
  label: string;
  colorClass: string;
}

const MOODS: Record<CatMood, MoodConfig> = {
  watching:  { face: "( o.o )", label: "security cat is watching",     colorClass: "text-[#8b949e]" },
  analyzing: { face: "( o.O )", label: "security cat is analyzing...", colorClass: "text-[#8b949e] animate-pulse" },
  alarmed:   { face: "( >_< )", label: "security cat is alarmed!",    colorClass: "text-[#f85149]" },
  napping:   { face: "( -.- )", label: "security cat is napping",     colorClass: "text-[#484f58]" },
  pleased:   { face: "( ^.^ )", label: "security cat is pleased",     colorClass: "text-[#8b949e]" },
};

function useCatMood(): CatMood {
  const { data: alerts } = useAlerts();
  const { data: pipeline } = usePipelineStatus();

  // Alert/breach state takes priority
  if (alerts?.network_monitor) {
    const nm = alerts.network_monitor as Record<string, unknown>;
    if (nm.status === "alert" || nm.qemu_status === "alert") {
      return "alarmed";
    }
  }

  // Currently analyzing
  if (pipeline?.running && pipeline.running.length > 0) {
    return "analyzing";
  }

  // Paused / feeder off
  if (alerts?.paused) {
    return "napping";
  }

  // All clear — no high/critical in recent completions
  if (pipeline?.recent_completed) {
    const hasHighSeverity = pipeline.recent_completed.some(
      (a) => a.severity === "critical" || a.severity === "high",
    );
    if (!hasHighSeverity && pipeline.recent_completed.length > 0) {
      return "pleased";
    }
  }

  return "watching";
}

export function SecurityCat() {
  const mood = useCatMood();
  const config = MOODS[mood];

  return (
    <div
      className="select-none text-center"
      title="Security cat is watching your malware"
    >
      <pre
        className={`inline-block font-mono text-sm leading-tight transition-colors duration-300 hover:text-[#f0883e] cursor-default ${config.colorClass}`}
      >
        {`  /\\_/\\
 ${config.face}
  > ^ <`}
      </pre>
      <div className="mt-1 text-[11px] text-[#484f58]">{config.label}</div>
    </div>
  );
}
