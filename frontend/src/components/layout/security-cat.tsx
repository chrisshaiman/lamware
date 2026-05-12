// Copyright 2026 Christopher Shaiman
// SPDX-License-Identifier: Apache-2.0
//
// Security cat — the lamware mascot. Lives in the sidebar footer.
// Mood states driven by platform health. Turns orange on hover.
// Click for analysis facts. Konami code for easter egg.

import { useState, useEffect, useCallback } from "react";
import { useAlerts } from "#hooks/use-alerts";
import { usePipelineStatus } from "#hooks/use-pipeline";
import { useStats } from "#hooks/use-stats";

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

const SECURITY_TIPS = [
  "Always detonate in an isolated environment.",
  "Check IOC overlaps across samples for campaign tracking.",
  "High entropy often means packed or encrypted payloads.",
  "MITRE ATT&CK mapping helps prioritize detections.",
  "Memory forensics catches what disk analysis misses.",
  "Dynamic analysis reveals runtime behavior static can't see.",
  "Cross-correlate DNS queries with known C2 infrastructure.",
  "Review evasion findings to harden your sandbox.",
];

function useCatMood(): CatMood {
  const { data: alerts } = useAlerts();
  const { data: pipeline } = usePipelineStatus();

  if (alerts?.network_monitor) {
    const nm = alerts.network_monitor as Record<string, unknown>;
    if (nm.status === "alert" || nm.qemu_status === "alert") {
      return "alarmed";
    }
  }

  if (pipeline?.running && pipeline.running.length > 0) {
    return "analyzing";
  }

  if (alerts?.paused) {
    return "napping";
  }

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

function useCatFact(): string {
  const { data: stats } = useStats();

  if (stats) {
    const facts = [
      `Security cat has watched ${stats.total_analyses} analyses.`,
      `${stats.total_iocs.toLocaleString()} IOCs catalogued so far.`,
      `${stats.total_techniques} MITRE techniques observed.`,
      `${stats.families_detected} malware families identified.`,
      `${stats.analyses_today} analyses today, ${stats.analyses_week} this week.`,
    ];
    return facts[Math.floor(Math.random() * facts.length)];
  }

  return SECURITY_TIPS[Math.floor(Math.random() * SECURITY_TIPS.length)];
}

// Konami code: up up down down left right left right b a
const KONAMI = [
  "ArrowUp", "ArrowUp", "ArrowDown", "ArrowDown",
  "ArrowLeft", "ArrowRight", "ArrowLeft", "ArrowRight",
  "b", "a",
];

function useKonamiCode(onActivate: () => void) {
  const [index, setIndex] = useState(0);

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === KONAMI[index]) {
        const next = index + 1;
        if (next === KONAMI.length) {
          onActivate();
          setIndex(0);
        } else {
          setIndex(next);
        }
      } else {
        setIndex(0);
      }
    };

    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [index, onActivate]);
}

const BIG_CAT = `
    /\\_____/\\
   /  o   o  \\
  ( ==  ^  == )
   )         (
  (           )
 ( (  )   (  ) )
(__(__)___(__)__)
`;

export function SecurityCat() {
  const mood = useCatMood();
  const config = MOODS[mood];
  const [showPopover, setShowPopover] = useState(false);
  const [showEasterEgg, setShowEasterEgg] = useState(false);
  const fact = useCatFact();

  const handleKonami = useCallback(() => {
    setShowEasterEgg(true);
    setTimeout(() => setShowEasterEgg(false), 3000);
  }, []);

  useKonamiCode(handleKonami);

  return (
    <>
      {/* Easter egg overlay */}
      {showEasterEgg && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-[#0d1117]/90 transition-opacity">
          <pre className="text-4xl leading-tight text-[#f0883e] animate-bounce font-mono">
            {BIG_CAT}
          </pre>
          <div className="absolute bottom-20 text-center text-sm text-[#8b949e]">
            security cat approves
          </div>
        </div>
      )}

      {/* Cat */}
      <div className="relative select-none text-center">
        <button
          onClick={() => setShowPopover(!showPopover)}
          className="focus:outline-none"
          data-testid="security-cat"
          title="Security cat is watching your malware"
        >
          <pre
            className={`inline-block font-mono text-sm leading-tight transition-colors duration-300 hover:text-[#f0883e] cursor-pointer ${config.colorClass}`}
          >
            {`  /\\_/\\
 ${config.face}
  > ^ <`}
          </pre>
        </button>
        <div className="mt-1 text-[11px] text-[#484f58]">{config.label}</div>

        {/* Click popover */}
        {showPopover && (
          <div className="absolute bottom-full left-1/2 mb-2 w-48 -translate-x-1/2 rounded-md border border-[var(--color-border)] bg-[var(--color-surface)] p-3 text-xs text-[var(--color-text-secondary)] shadow-lg">
            <div className="absolute bottom-0 left-1/2 -mb-1.5 h-3 w-3 -translate-x-1/2 rotate-45 border-b border-r border-[var(--color-border)] bg-[var(--color-surface)]" />
            {fact}
          </div>
        )}
      </div>
    </>
  );
}
