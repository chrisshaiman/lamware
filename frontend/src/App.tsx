// Copyright 2026 Christopher Shaiman
// SPDX-License-Identifier: Apache-2.0

import { Routes, Route, Navigate } from "react-router-dom";
import { AppShell } from "#components/layout/app-shell";
import { AnalysesPage } from "#pages/analyses/analyses-page";
import { AnalysisDetailPage } from "#pages/analysis-detail/analysis-detail-page";
import { IocsPage } from "#pages/iocs/iocs-page";
import { TechniquesPage } from "#pages/techniques/techniques-page";
import { StatsPage } from "#pages/stats/stats-page";
import { PipelinePage } from "#pages/pipeline/pipeline-page";
import { AlertsPage } from "#pages/alerts/alerts-page";
import { EvasionsPage } from "#pages/evasions/evasions-page";
import { SubmitPage } from "#pages/submit/submit-page";

export default function App() {
  return (
    <Routes>
      <Route element={<AppShell />}>
        <Route index element={<Navigate to="/analyses" replace />} />
        <Route path="/analyses" element={<AnalysesPage />} />
        <Route path="/analyses/:id" element={<AnalysisDetailPage />} />
        <Route path="/iocs" element={<IocsPage />} />
        <Route path="/techniques" element={<TechniquesPage />} />
        <Route path="/stats" element={<StatsPage />} />
        <Route path="/pipeline" element={<PipelinePage />} />
        <Route path="/alerts" element={<AlertsPage />} />
        <Route path="/evasions" element={<EvasionsPage />} />
        <Route path="/submit" element={<SubmitPage />} />
      </Route>
    </Routes>
  );
}
