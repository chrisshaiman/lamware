// Copyright 2026 Christopher Shaiman
// SPDX-License-Identifier: Apache-2.0

import type { ReactNode } from "react";
import { useWebSocket } from "#hooks/use-websocket";
import { WebSocketContext } from "#hooks/use-ws-context";

export function WebSocketProvider({ children }: { children: ReactNode }) {
  const status = useWebSocket();
  return (
    <WebSocketContext value={status}>
      {children}
    </WebSocketContext>
  );
}
