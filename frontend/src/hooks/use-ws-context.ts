// Copyright 2026 Christopher Shaiman
// SPDX-License-Identifier: Apache-2.0
//
// WebSocket status context — provides connection status to any component
// without prop drilling. The hook is mounted once in main.tsx.

import { createContext, useContext } from "react";
import type { WebSocketStatus } from "#hooks/use-websocket";

const defaultStatus: WebSocketStatus = { isConnected: false, isReconnecting: false };

export const WebSocketContext = createContext<WebSocketStatus>(defaultStatus);

export function useWsStatus(): WebSocketStatus {
  return useContext(WebSocketContext);
}
