/**
 * websocket.js — stub (DLS mode, backend-independent)
 *
 * TODO (backend integration): Uncomment the implementation below and remove
 * the stub export. Set VITE_WS_URL in .env to point at the FastAPI WebSocket.
 *
 *   const WS = import.meta.env.VITE_WS_URL || 'ws://localhost:8000/ws/dashboard'
 *
 *   export function connectDashboardSocket({ onData, onStatus }) {
 *     let socket, stopped = false, retry = 1000
 *     const connect = () => {
 *       if (stopped) return
 *       onStatus?.('CONNECTING')
 *       socket = new WebSocket(WS)
 *       socket.onopen  = () => { retry = 1000; onStatus?.('LIVE') }
 *       socket.onmessage = e => { try { onData?.(JSON.parse(e.data)) } catch {} }
 *       socket.onerror = () => socket.close()
 *       socket.onclose = () => {
 *         if (stopped) return
 *         onStatus?.('RECONNECTING')
 *         setTimeout(connect, retry)
 *         retry = Math.min(retry * 2, 8000)
 *       }
 *     }
 *     connect()
 *     return () => { stopped = true; socket?.close() }
 *   }
 */

export function connectDashboardSocket() {
  return () => {}
}
