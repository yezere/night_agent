import { useEffect, useRef, useState, useCallback } from "react"

interface WsMessage {
  kind: string
  payload?: unknown
  timestamp: number
  source: string
}

interface UseWebSocketReturn {
  connected: boolean
  lastMessage: WsMessage | null
  messages: WsMessage[]
  clearMessages: () => void
  replaceMessages: (messages: WsMessage[]) => void
}

export function useWebSocket(url: string): UseWebSocketReturn {
  const [connected, setConnected] = useState(false)
  const [lastMessage, setLastMessage] = useState<WsMessage | null>(null)
  const [messages, setMessages] = useState<WsMessage[]>([])
  const wsRef = useRef<WebSocket | null>(null)
  const retryRef = useRef(0)
  const retryTimerRef = useRef<number | null>(null)

  useEffect(() => {
    let stopped = false

    function scheduleReconnect(): void {
      if (stopped) return
      const delay = Math.min(15_000, 500 * 2 ** retryRef.current)
      retryRef.current += 1
      retryTimerRef.current = window.setTimeout(connect, delay)
    }

    function connect(): void {
      if (stopped) return
      const ws = new WebSocket(url)
      wsRef.current = ws

      ws.onopen = () => {
        retryRef.current = 0
        setConnected(true)
      }
      ws.onclose = () => {
        if (wsRef.current === ws) wsRef.current = null
        setConnected(false)
        scheduleReconnect()
      }
      ws.onerror = () => {
        setConnected(false)
        ws.close()
      }

      ws.onmessage = (event) => {
        try {
          const msg: WsMessage = JSON.parse(event.data)
          setLastMessage(msg)
          setMessages((prev) => {
            const next = [...prev, msg]
            return next.length > 500 ? next.slice(-300) : next
          })
        } catch {
          // ignore parse errors
        }
      }
    }

    connect()

    return () => {
      stopped = true
      if (retryTimerRef.current != null) window.clearTimeout(retryTimerRef.current)
      wsRef.current?.close()
      wsRef.current = null
    }
  }, [url])

  const clearMessages = useCallback(() => setMessages([]), [])
  const replaceMessages = useCallback((nextMessages: WsMessage[]) => {
    setMessages(nextMessages.slice(-300))
    setLastMessage(nextMessages.at(-1) ?? null)
  }, [])

  return { connected, lastMessage, messages, clearMessages, replaceMessages }
}
