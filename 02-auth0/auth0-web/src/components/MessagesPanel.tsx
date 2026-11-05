import { useAuth0 } from '@auth0/auth0-react'
import { useCallback, useEffect, useState } from 'react'
import { config } from '../config'
import { decodeJwt } from '../lib/jwt'

interface Message {
  id: number
  text: string
  createdBy: string
}

/**
 * Tarea Parte 2: lista de mensajes con boton Eliminar.
 * El boton se oculta si el access token NO trae delete:messages.
 * Ojo: esto es solo para que la pantalla se vea bien, la API es la que
 * de verdad bloquea el DELETE (403) si el usuario no tiene el permiso.
 */
export default function MessagesPanel() {
  const { getAccessTokenSilently } = useAuth0()
  const [messages, setMessages] = useState<Message[]>([])
  const [permissions, setPermissions] = useState<string[]>([])
  const [error, setError] = useState<string | null>(null)
  const [info, setInfo] = useState<string | null>(null)

  const loadMessages = useCallback(async () => {
    setError(null)
    try {
      const token = (await getAccessTokenSilently()) ?? ''

      // leo los permisos del payload del access token
      setPermissions(decodeJwt(token)?.payload.permissions ?? [])

      const response = await fetch(`${config.apiUrl}/api/messages`, {
        headers: { Authorization: `Bearer ${token}` },
      })
      if (!response.ok) {
        setError(`No se pudieron cargar los mensajes (HTTP ${response.status})`)
        return
      }
      setMessages(await response.json())
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    }
  }, [getAccessTokenSilently])

  useEffect(() => {
    loadMessages()
  }, [loadMessages])

  async function deleteMessage(id: number) {
    setError(null)
    setInfo(null)
    const token = (await getAccessTokenSilently()) ?? ''
    const response = await fetch(`${config.apiUrl}/api/messages/${id}`, {
      method: 'DELETE',
      headers: { Authorization: `Bearer ${token}` },
    })

    if (response.ok) {
      setMessages((prev) => prev.filter((m) => m.id !== id))
      setInfo(`Mensaje ${id} eliminado (HTTP ${response.status})`)
    } else {
      setError(`No se pudo eliminar el mensaje ${id} (HTTP ${response.status})`)
    }
  }

  const canDelete = permissions.includes('delete:messages')

  return (
    <section className="card">
      <h2>Mensajes</h2>
      <p className="muted">
        Tus permisos: <code>{JSON.stringify(permissions)}</code>
        {canDelete ? ' · puedes eliminar' : ' · solo lectura'}
      </p>

      {error && <p className="alert error">{error}</p>}
      {info && <p className="alert ok">{info}</p>}

      <table className="claims">
        <tbody>
          {messages.map((m) => (
            <tr key={m.id}>
              <th>#{m.id}</th>
              <td>{m.text}</td>
              <td style={{ width: 1 }}>
                {canDelete && (
                  <button className="secondary" onClick={() => deleteMessage(m.id)}>
                    Eliminar
                  </button>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>

      <div className="actions" style={{ marginTop: '0.75rem' }}>
        <button onClick={loadMessages}>Recargar</button>
      </div>
    </section>
  )
}
