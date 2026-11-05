import { createContext, useCallback, useContext, useMemo, useRef, useState, type ReactNode } from 'react'
import { apiFetch, ApiError } from '../api/apiFetch'

/*
 * ¿DÓNDE GUARDAR EL TOKEN EN EL NAVEGADOR?
 *
 * 1) En memoria (estado de React)  <- lo que usamos aquí
 *    + Un script malicioso (XSS) no lo encuentra en ningún almacenamiento persistente.
 *    - Se pierde al recargar la página (hay que volver a iniciar sesión).
 *
 * 2) localStorage / sessionStorage
 *    + Sobrevive a recargas, muy fácil de usar.
 *    - Cualquier JavaScript de la página puede leerlo: una vulnerabilidad XSS
 *      o una librería comprometida puede robar el token y usarlo desde otro lado.
 *
 * 3) Cookie HttpOnly + Secure + SameSite (puesta por el servidor)
 *    + JavaScript NO puede leerla: el robo por XSS se vuelve mucho más difícil.
 *    + El navegador la envía sola en cada petición.
 *    - Hay que protegerse de CSRF (SameSite, tokens anti-CSRF) y configurar CORS con credenciales.
 *    Es la opción recomendada en producción (por ejemplo con el patrón BFF).
 *
 * Para la demo usamos memoria: es simple y nos obliga a ver la expiración del token.
 * Tarea: el refresh token tambien se queda en memoria igual que el access token.
 */

interface TokenPair {
  accessToken: string
  refreshToken: string
}

interface AuthContextValue {
  token: string | null
  isAuthenticated: boolean
  login: (accessToken: string, refreshToken: string) => void
  /** Tarea: llama a /api/auth/logout para revocar el refresh token. */
  logout: () => Promise<void>
  /** apiFetch con el token. Si da 401 renueva con el refresh token y reintenta una vez. */
  authFetch: <T>(path: string, init?: RequestInit) => Promise<T>
}

const AuthContext = createContext<AuthContextValue | null>(null)

export function AuthProvider({ children }: { children: ReactNode }) {
  // el estado es para que React vuelva a dibujar (por ejemplo el TokenPanel)
  const [token, setToken] = useState<string | null>(null)

  // uso refs para leer siempre el valor mas nuevo dentro de authFetch
  const accessRef = useRef<string | null>(null)
  const refreshRef = useRef<string | null>(null)

  // si dos peticiones dan 401 al mismo tiempo, que solo se haga UN refresh.
  // si se hicieran dos con el mismo token, el segundo cuenta como reutilizacion
  // y la API revocaria toda la sesion
  const renovandoRef = useRef<Promise<boolean> | null>(null)

  const guardarSesion = useCallback((accessToken: string, refreshToken: string) => {
    accessRef.current = accessToken
    refreshRef.current = refreshToken
    setToken(accessToken)
  }, [])

  const borrarSesion = useCallback(() => {
    accessRef.current = null
    refreshRef.current = null
    setToken(null)
  }, [])

  const logout = useCallback(async () => {
    const refreshToken = refreshRef.current
    borrarSesion()
    if (!refreshToken) return
    try {
      await apiFetch('/api/auth/logout', { method: 'POST', body: JSON.stringify({ refreshToken }) })
    } catch {
      // si la API no responde igual se cierra la sesion en el navegador
    }
  }, [borrarSesion])

  const renovar = useCallback((): Promise<boolean> => {
    if (renovandoRef.current) return renovandoRef.current

    const refreshToken = refreshRef.current
    if (!refreshToken) return Promise.resolve(false)

    renovandoRef.current = apiFetch<TokenPair>('/api/auth/refresh', {
      method: 'POST',
      body: JSON.stringify({ refreshToken }),
    })
      .then((par) => {
        guardarSesion(par.accessToken, par.refreshToken)
        console.log('[auth] access token renovado con /api/auth/refresh')
        return true
      })
      .catch(() => false)
      .finally(() => {
        renovandoRef.current = null
      })

    return renovandoRef.current
  }, [guardarSesion])

  const authFetch = useCallback(
    async <T,>(path: string, init?: RequestInit): Promise<T> => {
      try {
        return await apiFetch<T>(path, init, { token: accessRef.current })
      } catch (err) {
        // solo nos interesa el 401 cuando si mandamos token (vencido)
        if (!(err instanceof ApiError) || err.status !== 401 || !accessRef.current) throw err

        const renovo = await renovar()
        if (!renovo) {
          borrarSesion() // ProtectedRoute nos manda a /login
          throw err
        }

        // reintento UNA sola vez con el token nuevo
        try {
          return await apiFetch<T>(path, init, { token: accessRef.current })
        } catch (err2) {
          if (err2 instanceof ApiError && err2.status === 401) borrarSesion()
          throw err2
        }
      }
    },
    [renovar, borrarSesion],
  )

  const value = useMemo(
    () => ({ token, isAuthenticated: token !== null, login: guardarSesion, logout, authFetch }),
    [token, guardarSesion, logout, authFetch],
  )

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
}

export function useAuth(): AuthContextValue {
  const context = useContext(AuthContext)
  if (!context) throw new Error('useAuth debe usarse dentro de <AuthProvider>')
  return context
}
