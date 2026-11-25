import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { useParams } from "react-router";
import { ApiError, api, setCsrfToken, setUnauthorizedHandler } from "./api";
import type { OrgSummary, SessionPayload } from "./types";

interface AuthState {
  session: SessionPayload | null;
  loading: boolean;
  setSession: (payload: SessionPayload | null) => void;
  refresh: () => Promise<SessionPayload | null>;
  logout: () => Promise<void>;
}

const AuthContext = createContext<AuthState | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [session, setSessionState] = useState<SessionPayload | null>(null);
  const [loading, setLoading] = useState(true);
  const queryClient = useQueryClient();

  const setSession = useCallback((payload: SessionPayload | null) => {
    setCsrfToken(payload?.csrf_token ?? null);
    setSessionState(payload);
  }, []);

  const refresh = useCallback(async () => {
    try {
      const payload = await api.get<SessionPayload>("/auth/session");
      setSession(payload);
      return payload;
    } catch (error) {
      if (error instanceof ApiError && error.status === 401) setSession(null);
      return null;
    } finally {
      setLoading(false);
    }
  }, [setSession]);

  const logout = useCallback(async () => {
    try {
      await api.post("/auth/logout");
    } finally {
      setSession(null);
      queryClient.clear();
    }
  }, [queryClient, setSession]);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  useEffect(() => {
    setUnauthorizedHandler(() => {
      setSession(null);
      queryClient.clear();
    });
    return () => setUnauthorizedHandler(null);
  }, [queryClient, setSession]);

  const value = useMemo(() => ({ session, loading, setSession, refresh, logout }), [session, loading, setSession, refresh, logout]);
  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (!context) throw new Error("useAuth must be used inside AuthProvider");
  return context;
}

/** The organisation addressed by the current URL plus the user's permissions in it. */
export function useOrg(): OrgSummary & { can: (permission: string) => boolean } {
  const { orgId } = useParams();
  const { session } = useAuth();
  const org = session?.organizations.find((item) => item.id === orgId);
  if (!org) throw new Error("Organization not available");
  return { ...org, can: (permission: string) => org.permissions.includes(permission) };
}
