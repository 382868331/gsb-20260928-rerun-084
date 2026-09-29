import type { LabState, VerifyResult } from "./types";

async function post<T>(path: string, body: unknown): Promise<T> {
  const res = await fetch(path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body ?? {}),
  });
  const data = await res.json();
  if (!res.ok) throw new Error(data.error ?? "request failed");
  return data as T;
}

export const api = {
  state: () => fetch("/api/state").then((r) => r.json() as Promise<LabState>),
  bootstrap: () => post<LabState>("/api/bootstrap", {}),
  reset: () => post<LabState>("/api/reset", {}),
  issue: (body: {
    name: string;
    kind: "root" | "intermediate" | "leaf";
    issuerId?: string;
    ekus?: string[];
    description?: string;
    ttlDays?: number;
  }) => post<{ cert: unknown }>("/api/issue", body),
  crossSign: (targetCertId: string, signerRootId: string) =>
    post<{ cert: unknown }>("/api/cross-sign", { targetCertId, signerRootId }),
  revoke: (certId: string, reason: string) =>
    post<{ cert: unknown }>("/api/revoke", { certId, reason }),
  verify: (body: { leafCertId: string; purpose: string; trustRoots: string[]; atDays?: number }) =>
    post<VerifyResult>("/api/verify", body),
};
