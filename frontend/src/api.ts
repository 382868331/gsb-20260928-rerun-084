import type { CertView, Evidence } from "./types";

async function req<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(path, {
    headers: { "Content-Type": "application/json" },
    ...init,
  });
  const body = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error((body as { error?: string }).error || res.statusText);
  return body as T;
}

export const api = {
  list: () => req<{ certs: CertView[]; trustedRoots: string[]; now: string }>("/api/certs"),
  addRoot: (CN: string) => req<CertView>("/api/roots", { method: "POST", body: JSON.stringify({ CN }) }),
  addIntermediate: (CN: string, issuerId: string, crossSubjectId?: string) =>
    req<CertView>("/api/intermediates", {
      method: "POST",
      body: JSON.stringify({ CN, issuerId, crossSubjectId }),
    }),
  addLeaf: (CN: string, issuerId: string, dnsNames: string[]) =>
    req<CertView>("/api/leaves", {
      method: "POST",
      body: JSON.stringify({ CN, issuerId, dnsNames, ekus: ["serverAuth"] }),
    }),
  rotate: (oldId: string) =>
    req<{ new: CertView }>("/api/leaves/rotate", { method: "POST", body: JSON.stringify({ oldId }) }),
  trust: (rootId: string, trust: boolean) =>
    req("/api/trust", { method: "POST", body: JSON.stringify({ rootId, trust }) }),
  revoke: (id: string) => req<CertView>("/api/revoke", { method: "POST", body: JSON.stringify({ id }) }),
  setCRL: (caId: string, published: boolean) =>
    req("/api/crl", { method: "POST", body: JSON.stringify({ caId, published }) }),
  verify: (leafId: string, purpose: string, note: string) =>
    req<Evidence>("/api/verify", { method: "POST", body: JSON.stringify({ leafId, purpose, note }) }),
  evidence: () => req<{ evidence: Evidence[] }>("/api/evidence"),
};
