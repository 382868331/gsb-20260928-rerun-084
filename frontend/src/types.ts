export type NodeKind = "root" | "intermediate" | "cross" | "leaf";

export interface CertView {
  id: string;
  label: string;
  kind: NodeKind;
  issuerId: string;
  parentId?: string;
  supersededBy?: string;
  ekus: string[];
  subject: string;
  issuer: string;
  serial: string;
  notBefore: string;
  notAfter: string;
  revoked: boolean;
  revokedAt?: string;
  crlBlocked?: boolean;
  pem: string;
}

export interface CheckResult {
  name: string;
  pass: boolean;
  detail: string;
}

export interface PathStep {
  id: string;
  label: string;
  kind: NodeKind;
  subject: string;
  issuer: string;
  notAfter: string;
  expired: boolean;
  revoked: boolean;
  signatureValid: boolean;
  trusted?: boolean;
}

export interface ChainReport {
  path: PathStep[];
  valid: boolean;
  reason?: string;
  checks: CheckResult[];
}

export interface VerifyResult {
  leafId: string;
  purpose: string;
  checkedAt: string;
  valid: boolean;
  reason?: string;
  selectedPath?: string[];
  chains: ChainReport[];
  trustedRoots: string[];
}

export interface Evidence {
  id: string;
  createdAt: string;
  leafId: string;
  leafLabel: string;
  purpose: string;
  valid: boolean;
  note?: string;
  result: VerifyResult;
}
