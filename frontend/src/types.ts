export type Kind = "root" | "intermediate" | "leaf";

export interface Entity {
  id: string;
  name: string;
  kind: Kind;
  description: string;
  versions: string[];
}

export interface Cert {
  id: string;
  entityId: string;
  version: number;
  serial: string;
  subject: string;
  issuerId?: string;
  isCA: boolean;
  ekus: string[];
  notBefore: string;
  notAfter: string;
  revoked: boolean;
  revokedAt?: string;
  revokeReason?: string;
  crossSignedBy?: string;
  pem: string;
  createdAt: string;
}

export interface RootInfo {
  certId: string;
  entityId: string;
  subject: string;
  version: number;
}

export interface LabState {
  createdAt: string;
  entities: Record<string, Entity>;
  certs: Record<string, Cert>;
  order: string[];
  roots: RootInfo[];
}

export interface PathNode {
  certId: string;
  entityId: string;
  subject: string;
  version: number;
  isRoot: boolean;
  cross: boolean;
  revoked: boolean;
  expired: boolean;
  notBefore: string;
  notAfter: string;
}

export interface PathResult {
  nodes: PathNode[];
  rootCertId: string;
  rootEntityId: string;
  trusted: boolean;
  valid: boolean;
  reasons: string[];
  label: string;
}

export interface VerifyResult {
  leafCertId: string;
  purpose: string;
  at: string;
  valid: boolean;
  chosenPath?: PathResult;
  paths: PathResult[];
}
