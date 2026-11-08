// API 类型定义（与后端 Pydantic schema 对应）

export type Role = "admin" | "analyst" | "viewer";

export interface User {
  id: string;
  username: string;
  role: Role;
  is_active: boolean;
  created_at: string;
}

export interface LoginResponse {
  access_token: string;
  token_type: string;
  user: User;
}

export interface UploadInitResponse {
  upload_id: string;
  chunk_size: number;
  instant: boolean;
  apk_id: string | null;
  task_id: string | null;
  reused_task: boolean;
}

export interface Apk {
  id: string;
  sha256: string;
  filename: string;
  size: number;
  created_at: string;
}

export type TaskStatus =
  | "PENDING"
  | "DECOMPILING"
  | "SCANNING"
  | "INDEXING"
  | "COMPLETED"
  | "FAILED";

export interface Finding {
  id: string;
  rule_id: string;
  category: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
  cwe: string | null;
  title: string;
  description: string;
  file: string;
  line: number;
  snippet: string;
  suggestion: string;
}

export interface ManifestComponent {
  type: string;
  name: string;
  exported: boolean;
  exported_attr: boolean | null;
  permission: string | null;
  intent_actions: string[];
  intent_categories: string[];
}

export interface ManifestInfo {
  package: string;
  version_name: string;
  application_class: string;
  debuggable: boolean;
  allow_backup: boolean;
  uses_cleartext_traffic: boolean;
  permissions: string[];
  components: ManifestComponent[];
  main_activity: string;
  exported_components: ManifestComponent[];
}

export interface PackerHit {
  name: string;
  confidence: string;
  evidence: string[];
}

export interface TaskResult {
  decompile?: { engine: string; source_files: number; manifest_found: boolean };
  summary: {
    total: number;
    by_severity: Record<string, number>;
    by_category: Record<string, number>;
  };
  scanned_files: number;
  manifest: ManifestInfo | null;
  packers: PackerHit[];
  index?: { chunks: number; mode: string };
  findings: Finding[];
}

export interface Task {
  id: string;
  apk_id: string;
  status: TaskStatus;
  error: string | null;
  retries: number;
  duration_ms: number | null;
  result_json: TaskResult | null;
  apk?: Apk | null;
  created_at: string;
  updated_at: string;
  started_at: string | null;
  finished_at: string | null;
}

export interface TaskCreateResponse {
  apk: Apk;
  task: Task;
  reused: boolean;
}

export interface CodeClass {
  name: string;
  file: string;
}

export interface CodePackage {
  name: string;
  classes: CodeClass[];
}

export interface CodeTree {
  packages: CodePackage[];
  total_packages: number;
  total_classes: number;
}

export interface CodeFile {
  path: string;
  total_lines: number;
  content: string;
}

export interface SearchHit {
  file: string;
  line: number;
  text: string;
  package: string;
  class: string;
}

export interface AgentEvent {
  type: "thought" | "tool_call" | "tool_result" | "guardrail_alert" | "answer" | "error" | "done";
  data: Record<string, unknown>;
}

export interface HealthInfo {
  status: string;
  app: string;
  version: string;
  database: string;
  worker: string;
  queue_depth: number;
  llm: string;
}
