// 统一 API 客户端：错误信封解析、令牌注入、SSE 流解析

import type {
  AgentEvent,
  CodeFile,
  CodeTree,
  HealthInfo,
  LoginResponse,
  SearchHit,
  Task,
  TaskCreateResponse,
  UploadInitResponse,
  User,
} from "./types";

const BASE = "";

export class ApiError extends Error {
  code: string;
  status: number;

  constructor(status: number, code: string, message: string) {
    super(message);
    this.status = status;
    this.code = code;
  }
}

let tokenProvider: () => string | null = () => null;

export function setTokenProvider(provider: () => string | null): void {
  tokenProvider = provider;
}

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const headers = new Headers(init.headers);
  const token = tokenProvider();
  if (token) headers.set("Authorization", `Bearer ${token}`);
  if (init.body && !(init.body instanceof Blob) && typeof init.body !== "string") {
    // JSON body already stringified by callers
  }

  const response = await fetch(BASE + path, { ...init, headers });
  const text = await response.text();
  let payload: unknown = null;
  try {
    payload = text ? JSON.parse(text) : null;
  } catch {
    payload = null;
  }

  if (!response.ok) {
    const body = (payload ?? {}) as { code?: string; message?: string };
    throw new ApiError(
      response.status,
      body.code ?? "HTTP_ERROR",
      body.message ?? `请求失败 (${response.status})`,
    );
  }
  return payload as T;
}

function jsonInit(method: string, body: unknown): RequestInit {
  return {
    method,
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  };
}

// ---------- auth ----------
export const api = {
  register: (username: string, password: string) =>
    request<User>("/api/v1/auth/register", jsonInit("POST", { username, password })),
  login: (username: string, password: string) =>
    request<LoginResponse>("/api/v1/auth/login", jsonInit("POST", { username, password })),
  me: () => request<User>("/api/v1/auth/me"),
  health: () => request<HealthInfo>("/health"),

  // ---------- upload ----------
  uploadInit: (filename: string, totalSize: number, totalChunks: number, sha256: string) =>
    request<UploadInitResponse>(
      "/api/v1/apks/upload/init",
      jsonInit("POST", {
        filename,
        total_size: totalSize,
        total_chunks: totalChunks,
        file_sha256: sha256,
      }),
    ),
  uploadChunk: (uploadId: string, index: number, chunk: Blob) =>
    request<{ upload_id: string; index: number; bytes_stored: number }>(
      `/api/v1/apks/upload/chunk?upload_id=${encodeURIComponent(uploadId)}&index=${index}`,
      { method: "POST", body: chunk },
    ),
  uploadComplete: (uploadId: string, sha256: string) =>
    request<TaskCreateResponse>(
      "/api/v1/apks/upload/complete",
      jsonInit("POST", { upload_id: uploadId, file_sha256: sha256 }),
    ),

  // ---------- tasks ----------
  listTasks: () => request<Task[]>("/api/v1/tasks"),
  getTask: (taskId: string) => request<Task>(`/api/v1/tasks/${taskId}`),
  reportUrl: (taskId: string, format: "md" | "json") => {
    const token = tokenProvider();
    return `/api/v1/tasks/${taskId}/report.${format}${format === "md" ? "" : ""}${
      token ? `?token=${encodeURIComponent(token)}` : ""
    }`;
  },
  downloadReport: async (taskId: string, format: "md" | "json"): Promise<string> => {
    const headers: HeadersInit = { Authorization: `Bearer ${tokenProvider() ?? ""}` };
    const response = await fetch(`/api/v1/tasks/${taskId}/report.${format}`, { headers });
    if (!response.ok) throw new ApiError(response.status, "REPORT_FAILED", "报告导出失败");
    return response.text();
  },
  retryTask: (taskId: string) =>
    request<Task>(`/api/v1/tasks/${taskId}/retry`, { method: "POST" }),

  // ---------- code browser ----------
  codeTree: (taskId: string) => request<CodeTree>(`/api/v1/tasks/${taskId}/code/tree`),
  codeFile: (taskId: string, path: string) =>
    request<CodeFile>(
      `/api/v1/tasks/${taskId}/code/file?path=${encodeURIComponent(path)}`,
    ),
  codeSearch: (taskId: string, keyword: string, regex = false) =>
    request<{ matches: SearchHit[]; total: number }>(
      `/api/v1/tasks/${taskId}/code/search?keyword=${encodeURIComponent(keyword)}&regex=${regex}`,
    ),
  ragSearch: (taskId: string, q: string) =>
    request<{ results: Array<{ chunk: { file: string; start_line: number; class_name: string; method_name: string | null }; score: number }> }>(
      `/api/v1/tasks/${taskId}/rag/search?q=${encodeURIComponent(q)}`,
    ),

  agentMessages: (taskId: string) =>
    request<
      Array<{
        question: string;
        answer: string;
        mode: string;
        created_at: string;
        events: Array<{ type: string; data: Record<string, unknown> }>;
      }>
    >(`/api/v1/tasks/${taskId}/agent/messages`),
};

// ---------- SSE ----------
export async function streamAgent(
  taskId: string,
  question: string,
  onEvent: (event: AgentEvent) => void,
  signal?: AbortSignal,
): Promise<void> {
  const token = tokenProvider();
  const response = await fetch(
    `/api/v1/tasks/${taskId}/agent/stream?q=${encodeURIComponent(question)}`,
    { headers: { Authorization: `Bearer ${token ?? ""}` }, signal },
  );
  if (!response.ok || !response.body) {
    const text = await response.text().catch(() => "");
    let code = "HTTP_ERROR";
    let message = `Agent 请求失败 (${response.status})`;
    try {
      const body = JSON.parse(text) as { code?: string; message?: string };
      code = body.code ?? code;
      message = body.message ?? message;
    } catch {
      /* plain error text */
    }
    throw new ApiError(response.status, code, message);
  }

  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let buffer = "";
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    buffer += decoder.decode(value, { stream: true });
    let sep: number;
    while ((sep = buffer.indexOf("\n\n")) >= 0) {
      const block = buffer.slice(0, sep);
      buffer = buffer.slice(sep + 2);
      const event = parseSseBlock(block);
      if (event) onEvent(event);
    }
  }
}

function parseSseBlock(block: string): AgentEvent | null {
  let type = "";
  let data = "";
  for (const line of block.split("\n")) {
    if (line.startsWith("event: ")) type = line.slice(7).trim();
    else if (line.startsWith("data: ")) data += line.slice(6);
  }
  if (!type) return null;
  const known = [
    "thought", "tool_call", "tool_result", "guardrail_alert", "answer", "error", "done",
  ] as const;
  if (!(known as readonly string[]).includes(type)) return null;
  const eventType = type as (typeof known)[number];
  try {
    return { type: eventType, data: data ? JSON.parse(data) : {} };
  } catch {
    return { type: eventType, data: {} };
  }
}
