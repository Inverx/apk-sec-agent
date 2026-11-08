<script setup lang="ts">
import { computed, nextTick, onMounted, ref } from "vue";
import { useRoute } from "vue-router";
import { Send, Square } from "lucide-vue-next";
import { api, streamAgent } from "@/api";
import { renderMarkdown } from "@/markdown";
import { useAuthStore } from "@/stores/auth";
import type { AgentEvent } from "@/types";

const route = useRoute();
const auth = useAuthStore();

const taskId = computed(() => String(route.params.taskId));

interface ChatEntry {
  question: string;
  events: AgentEvent[];
  answer: string;
  running: boolean;
}

const chats = ref<ChatEntry[]>([]);
const question = ref("");
const streaming = ref(false);
const timelineEl = ref<HTMLDivElement | null>(null);
let controller: AbortController | null = null;

const shortcuts = [
  "定位登录请求的签名与加密逻辑",
  "检查是否存在 Prompt 注入风险",
  "给出这个应用的风险概览",
];

const quickQuestions = computed(() =>
  auth.canAnalyze ? shortcuts : [],
);

async function send(preset?: string): Promise<void> {
  const q = (preset ?? question.value).trim();
  if (!q || streaming.value) return;
  question.value = "";
  streaming.value = true;

  const entry: ChatEntry = { question: q, events: [], answer: "", running: true };
  chats.value.push(entry);
  await nextTick();
  scrollBottom();

  controller = new AbortController();
  try {
    await streamAgent(
      taskId.value,
      q,
      (event) => {
        entry.events.push(event);
        if (event.type === "answer") {
          entry.answer = String(event.data.text ?? "");
        }
        scrollBottom();
      },
      controller.signal,
    );
  } catch (exc) {
    if (!controller.signal.aborted) {
      entry.events.push({ type: "error", data: { message: String(exc) } });
    }
  } finally {
    entry.running = false;
    streaming.value = false;
    controller = null;
    scrollBottom();
  }
}

function stop(): void {
  controller?.abort();
}

async function loadHistory(): Promise<void> {
  const history = await api.agentMessages(taskId.value);
  for (const item of history.slice().reverse()) {
    chats.value.push({
      question: item.question,
      // 还原历史事件流：刷新后仍可查看思考 / MCP 工具调用 / 安全校验提示时间线
      events: (item.events ?? []) as AgentEvent[],
      answer: item.answer,
      running: false,
    });
  }
}

function scrollBottom(): void {
  timelineEl.value?.scrollTo({ top: timelineEl.value.scrollHeight });
}

function toolArgPreview(event: AgentEvent): string {
  const args = event.data.arguments as Record<string, unknown> | undefined;
  if (!args) return "";
  return Object.entries(args)
    .map(([key, value]) => `${key}=${String(value).slice(0, 80)}`)
    .join(", ")
    .slice(0, 160);
}

function toolResultPreview(event: AgentEvent): string {
  return JSON.stringify(event.data.result ?? {}, null, 1).slice(0, 600);
}

function guardrailMessage(event: AgentEvent): string {
  if (typeof event.data.message === "string") return event.data.message;
  if (Array.isArray(event.data.issues)) return `输出校验: ${(event.data.issues as string[]).join("、")}`;
  return "安全校验提示";
}

onMounted(() => {
  // 历史对话对所有角色只读可见；提问能力由输入区禁用控制
  void loadHistory();
});
</script>

<template>
  <div class="flex h-full min-h-0">
    <div class="mx-auto flex w-full max-w-240 min-h-0 flex-col p-6">
      <header class="mb-4">
        <h1 class="text-xl font-medium text-paper">AI 分析</h1>
        <p class="text-sm text-paper-3">
          结合反编译源码、调用链与 Manifest 信息进行安全审计问答
        </p>
      </header>

      <div v-if="!auth.canAnalyze" class="card mb-4 px-4 py-3 text-sm text-paper-2">
        当前账号为只读权限，仅可查看历史审计记录
      </div>

      <div ref="timelineEl" class="min-h-0 flex-1 overflow-y-auto pr-1">
        <div v-if="chats.length === 0 && auth.canAnalyze" class="card p-6">
          <p class="mb-3 text-sm text-paper-2">常见审计问题</p>
          <div class="flex flex-col items-start gap-2">
            <button
              v-for="item in quickQuestions"
              :key="item"
              class="h-8 rounded-control border hairline bg-ink-800 px-3 text-sm text-paper-2 hover:bg-ink-700 hover:text-paper"
              @click="send(item)"
            >
              {{ item }}
            </button>
          </div>
        </div>

          <div v-for="(chat, chatIndex) in chats" :key="chatIndex" class="mb-6">
            <!-- 问题 -->
            <div class="mb-3 flex justify-end">
              <div class="max-w-120 rounded-card bg-ink-700 px-3.5 py-2 text-sm text-paper">
                {{ chat.question }}
              </div>
            </div>

            <!-- 事件时间线 -->
            <div class="mb-2 flex flex-col gap-1.5">
              <template v-for="(event, eventIndex) in chat.events" :key="eventIndex">
                <div
                  v-if="event.type === 'thought'"
                  class="flex items-start gap-2 text-sm text-paper-3"
                >
                  <span class="mt-1.5 h-1 w-1 shrink-0 rounded-full bg-paper-3" />
                  <span>{{ event.data.text }}</span>
                </div>

                <div
                  v-else-if="event.type === 'tool_call'"
                  class="flex flex-wrap items-center gap-2"
                >
                  <span class="rounded-control bg-ink-800 px-2 py-0.5 font-mono text-xs text-accent">
                    {{ event.data.tool }}
                  </span>
                  <span class="truncate font-mono text-xs text-paper-3">
                    {{ toolArgPreview(event) }}
                  </span>
                </div>

                <details
                  v-else-if="event.type === 'tool_result'"
                  class="rounded-control border hairline bg-ink-950/60"
                >
                  <summary class="cursor-pointer px-2.5 py-1 font-mono text-xs text-paper-3">
                    {{ event.data.tool }} 返回
                  </summary>
                  <pre class="overflow-x-auto px-2.5 pb-2 font-mono text-xs text-paper-3">{{ toolResultPreview(event) }}</pre>
                </details>

                <div
                  v-else-if="event.type === 'guardrail_alert'"
                  class="rounded-control border-l-2 border-sev-medium bg-ink-800 px-3 py-2 text-sm text-paper-2"
                >
                  <span class="mr-2 font-medium text-sev-medium">边界隔离</span>{{ guardrailMessage(event) }}
                </div>

                <div v-else-if="event.type === 'error'" class="text-sm text-sev-critical">
                  {{ event.data.message }}
                </div>
              </template>

              <div v-if="chat.running" class="text-sm text-paper-3">分析中…</div>
            </div>

            <!-- 结论 -->
            <div
              v-if="chat.answer"
              class="card markdown px-4 py-3"
              v-html="renderMarkdown(chat.answer)"
            />
          </div>
        </div>

        <!-- 输入区（viewer 只读：禁用输入与发送） -->
        <div v-if="auth.canAnalyze" class="mt-4 flex items-center gap-2">
          <input
            v-model="question"
            :disabled="streaming"
            placeholder="例如：登录接口的 token 是如何生成的"
            class="h-10 flex-1 rounded-control bg-ink-800 border hairline px-3.5 text-sm text-paper placeholder:text-paper-3"
            @keydown.enter="send()"
          />
          <button
            v-if="!streaming"
            class="flex h-10 w-10 items-center justify-center rounded-control bg-paper text-ink-950 hover:opacity-90"
            title="发送"
            @click="send()"
          >
            <Send class="h-4 w-4" :stroke-width="1.5" />
          </button>
          <button
            v-else
            class="flex h-10 w-10 items-center justify-center rounded-control border hairline text-paper-2 hover:bg-ink-700"
            title="停止"
            @click="stop"
          >
            <Square class="h-4 w-4" :stroke-width="1.5" />
          </button>
        </div>
    </div>
  </div>
</template>

<style>
.markdown .md-h1,
.markdown .md-h2,
.markdown .md-h3,
.markdown .md-h4 {
  color: var(--color-paper);
  font-weight: 500;
  margin: 8px 0 4px;
}
.markdown .md-h1 { font-size: 16px; }
.markdown .md-h2 { font-size: 15px; }
.markdown .md-h3 { font-size: 14px; }
.markdown .md-p { color: var(--color-paper-2); margin: 2px 0; }
.markdown .md-gap { height: 6px; }
.markdown .md-code {
  font-family: var(--font-mono);
  font-size: 12px;
  background: var(--color-ink-900);
  border: 1px solid #e2e8f0;
  border-radius: 4px;
  padding: 1px 5px;
  color: var(--color-accent-dim);
}
.markdown .md-pre {
  font-family: var(--font-mono);
  font-size: 12px;
  background: var(--color-ink-900);
  border: 1px solid #e2e8f0;
  border-radius: 8px;
  padding: 10px;
  overflow-x: auto;
  color: var(--color-paper-2);
  margin: 6px 0;
}
.markdown .md-table {
  width: 100%;
  border-collapse: collapse;
  margin: 8px 0;
  font-size: 12px;
}
.markdown .md-table th,
.markdown .md-table td {
  border-bottom: 1px solid #e2e8f0;
  padding: 5px 8px;
  text-align: left;
  color: var(--color-paper-2);
}
.markdown .md-table th {
  color: var(--color-paper-3);
  font-weight: 400;
}
.markdown .md-li {
  color: var(--color-paper-2);
  padding-left: 14px;
  position: relative;
  margin: 2px 0;
}
.markdown .md-li::before {
  content: "·";
  position: absolute;
  left: 4px;
  color: var(--color-paper-3);
}
.markdown .md-hr {
  border: none;
  border-top: 1px solid #e2e8f0;
  margin: 10px 0;
}
</style>
