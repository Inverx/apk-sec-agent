<script setup lang="ts">
import { computed, nextTick, onMounted, ref, watch } from "vue";
import { useRoute } from "vue-router";
import { Search } from "lucide-vue-next";
import hljs from "highlight.js/lib/core";
import java from "highlight.js/lib/languages/java";
import xml from "highlight.js/lib/languages/xml";
import { api } from "@/api";
import SeverityBadge from "@/components/SeverityBadge.vue";
import type { CodePackage, Finding, SearchHit } from "@/types";

hljs.registerLanguage("java", java);
hljs.registerLanguage("xml", xml);

const route = useRoute();
const taskId = computed(() => String(route.params.taskId));

const packages = ref<CodePackage[]>([]);
const currentFile = ref<string>("");
const source = ref("");
const totalLines = ref(0);
const loading = ref(false);
const errorText = ref("");
const highlightLine = ref(0);
const sourceContainer = ref<HTMLDivElement | null>(null);

const findings = ref<Finding[]>([]);
const searchKeyword = ref("");
const searchHits = ref<SearchHit[] | null>(null);

const findingsForFile = computed(() =>
  findings.value.filter((f) => f.file === currentFile.value),
);

const expandedPackages = ref<Set<string>>(new Set());

// ---------- 语法高亮：整份源码一次 highlight，按行拆分。
// 用「开标签栈」跨行续接：行首拼接栈中未闭合的完整起始标签（含 class），
// 保证多行注释 / 多行字符串的续行样式完整；闭合用 pop，天然防御多余闭合标签。
let cachedKey = "";
let cachedLines: string[] = [];

function splitHighlighted(text: string, language: string): string[] {
  const cacheKey = `${language}::${text}`;
  if (cacheKey === cachedKey) return cachedLines;

  const result = hljs.highlight(text, { language, ignoreIllegals: true });
  const rawLines = result.value.split("\n");
  const fixed: string[] = [];
  const openTags: string[] = [];

  for (const line of rawLines) {
    const prefix = openTags.join("");
    const tokens = line.match(/<span[^>]*>|<\/span>/g) ?? [];
    for (const token of tokens) {
      if (token === "</span>") {
        openTags.pop(); // 空栈 pop 返回 undefined，天然防御不平衡输出
      } else {
        openTags.push(token);
      }
    }
    // 行尾补齐闭合标签，保证每行 v-html 当行严格闭合；栈保留供下一行续接前缀
    fixed.push(prefix + line + "</span>".repeat(openTags.length));
  }

  cachedKey = cacheKey;
  cachedLines = fixed;
  return fixed;
}

const highlightedLines = computed(() =>
  source.value
    ? splitHighlighted(source.value, currentFile.value.endsWith(".xml") ? "xml" : "java")
    : [],
);

function togglePackage(name: string): void {
  const next = new Set(expandedPackages.value);
  if (next.has(name)) next.delete(name);
  else next.add(name);
  expandedPackages.value = next;
}

async function loadTree(): Promise<void> {
  const tree = await api.codeTree(taskId.value);
  packages.value = tree.packages;
  if (tree.packages.length) expandedPackages.value = new Set([tree.packages[0].name]);
}

async function loadFindings(): Promise<void> {
  const response = await api.getTask(taskId.value);
  findings.value = response.result_json?.findings ?? [];
}

async function openFile(path: string, line = 0): Promise<void> {
  loading.value = true;
  errorText.value = "";
  try {
    const file = await api.codeFile(taskId.value, path);
    currentFile.value = path;
    source.value = file.content;
    totalLines.value = file.total_lines;
    highlightLine.value = line;
    searchHits.value = null;
    await nextTick();
    scrollToLine(line);
  } catch (exc) {
    errorText.value = exc instanceof Error ? exc.message : "加载失败";
  } finally {
    loading.value = false;
  }
}

function scrollToLine(line: number): void {
  if (!line || !sourceContainer.value) return;
  const row = sourceContainer.value.querySelector(`[data-line="${line}"]`);
  row?.scrollIntoView({ block: "center" });
}

async function runSearch(): Promise<void> {
  if (!searchKeyword.value.trim()) return;
  try {
    const response = await api.codeSearch(taskId.value, searchKeyword.value.trim());
    searchHits.value = response.matches;
  } catch {
    searchHits.value = [];
  }
}

onMounted(async () => {
  try {
    await Promise.all([loadTree(), loadFindings()]);
    const queryFile = route.query.file;
    const queryLine = Number(route.query.line ?? 0);
    if (typeof queryFile === "string" && queryFile) {
      await openFile(queryFile, queryLine);
    } else if (packages.value.length) {
      const first = packages.value[0].classes[0];
      if (first) await openFile(first.file);
    }
  } catch (exc) {
    errorText.value = exc instanceof Error ? exc.message : "加载失败";
  }
});

watch(
  () => route.query,
  async (query) => {
    if (route.name !== "code") return;
    if (typeof query.file === "string" && query.file && query.file !== currentFile.value) {
      await openFile(query.file, Number(query.line ?? 0));
    } else if (typeof query.line === "string") {
      highlightLine.value = Number(query.line);
      await nextTick();
      scrollToLine(Number(query.line));
    }
  },
);
</script>

<template>
  <div class="flex h-full min-h-0">
    <!-- 左侧：搜索 + 包/类树 + 本文件风险 -->
    <aside class="flex w-80 shrink-0 flex-col border-r hairline bg-ink-950">
      <div class="border-b hairline p-3">
        <div class="relative">
          <Search class="absolute top-2.5 left-2.5 h-4 w-4 text-paper-3" :stroke-width="1.5" />
          <input
            v-model="searchKeyword"
            placeholder="搜索代码"
            class="h-9 w-full rounded-control bg-ink-800 border hairline pr-3 pl-8 text-sm text-paper placeholder:text-paper-3"
            @keydown.enter="runSearch"
          />
        </div>
      </div>

      <div v-if="searchHits !== null" class="min-h-0 flex-1 overflow-y-auto p-2">
        <div class="mb-2 flex items-center justify-between px-1">
          <span class="num text-xs text-paper-3">{{ searchHits.length }} 个结果</span>
          <button class="text-xs text-paper-3 hover:text-paper" @click="searchHits = null">
            关闭
          </button>
        </div>
        <button
          v-for="(hit, index) in searchHits"
          :key="index"
          class="mb-1 w-full rounded-control px-2 py-1.5 text-left hover:bg-ink-700"
          @click="openFile(hit.file, hit.line)"
        >
          <div class="font-mono text-xs text-accent-dim">{{ hit.class }}:{{ hit.line }}</div>
          <div class="truncate font-mono text-xs text-paper-3">{{ hit.text }}</div>
        </button>
        <p v-if="searchHits.length === 0" class="px-1 text-xs text-paper-3">无匹配结果</p>
      </div>

      <div v-else class="min-h-0 flex-1 overflow-y-auto p-2">
        <div v-for="pkg in packages" :key="pkg.name" class="mb-0.5">
          <button
            class="flex h-8 w-full items-center gap-1 rounded-control px-2 text-left hover:bg-ink-800"
            @click="togglePackage(pkg.name)"
          >
            <span class="num text-xs text-paper-3">{{ pkg.classes.length }}</span>
            <span class="truncate font-mono text-xs text-paper-2">
              {{ pkg.name || "(default)" }}
            </span>
          </button>
          <div v-if="expandedPackages.has(pkg.name)" class="ml-3 border-l hairline pl-2">
            <button
              v-for="node in pkg.classes"
              :key="node.file"
              class="flex h-7 w-full items-center rounded-control px-2 text-left"
              :class="
                currentFile === node.file ? 'bg-ink-700 text-paper' : 'text-paper-2 hover:bg-ink-800'
              "
              @click="openFile(node.file)"
            >
              <span class="truncate font-mono text-xs">{{ node.name }}</span>
            </button>
          </div>
        </div>
      </div>

      <div v-if="findingsForFile.length" class="max-h-56 overflow-y-auto border-t hairline p-3">
        <div class="mb-2 text-xs text-paper-3">本文件风险（{{ findingsForFile.length }}）</div>
        <button
          v-for="finding in findingsForFile"
          :key="finding.id"
          class="mb-1.5 flex w-full items-center gap-2 rounded-control px-2 py-1.5 text-left hover:bg-ink-700"
          @click="openFile(finding.file, finding.line)"
        >
          <span class="font-mono text-xs text-paper-3">{{ finding.id }}</span>
          <SeverityBadge :severity="finding.severity" />
          <span class="truncate text-xs text-paper-3">{{ finding.title }}</span>
        </button>
      </div>
    </aside>

    <!-- 源码视图：对高亮数组 0-based 迭代，行号显示 idx+1（从 1 开始对齐） -->
    <section class="flex min-w-0 flex-1 flex-col">
      <div class="flex h-12 items-center justify-between border-b hairline px-4">
        <span class="truncate font-mono text-xs text-paper-2">
          {{ currentFile || "选择左侧文件" }}
        </span>
        <span class="num text-xs text-paper-3">{{ totalLines }} 行</span>
      </div>

      <div v-if="errorText" class="p-4 text-sm text-sev-critical">{{ errorText }}</div>
      <div v-else-if="loading && !source" class="p-4 text-sm text-paper-3">加载中</div>

      <div v-else ref="sourceContainer" class="min-h-0 flex-1 overflow-auto bg-ink-800">
        <table class="w-full border-collapse font-mono text-xs leading-5">
          <tbody>
            <tr
              v-for="(lineHtml, idx) in highlightedLines"
              :key="idx"
              :data-line="idx + 1"
              class="align-top"
              :class="{ 'bg-[#eff6ff]': highlightLine === idx + 1 }"
            >
              <td
                class="w-12 min-w-12 border-r hairline bg-ink-950 px-2 text-right text-paper-3 select-none"
                :class="{
                  'border-l-2 border-l-accent font-medium text-accent-dim':
                    highlightLine === idx + 1,
                }"
              >
                {{ idx + 1 }}
              </td>
              <td class="pr-4 pl-3">
                <span
                  v-if="findingsForFile.some((f) => f.line === idx + 1)"
                  class="mr-2 inline-block h-1.5 w-1.5 rounded-full bg-sev-high align-middle"
                  :title="findingsForFile.find((f) => f.line === idx + 1)?.title"
                />
                <!-- 内容经 highlight.js 转义，无原始 HTML 注入面 -->
                <span class="code-line whitespace-pre" v-html="lineHtml" />
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </section>
  </div>
</template>

<style>
/* GitHub Light 风格语法高亮（白底深色高亮） */
.code-line .hljs-keyword,
.code-line .hljs-built_in {
  color: #cf222e;
}
.code-line .hljs-string {
  color: #0a3069;
}
.code-line .hljs-comment,
.code-line .hljs-meta {
  color: #6e7781;
  font-style: italic;
}
.code-line .hljs-number,
.code-line .hljs-literal {
  color: #0550ae;
}
.code-line .hljs-title,
.code-line .hljs-title.function_,
.code-line .hljs-name {
  color: #8250df;
}
.code-line .hljs-attr,
.code-line .hljs-attribute {
  color: #0550ae;
}
.code-line .hljs-tag {
  color: #116329;
}
.code-line .hljs-type,
.code-line .hljs-class .hljs-title {
  color: #953800;
}
.code-line .hljs-variable,
.code-line .hljs-params {
  color: #24292f;
}
</style>
