<script setup lang="ts">
import { computed, nextTick, onBeforeUnmount, onMounted, ref, watch } from "vue";
import { useRoute, useRouter } from "vue-router";
import * as echarts from "echarts/core";
import { BarChart } from "echarts/charts";
import { GridComponent, LegendComponent, TooltipComponent } from "echarts/components";
import { CanvasRenderer } from "echarts/renderers";
import { Download } from "lucide-vue-next";
import { api } from "@/api";
import { useAuthStore } from "@/stores/auth";
import RiskTable from "@/components/RiskTable.vue";
import StatusDot from "@/components/StatusDot.vue";
import type { Finding, Task } from "@/types";

echarts.use([BarChart, GridComponent, LegendComponent, TooltipComponent, CanvasRenderer]);

const route = useRoute();
const router = useRouter();
const auth = useAuthStore();

const taskId = computed(() => String(route.params.taskId));
const task = ref<Task | null>(null);
const loading = ref(true);
const errorText = ref("");

const authCanRetry = computed(
  () => task.value?.status === "FAILED" && auth.role === "admin",
);

async function retryTask(): Promise<void> {
  try {
    await api.retryTask(taskId.value);
    await load();
  } catch (exc) {
    errorText.value = exc instanceof Error ? exc.message : "重试失败";
  }
}
const mainChart = ref<HTMLDivElement | null>(null);
const cweChart = ref<HTMLDivElement | null>(null);
let mainInstance: echarts.ECharts | null = null;
let cweInstance: echarts.ECharts | null = null;
let pollTimer: number | null = null;

// 图表浅色主题常量（白底可读）
const AXIS_LABEL = "#475569";
const AXIS_LINE = "#cbd5e1";
const SPLIT_LINE = "#e2e8f0";
const NEUTRAL_BAR = "#94a3b8";
const ACCENT_BAR = "#0d9488";
const MONO_FONT = "JetBrains Mono, Consolas, monospace";

const SEVERITY_META = [
  { key: "CRITICAL", color: "#dc2626" },
  { key: "HIGH", color: "#ea580c" },
  { key: "MEDIUM", color: "#b45309" },
  { key: "LOW", color: "#16a34a" },
] as const;

const findings = computed<Finding[]>(() => task.value?.result_json?.findings ?? []);
const summary = computed(() => task.value?.result_json?.summary);
const manifest = computed(() => task.value?.result_json?.manifest ?? null);
const packers = computed(() => task.value?.result_json?.packers ?? []);

const severityCounts = computed(() => {
  const by = summary.value?.by_severity ?? {};
  return SEVERITY_META.map((meta) => ({ ...meta, value: by[meta.key] ?? 0 }));
});

// 主图：类别 × 严重度堆叠矩阵
const categoryStack = computed(() => {
  const counter = new Map<string, Map<string, number>>();
  for (const f of findings.value) {
    let bySeverity = counter.get(f.category);
    if (!bySeverity) {
      bySeverity = new Map();
      counter.set(f.category, bySeverity);
    }
    bySeverity.set(f.severity, (bySeverity.get(f.severity) ?? 0) + 1);
  }
  const categories = Array.from(counter.keys()).sort(
    (a, b) =>
      (summary.value?.by_category?.[b] ?? 0) - (summary.value?.by_category?.[a] ?? 0),
  );
  return { categories, counter };
});

const cweTop = computed(() => {
  const counter = new Map<string, number>();
  for (const f of findings.value) {
    const key = f.cwe ?? "N/A";
    counter.set(key, (counter.get(key) ?? 0) + 1);
  }
  return Array.from(counter.entries())
    .sort((a, b) => b[1] - a[1])
    .slice(0, 6);
});

const categoryShare = computed(() => {
  const by = summary.value?.by_category ?? {};
  const total = Object.values(by).reduce((sum, n) => sum + n, 0) || 1;
  return Object.entries(by)
    .sort((a, b) => b[1] - a[1])
    .map(([name, count]) => ({ name, count, pct: Math.round((count / total) * 100) }));
});

async function load(): Promise<void> {
  loading.value = true;
  errorText.value = "";
  try {
    task.value = await api.getTask(taskId.value);
  } catch (exc) {
    errorText.value = exc instanceof Error ? exc.message : "加载失败";
  } finally {
    loading.value = false;
  }
  await nextTick(); // 图表容器随 v-else 分支渲染，需等 DOM 挂载后再 init
  renderCharts();
}

function renderCharts(): void {
  const completed = task.value?.status === "COMPLETED";
  renderMainChart(completed);
  renderCweChart(completed);
}

function renderMainChart(completed: boolean): void {
  if (!mainChart.value) return;
  mainInstance ??= echarts.init(mainChart.value);
  const { categories, counter } = categoryStack.value;

  mainInstance.setOption(
    {
      grid: { left: 40, right: 12, top: 36, bottom: 28 },
      legend: {
        top: 4,
        left: "center",
        itemWidth: 10,
        itemHeight: 10,
        icon: "circle",
        textStyle: { color: AXIS_LABEL, fontSize: 11 },
      },
      tooltip: { trigger: "axis" },
      xAxis: {
        type: "category",
        data: completed ? categories : [],
        axisLine: { lineStyle: { color: AXIS_LINE } },
        axisTick: { show: false },
        axisLabel: { color: AXIS_LABEL, fontFamily: MONO_FONT, fontSize: 11 },
      },
      yAxis: {
        type: "value",
        minInterval: 1,
        splitLine: { lineStyle: { color: SPLIT_LINE } },
        axisLabel: { color: AXIS_LABEL, fontFamily: MONO_FONT, fontSize: 11 },
      },
      series: SEVERITY_META.map((meta) => ({
        name: meta.key,
        type: "bar",
        stack: "total",
        barWidth: 28,
        itemStyle: { color: meta.color },
        data: categories.map(
          (category) => counter.get(category)?.get(meta.key) ?? 0,
        ),
      })),
    },
    { notMerge: true },
  );
}

function renderCweChart(completed: boolean): void {
  if (!cweChart.value) return;
  cweInstance ??= echarts.init(cweChart.value);
  const entries = completed ? cweTop.value : [];

  // entries 按计数降序：reverse 前以 i===0 标记最大项，reverse 后与类目轴对齐，
  // 保证计数最高的 CWE 高亮为主题色。
  const seriesData = entries
    .map(([, count], i) => ({
      value: count,
      itemStyle: { color: i === 0 ? ACCENT_BAR : NEUTRAL_BAR },
    }))
    .reverse();

  cweInstance.setOption(
    {
      grid: { left: 84, right: 24, top: 8, bottom: 24 },
      tooltip: { trigger: "axis" },
      xAxis: {
        type: "value",
        minInterval: 1,
        splitLine: { lineStyle: { color: SPLIT_LINE } },
        axisLabel: { color: AXIS_LABEL, fontFamily: MONO_FONT, fontSize: 11 },
      },
      yAxis: {
        type: "category",
        data: entries.map(([cwe]) => cwe).reverse(),
        axisLine: { show: false },
        axisTick: { show: false },
        axisLabel: { color: AXIS_LABEL, fontFamily: MONO_FONT, fontSize: 11 },
      },
      series: [{ type: "bar", data: seriesData, barWidth: 14 }],
    },
    { notMerge: true },
  );
}

function handleResize(): void {
  mainInstance?.resize();
  cweInstance?.resize();
}

function jumpToCode(finding: Finding): void {
  router.push({
    name: "code",
    params: { taskId: taskId.value },
    query: { file: finding.file, line: String(finding.line), finding: finding.id },
  });
}

async function downloadReport(format: "md" | "json"): Promise<void> {
  const content = await api.downloadReport(taskId.value, format);
  const blob = new Blob([content], {
    type: format === "md" ? "text/markdown;charset=utf-8" : "application/json",
  });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = `report-${taskId.value.slice(0, 8)}.${format}`;
  link.click();
  URL.revokeObjectURL(url);
}

onMounted(() => {
  void load();
  pollTimer = window.setInterval(async () => {
    if (task.value && !["COMPLETED", "FAILED"].includes(task.value.status)) await load();
  }, 2500);
  window.addEventListener("resize", handleResize);
});
onBeforeUnmount(() => {
  if (pollTimer !== null) window.clearInterval(pollTimer);
  window.removeEventListener("resize", handleResize);
  mainInstance?.dispose();
  cweInstance?.dispose();
});
watch(taskId, () => void load());
</script>

<template>
  <div class="mx-auto max-w-300 p-6">
    <div v-if="loading && !task" class="py-20 text-center text-sm text-paper-3">加载中</div>
    <div v-else-if="!task" class="py-20 text-center text-sm text-sev-critical">{{ errorText }}</div>

    <template v-else>
      <header class="mb-5 flex items-start justify-between">
        <div>
          <div class="mb-1 flex items-center gap-3">
            <h1 class="text-xl font-medium text-paper">
              {{ task.apk?.filename ?? "分析任务" }}
            </h1>
            <StatusDot :status="task.status" />
          </div>
          <p class="font-mono text-xs text-paper-3">
            {{ task.apk?.sha256 }}
            <template v-if="task.duration_ms !== null">
              · 耗时 {{ (task.duration_ms / 1000).toFixed(1) }}s
            </template>
            <template v-if="task.result_json?.decompile">
              · {{ task.result_json.decompile.engine }} · {{ task.result_json.decompile.source_files }} 个源文件
            </template>
          </p>
          <p v-if="task.status === 'FAILED' && task.error" class="mt-1 text-sm text-sev-critical">
            {{ task.error }}
          </p>
          <p
            v-if="task.status === 'FAILED' && authCanRetry"
            class="mt-2"
          >
            <button
              class="h-8 rounded-control bg-accent px-3 text-sm font-medium text-white hover:opacity-90"
              @click="retryTask"
            >
              重试分析
            </button>
          </p>
        </div>
        <div class="flex gap-2">
          <button
            class="flex h-8 items-center gap-1.5 rounded-control border hairline bg-ink-800 px-3 text-sm text-paper-2 hover:bg-ink-950 hover:text-paper"
            @click="downloadReport('md')"
          >
            <Download class="h-3.5 w-3.5" :stroke-width="1.5" /> Markdown
          </button>
          <button
            class="flex h-8 items-center gap-1.5 rounded-control border hairline bg-ink-800 px-3 text-sm text-paper-2 hover:bg-ink-950 hover:text-paper"
            @click="downloadReport('json')"
          >
            <Download class="h-3.5 w-3.5" :stroke-width="1.5" /> JSON
          </button>
        </div>
      </header>

      <!-- 统计行：数字本体 -->
      <div class="mb-4 flex gap-4">
        <div class="card flex-1 px-4 py-3">
          <div class="text-xs text-paper-3">风险总数</div>
          <div class="num mt-1 text-[28px] leading-8 font-medium text-paper">
            {{ summary?.total ?? 0 }}
          </div>
        </div>
        <div v-for="sev in severityCounts" :key="sev.key" class="card flex-1 px-4 py-3">
          <div class="flex items-center gap-1.5 text-xs">
            <span class="h-1.5 w-1.5 rounded-full" :style="{ background: sev.color }" />
            <span class="text-paper-3">{{ sev.key }}</span>
          </div>
          <div class="num mt-1 text-[28px] leading-8 font-medium" :style="{ color: sev.color }">
            {{ sev.value }}
          </div>
        </div>
      </div>

      <div v-if="task.status !== 'COMPLETED'" class="card mb-4 px-4 py-3 text-sm text-paper-2">
        任务状态 {{ task.status }}，图表在分析完成后生成。
      </div>

      <div v-else class="mb-4 flex gap-4">
        <!-- 主图：类别 × 严重度堆叠 -->
        <div class="card min-w-0 flex-[2] p-4">
          <div class="mb-2 text-sm text-paper-2">各类别风险严重度分布</div>
          <div ref="mainChart" class="h-64" />
        </div>
        <!-- 次级：CWE Top -->
        <div class="card min-w-0 flex-1 p-4">
          <div class="mb-2 text-sm text-paper-2">CWE 分布</div>
          <div ref="cweChart" class="h-64" />
        </div>
        <!-- 类别占比：紧凑条形列表 -->
        <div class="card min-w-0 flex-1 p-4">
          <div class="mb-3 text-sm text-paper-2">类别占比</div>
          <div class="flex flex-col gap-2.5">
            <div v-for="cat in categoryShare" :key="cat.name">
              <div class="mb-1 flex items-center justify-between text-xs">
                <span class="text-paper-2">{{ cat.name }}</span>
                <span class="num text-paper-3">{{ cat.count }}</span>
              </div>
              <div class="h-1 rounded-full bg-ink-700">
                <div class="h-1 rounded-full bg-paper-3" :style="{ width: `${cat.pct}%` }" />
              </div>
            </div>
          </div>
        </div>
      </div>

      <!-- Manifest 与加固 -->
      <div class="mb-4 flex gap-4" v-if="manifest || packers.length">
        <div v-if="manifest" class="card min-w-0 flex-[2] p-4">
          <div class="mb-3 flex items-center justify-between">
            <span class="text-sm text-paper-2">Manifest</span>
            <span class="font-mono text-xs text-paper-3">{{ manifest.package }}</span>
          </div>
          <div class="mb-3 flex flex-wrap gap-2 text-xs">
            <span
              v-if="manifest.debuggable"
              class="rounded-control border hairline bg-ink-800 px-2 py-0.5 text-sev-high"
            >debuggable</span>
            <span
              v-if="manifest.allow_backup"
              class="rounded-control border hairline bg-ink-800 px-2 py-0.5 text-sev-medium"
            >allowBackup</span>
            <span
              v-if="manifest.uses_cleartext_traffic"
              class="rounded-control border hairline bg-ink-800 px-2 py-0.5 text-sev-medium"
            >cleartextTraffic</span>
            <span class="rounded-control border hairline bg-ink-800 px-2 py-0.5 text-paper-3">
              入口 {{ manifest.main_activity.split(".").pop() }}
            </span>
          </div>
          <div class="mb-2 text-xs text-paper-3">权限（{{ manifest.permissions.length }}）</div>
          <div class="mb-3 flex flex-wrap gap-1.5">
            <span
              v-for="perm in manifest.permissions"
              :key="perm"
              class="rounded-control bg-ink-900 px-2 py-0.5 font-mono text-xs text-paper-2"
            >{{ perm.replace("android.permission.", "") }}</span>
          </div>
          <div class="mb-2 text-xs text-paper-3">
            导出组件（{{ manifest.exported_components.length }}）
          </div>
          <div class="flex flex-col gap-1">
            <div
              v-for="comp in manifest.exported_components"
              :key="comp.name"
              class="flex items-center justify-between rounded-control bg-ink-900 px-2.5 py-1.5"
            >
              <span class="font-mono text-xs text-paper-2">{{ comp.name }}</span>
              <span class="text-xs" :class="comp.permission ? 'text-paper-3' : 'text-sev-high'">
                {{ comp.type }}{{ comp.permission ? ` · ${comp.permission}` : " · 无权限保护" }}
              </span>
            </div>
          </div>
        </div>
        <div v-if="packers.length" class="card min-w-0 flex-1 p-4">
          <div class="mb-3 text-sm text-paper-2">加固识别</div>
          <div v-for="packer in packers" :key="packer.name" class="mb-3">
            <div class="text-sm text-paper">{{ packer.name }}</div>
            <div class="mt-1 flex flex-col gap-0.5">
              <div
                v-for="evidence in packer.evidence"
                :key="evidence"
                class="font-mono text-xs text-paper-3"
              >{{ evidence }}</div>
            </div>
          </div>
        </div>
      </div>

      <!-- 风险清单 -->
      <div class="card p-4">
        <div class="mb-3 flex items-center justify-between">
          <span class="text-sm text-paper-2">风险清单</span>
          <span class="num text-xs text-paper-3">共 {{ findings.length }} 项</span>
        </div>
        <RiskTable :findings="findings" @jump="jumpToCode" />
      </div>
    </template>
  </div>
</template>
