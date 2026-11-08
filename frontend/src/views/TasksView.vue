<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref } from "vue";
import { useRouter } from "vue-router";
import { CloudUpload, RefreshCw, RotateCcw } from "lucide-vue-next";
import { api, ApiError } from "@/api";
import { hashBlob } from "@/sha256";
import { useAuthStore } from "@/stores/auth";
import StatusDot from "@/components/StatusDot.vue";
import type { Task, TaskCreateResponse } from "@/types";

const auth = useAuthStore();
const router = useRouter();
const retryingId = ref<string | null>(null);

interface UploadJob {
  name: string;
  size: number;
  phase: "hashing" | "uploading" | "done" | "error";
  progress: number;
  message: string;
}

const tasks = ref<Task[]>([]);
const jobs = ref<UploadJob[]>([]);
const dragging = ref(false);
const loading = ref(false);
const fileInput = ref<HTMLInputElement | null>(null);
let pollTimer: number | null = null;

onMounted(() => {
  refresh();
  pollTimer = window.setInterval(pollRunning, 3000);
});
onBeforeUnmount(() => {
  if (pollTimer !== null) window.clearInterval(pollTimer);
});

async function refresh(): Promise<void> {
  loading.value = true;
  try {
    tasks.value = await api.listTasks();
  } catch {
    /* 忽略轮询错误 */
  } finally {
    loading.value = false;
  }
}

const runningCount = computed(
  () => tasks.value.filter((t) => !["COMPLETED", "FAILED"].includes(t.status)).length,
);

async function pollRunning(): Promise<void> {
  if (runningCount.value === 0 && jobs.value.every((j) => j.phase === "done" || j.phase === "error")) {
    return;
  }
  await refresh();
}

// ---------- 上传（分片 + 边读边算 SHA256 实现秒传预检） ----------
async function uploadFiles(files: FileList | File[]): Promise<void> {
  for (const file of Array.from(files)) {
    await uploadOne(file);
  }
  await refresh();
}

async function uploadOne(file: File): Promise<void> {
  const job: UploadJob = { name: file.name, size: file.size, phase: "hashing", progress: 0, message: "计算 SHA256" };
  jobs.value.unshift(job);

  try {
    if (!/\.(apk|zip)$/i.test(file.name)) {
      job.phase = "error";
      job.message = "仅支持 .apk / .zip";
      return;
    }
    const sha256 = await hashBlob(file, (ratio) => {
      job.progress = ratio * 0.2;
    });

    job.phase = "uploading";
    job.message = "建立上传会话";
    const totalChunks = Math.max(1, Math.ceil(file.size / (4 * 1024 * 1024)));
    const init = await api.uploadInit(file.name, file.size, totalChunks, sha256);

    if (init.instant) {
      // SHA256 命中历史分析，无需再传
      job.phase = "done";
      job.progress = 1;
      job.message = init.reused_task ? "秒传命中，已复用历史分析结果" : "秒传命中，已创建新任务";
      await refresh();
      return;
    }

    job.message = "上传分片";
    for (let index = 0; index < totalChunks; index++) {
      const chunk = file.slice(index * init.chunk_size, (index + 1) * init.chunk_size);
      await api.uploadChunk(init.upload_id, index, chunk);
      job.progress = 0.2 + ((index + 1) / totalChunks) * 0.8;
    }

    const complete: TaskCreateResponse = await api.uploadComplete(init.upload_id, sha256);
    job.phase = "done";
    job.progress = 1;
    job.message = complete.reused ? "已复用历史分析结果" : "上传完成，任务已入队";
  } catch (exc) {
    job.phase = "error";
    job.message = exc instanceof ApiError ? exc.message : "上传失败";
  }
}

function onDrop(event: DragEvent): void {
  dragging.value = false;
  if (!auth.canAnalyze) return; // viewer 只读，禁止上传
  if (event.dataTransfer?.files.length) {
    void uploadFiles(event.dataTransfer.files);
  }
}

async function retryFailed(task: Task): Promise<void> {
  if (retryingId.value) return;
  retryingId.value = task.id;
  try {
    await api.retryTask(task.id);
    await refresh();
  } catch {
    /* 重试失败时保留原状态，错误在任务详情可见 */
  } finally {
    retryingId.value = null;
  }
}

function onFileChosen(event: Event): void {
  const input = event.target as HTMLInputElement;
  if (input.files?.length) {
    void uploadFiles(input.files);
  }
  input.value = "";
}

function openTask(task: Task): void {
  router.push({ name: "dashboard", params: { taskId: task.id } });
}

function shortSha(sha: string): string {
  return sha.slice(0, 16) + "…";
}

function formatTime(iso: string): string {
  return new Date(iso).toLocaleString("zh-CN", { hour12: false });
}
</script>

<template>
  <div class="mx-auto max-w-300 p-6">
    <header class="mb-5 flex items-center justify-between">
      <div>
        <h1 class="text-xl font-medium text-paper">任务与上传</h1>
        <p class="text-sm text-paper-3">管理 APK 样本与静态安全审计任务</p>
      </div>
      <button
        class="flex h-8 items-center gap-1.5 rounded-control border hairline px-3 text-sm text-paper-2 hover:bg-ink-700 hover:text-paper"
        @click="refresh"
      >
        <RefreshCw class="h-3.5 w-3.5" :stroke-width="1.5" :class="{ 'animate-spin': loading }" />
        刷新
      </button>
    </header>

    <div
      class="mb-6 flex h-36 flex-col items-center justify-center gap-2 rounded-card border border-dashed hairline bg-ink-800/60"
      :class="{
        'cursor-pointer border-accent bg-ink-700/50': dragging && auth.canAnalyze,
        'cursor-pointer hover:bg-ink-950': auth.canAnalyze && !dragging,
      }"
      v-on="auth.canAnalyze
        ? { click: () => fileInput?.click(), dragover: (e: Event) => { dragging = true; e.preventDefault(); }, dragleave: () => { dragging = false; }, drop: onDrop }
        : {}"
    >
      <CloudUpload class="h-6 w-6 text-paper-3" :stroke-width="1.5" />
      <template v-if="auth.canAnalyze">
        <p class="text-sm text-paper-2">拖拽 APK 到此处，或点击选择文件</p>
        <p class="text-xs text-paper-3">支持 .apk / .zip 格式，单文件上限 200 MB</p>
      </template>
      <template v-else>
        <p class="text-sm text-paper-2">当前账号为只读权限，不支持上传样本</p>
      </template>
      <input
        v-if="auth.canAnalyze"
        ref="fileInput"
        type="file"
        accept=".apk,.zip"
        class="hidden"
        @change="onFileChosen"
      />
    </div>

    <div v-if="jobs.length" class="mb-6 flex flex-col gap-2">
      <div v-for="job in jobs" :key="job.name + job.message" class="card px-4 py-3">
        <div class="mb-1.5 flex items-center justify-between text-sm">
          <span class="font-mono text-xs text-paper-2">{{ job.name }}</span>
          <span
            class="text-xs"
            :class="job.phase === 'error' ? 'text-sev-critical' : job.phase === 'done' ? 'text-sev-low' : 'text-paper-3'"
          >
            {{ job.message }}
          </span>
        </div>
        <div class="h-1 rounded-full bg-ink-700">
          <div
            class="h-1 rounded-full"
            :class="job.phase === 'error' ? 'bg-sev-critical' : 'bg-accent'"
            :style="{ width: `${Math.round(job.progress * 100)}%` }"
          />
        </div>
      </div>
    </div>

    <div class="card overflow-hidden">
      <div class="flex h-10 items-center justify-between border-b hairline px-4">
        <span class="text-sm text-paper-2">分析任务</span>
        <span class="num text-xs text-paper-3">{{ tasks.length }} 个任务</span>
      </div>
      <table class="w-full border-collapse">
        <thead>
          <tr class="bg-ink-950 text-left text-xs text-paper-3">
            <th class="h-9 px-4 font-normal">状态</th>
            <th class="h-9 px-4 font-normal">文件</th>
            <th class="h-9 px-4 font-normal">SHA256</th>
            <th class="h-9 px-4 font-normal">风险</th>
            <th class="h-9 px-4 font-normal">耗时</th>
            <th class="h-9 px-4 font-normal">创建时间</th>
          </tr>
        </thead>
        <tbody>
          <tr
            v-for="task in tasks"
            :key="task.id"
            class="cursor-pointer border-t hairline hover:bg-ink-700/60"
            @click="openTask(task)"
          >
            <td class="h-10 px-4"><StatusDot :status="task.status" /></td>
            <td class="h-10 max-w-60 truncate px-4 text-sm text-paper">
              {{ task.apk?.filename ?? task.apk_id }}
              <span v-if="task.error" class="ml-1 text-xs text-sev-critical">{{ task.error }}</span>
            </td>
            <td class="h-10 px-4 font-mono text-xs text-paper-3">
              {{ task.apk ? shortSha(task.apk.sha256) : "—" }}
            </td>
            <td class="h-10 px-4 num text-sm text-paper-2">
              {{ task.result_json?.summary?.total ?? "—" }}
            </td>
            <td class="h-10 px-4 num text-sm text-paper-2">
              {{ task.duration_ms !== null ? `${(task.duration_ms / 1000).toFixed(1)}s` : "—" }}
            </td>
            <td class="h-10 px-4 text-xs text-paper-3">
              {{ formatTime(task.created_at) }}
              <button
                v-if="task.status === 'FAILED' && auth.role === 'admin'"
                class="ml-2 inline-flex h-6 items-center gap-1 rounded-control border hairline bg-ink-800 px-2 text-xs text-paper-2 hover:bg-ink-700 hover:text-paper"
                :disabled="retryingId === task.id"
                @click.stop="retryFailed(task)"
              >
                <RotateCcw
                  class="h-3 w-3"
                  :stroke-width="1.5"
                  :class="{ 'animate-spin': retryingId === task.id }"
                />
                重试
              </button>
            </td>
          </tr>
          <tr v-if="tasks.length === 0">
            <td colspan="6" class="h-16 text-center text-sm text-paper-3">
              暂无任务，先上传一个 APK
            </td>
          </tr>
        </tbody>
      </table>
    </div>
  </div>
</template>
