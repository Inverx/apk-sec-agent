<script setup lang="ts">
import { computed } from "vue";
import { useRoute, useRouter } from "vue-router";
import { Bot, FileSearch, LayoutDashboard, LogOut, ShieldCheck, UploadCloud } from "lucide-vue-next";
import { useAuthStore } from "@/stores/auth";

const auth = useAuthStore();
const route = useRoute();
const router = useRouter();

const currentTaskId = computed(() => {
  const value = route.params.taskId;
  return typeof value === "string" ? value : null;
});

const navItems = computed(() => {
  const items: Array<{ label: string; icon: unknown; to: string; active: boolean }> = [
    { label: "任务与上传", icon: UploadCloud, to: "/", active: route.name === "tasks" },
  ];
  if (currentTaskId.value) {
    items.push(
      {
        label: "风险看板",
        icon: LayoutDashboard,
        to: `/task/${currentTaskId.value}`,
        active: route.name === "dashboard",
      },
      {
        label: "代码审计",
        icon: FileSearch,
        to: `/task/${currentTaskId.value}/code`,
        active: route.name === "code",
      },
      {
        label: "AI 分析",
        icon: Bot,
        to: `/task/${currentTaskId.value}/agent`,
        active: route.name === "agent",
      },
    );
  }
  return items;
});

function logout(): void {
  auth.logout();
  router.push({ name: "login" });
}
</script>

<template>
  <div class="flex h-full">
    <aside class="flex w-60 shrink-0 flex-col bg-ink-950 hairline border-r">
      <div class="flex items-center gap-2 px-4 pt-5 pb-4">
        <ShieldCheck class="h-5 w-5 text-accent" :stroke-width="1.5" />
        <div>
          <div class="text-[15px] leading-5 font-medium">APK-SecAgent</div>
          <div class="text-xs text-paper-3">Android 安全分析平台</div>
        </div>
      </div>

      <nav class="mt-2 flex flex-col gap-0.5 px-2">
        <div class="px-2 pt-3 pb-1 text-xs text-paper-3">工作台</div>
        <router-link
          v-for="item in navItems"
          :key="item.to"
          :to="item.to"
          class="flex h-8 items-center gap-2.5 rounded-control px-2 text-sm"
          :class="item.active ? 'bg-ink-700 text-paper' : 'text-paper-2 hover:bg-ink-800 hover:text-paper'"
        >
          <component
            :is="item.icon"
            class="h-4 w-4 shrink-0"
            :class="item.active ? 'text-accent' : 'text-paper-3'"
            :stroke-width="1.5"
          />
          <span>{{ item.label }}</span>
        </router-link>
      </nav>

      <div class="mt-auto border-t hairline px-4 py-3">
        <template v-if="auth.user">
          <div class="flex items-center justify-between">
            <div>
              <div class="text-sm text-paper">{{ auth.user.username }}</div>
              <div class="text-xs text-paper-3">{{ auth.user.role }}</div>
            </div>
            <button
              class="flex h-8 w-8 items-center justify-center rounded-control text-paper-3 hover:bg-ink-700 hover:text-paper"
              title="退出登录"
              @click="logout"
            >
              <LogOut class="h-4 w-4" :stroke-width="1.5" />
            </button>
          </div>
        </template>
      </div>
    </aside>

    <main class="min-w-0 flex-1 overflow-y-auto">
      <router-view />
    </main>
  </div>
</template>
