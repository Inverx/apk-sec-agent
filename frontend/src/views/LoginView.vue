<script setup lang="ts">
import { ref } from "vue";
import { useRouter } from "vue-router";
import { ShieldCheck } from "lucide-vue-next";
import { ApiError } from "@/api";
import { useAuthStore } from "@/stores/auth";

const auth = useAuthStore();
const router = useRouter();

const mode = ref<"login" | "register">("login");
const username = ref("");
const password = ref("");
const error = ref("");
const busy = ref(false);

async function submit(): Promise<void> {
  error.value = "";
  busy.value = true;
  try {
    if (mode.value === "register") {
      await auth.register(username.value, password.value);
    }
    await auth.login(username.value, password.value);
    await auth.fetchMe();
    router.push({ name: "tasks" });
  } catch (exc) {
    error.value =
      exc instanceof ApiError ? exc.message : "网络错误，请确认后端服务已启动";
  } finally {
    busy.value = false;
  }
}
</script>

<template>
  <div class="flex h-full items-center justify-center bg-ink-900">
    <div class="w-96 card p-6">
      <div class="mb-6 flex items-center gap-2.5">
        <ShieldCheck class="h-6 w-6 text-accent" :stroke-width="1.5" />
        <div>
          <h1 class="text-lg font-medium text-paper">APK-SecAgent</h1>
          <p class="text-xs text-paper-3">Android 应用静态安全分析平台</p>
        </div>
      </div>

      <form class="flex flex-col gap-3" @submit.prevent="submit">
        <label class="flex flex-col gap-1">
          <span class="text-xs text-paper-2">用户名</span>
          <input
            v-model="username"
            type="text"
            autocomplete="username"
            class="h-9 rounded-control bg-ink-900 border hairline px-3 text-sm text-paper"
            required
          />
        </label>
        <label class="flex flex-col gap-1">
          <span class="text-xs text-paper-2">密码</span>
          <input
            v-model="password"
            type="password"
            autocomplete="current-password"
            class="h-9 rounded-control bg-ink-900 border hairline px-3 text-sm text-paper"
            required
            minlength="8"
          />
        </label>

        <p v-if="error" class="text-xs text-sev-critical">{{ error }}</p>

        <button
          type="submit"
          :disabled="busy"
          class="mt-1 h-9 rounded-control bg-paper text-sm font-medium text-ink-950 hover:opacity-90 disabled:opacity-50"
        >
          {{ mode === "login" ? "登录" : "注册并登录" }}
        </button>
      </form>

      <button
        class="mt-3 h-9 w-full rounded-control border hairline text-sm text-paper-2 hover:bg-ink-950 hover:text-paper"
        @click="mode = mode === 'login' ? 'register' : 'login'"
      >
        {{ mode === "login" ? "注册新账号" : "返回登录" }}
      </button>
    </div>
  </div>
</template>
