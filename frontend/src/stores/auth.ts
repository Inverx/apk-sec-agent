import { defineStore } from "pinia";
import { computed, ref } from "vue";
import { api, setTokenProvider } from "@/api";
import type { User } from "@/types";

const STORAGE_KEY = "apksec.token";

export const useAuthStore = defineStore("auth", () => {
  const token = ref<string | null>(localStorage.getItem(STORAGE_KEY));
  const user = ref<User | null>(null);

  const isAuthenticated = computed(() => token.value !== null);
  const role = computed(() => user.value?.role ?? "viewer");
  const canAnalyze = computed(() => role.value === "admin" || role.value === "analyst");

  setTokenProvider(() => token.value);

  async function login(username: string, password: string): Promise<void> {
    const response = await api.login(username, password);
    token.value = response.access_token;
    user.value = response.user;
    localStorage.setItem(STORAGE_KEY, response.access_token);
  }

  async function register(username: string, password: string): Promise<User> {
    return api.register(username, password);
  }

  async function fetchMe(): Promise<void> {
    if (!token.value) return;
    try {
      user.value = await api.me();
    } catch {
      logout();
    }
  }

  function logout(): void {
    token.value = null;
    user.value = null;
    localStorage.removeItem(STORAGE_KEY);
  }

  return { token, user, isAuthenticated, role, canAnalyze, login, register, fetchMe, logout };
});
