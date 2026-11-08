import { createRouter, createWebHistory } from "vue-router";
import AppShell from "@/components/AppShell.vue";
import { useAuthStore } from "@/stores/auth";

const router = createRouter({
  history: createWebHistory(),
  routes: [
    {
      path: "/login",
      name: "login",
      component: () => import("@/views/LoginView.vue"),
      meta: { public: true },
    },
    {
      path: "/",
      component: AppShell,
      children: [
        { path: "", name: "tasks", component: () => import("@/views/TasksView.vue") },
        {
          path: "task/:taskId",
          name: "dashboard",
          component: () => import("@/views/DashboardView.vue"),
        },
        {
          path: "task/:taskId/code",
          name: "code",
          component: () => import("@/views/CodeBrowserView.vue"),
        },
        {
          path: "task/:taskId/agent",
          name: "agent",
          component: () => import("@/views/AgentChatView.vue"),
        },
      ],
    },
    { path: "/:pathMatch(.*)*", redirect: "/" },
  ],
});

router.beforeEach(async (to) => {
  const auth = useAuthStore();
  if (to.meta.public) {
    if (auth.isAuthenticated && to.name === "login") return { name: "tasks" };
    return true;
  }
  if (!auth.isAuthenticated) return { name: "login" };
  if (auth.user === null) await auth.fetchMe();
  return true;
});

export default router;
