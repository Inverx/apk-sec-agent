<script setup lang="ts">
import { computed } from "vue";
import type { TaskStatus } from "@/types";

const props = defineProps<{ status: TaskStatus }>();

const style = computed(() => {
  switch (props.status) {
    case "COMPLETED":
      return { dot: "bg-sev-low", label: "text-paper-2" };
    case "FAILED":
      return { dot: "bg-sev-critical", label: "text-sev-critical" };
    case "PENDING":
      return { dot: "bg-paper-3", label: "text-paper-2" };
    default:
      // DECOMPILING / SCANNING / INDEXING：进行中
      return { dot: "bg-accent", label: "text-accent" };
  }
});
</script>

<template>
  <span class="inline-flex items-center gap-2">
    <span class="relative flex h-2 w-2">
      <span
        v-if="status !== 'PENDING' && status !== 'COMPLETED' && status !== 'FAILED'"
        class="absolute inline-flex h-full w-full animate-ping rounded-full opacity-60"
        :class="style.dot"
      />
      <span class="relative inline-flex h-2 w-2 rounded-full" :class="style.dot" />
    </span>
    <span class="num text-xs" :class="style.label">{{ status }}</span>
  </span>
</template>
