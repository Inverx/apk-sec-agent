<script setup lang="ts">
import { computed } from "vue";

const props = defineProps<{ severity: string }>();

const style = computed(() => {
  switch (props.severity) {
    case "CRITICAL":
      return { dot: "bg-sev-critical", text: "text-sev-critical" };
    case "HIGH":
      return { dot: "bg-sev-high", text: "text-sev-high" };
    case "MEDIUM":
      return { dot: "bg-sev-medium", text: "text-sev-medium" };
    default:
      return { dot: "bg-sev-low", text: "text-sev-low" };
  }
});
</script>

<template>
  <span class="inline-flex items-center gap-1.5">
    <span class="h-1.5 w-1.5 rounded-full" :class="style.dot" />
    <span class="num text-xs font-medium" :class="style.text">{{ severity }}</span>
  </span>
</template>
