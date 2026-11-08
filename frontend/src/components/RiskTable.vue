<script setup lang="ts">
import { ref } from "vue";
import { ChevronDown, ChevronRight } from "lucide-vue-next";
import SeverityBadge from "@/components/SeverityBadge.vue";
import type { Finding } from "@/types";

defineProps<{ findings: Finding[] }>();

const emit = defineEmits<{ jump: [finding: Finding] }>();

const expanded = ref<string | null>(null);

function toggle(id: string): void {
  expanded.value = expanded.value === id ? null : id;
}
</script>

<template>
  <div class="overflow-hidden rounded-card border hairline">
    <table class="w-full border-collapse">
      <thead>
        <tr class="bg-ink-950 text-left text-xs text-paper-3">
          <th class="h-9 px-3 font-normal">编号</th>
          <th class="h-9 px-3 font-normal">等级</th>
          <th class="h-9 px-3 font-normal">风险</th>
          <th class="h-9 px-3 font-normal">CWE</th>
          <th class="h-9 px-3 font-normal">位置</th>
          <th class="h-9 px-3 font-normal">类别</th>
        </tr>
      </thead>
      <tbody>
        <template v-for="finding in findings" :key="finding.id">
          <tr
            class="cursor-pointer border-t hairline text-sm hover:bg-ink-700/60"
            @click="toggle(finding.id)"
          >
            <td class="h-9 px-3 font-mono text-xs text-paper-2">{{ finding.id }}</td>
            <td class="h-9 px-3"><SeverityBadge :severity="finding.severity" /></td>
            <td class="h-9 max-w-105 truncate px-3 text-paper">{{ finding.title }}</td>
            <td class="h-9 px-3 font-mono text-xs text-paper-3">{{ finding.cwe ?? "N/A" }}</td>
            <td class="h-9 max-w-90 truncate px-3 font-mono text-xs text-paper-2">
              {{ finding.file.split("/").slice(-1)[0] }}:{{ finding.line }}
            </td>
            <td class="h-9 px-3 text-xs text-paper-3">{{ finding.category }}</td>
          </tr>
          <tr v-if="expanded === finding.id" class="border-t hairline bg-ink-950/60">
            <td colspan="6" class="px-4 py-3">
              <div class="mb-2 flex items-start gap-2 text-sm">
                <component
                  :is="expanded === finding.id ? ChevronDown : ChevronRight"
                  class="mt-0.5 h-4 w-4 text-paper-3"
                />
                <div>
                  <p class="mb-1 text-paper-2">{{ finding.description }}</p>
                  <p class="mb-2 text-xs text-paper-3">规则 {{ finding.rule_id }}</p>
                  <pre class="overflow-x-auto rounded-control bg-ink-900 p-2 font-mono text-xs text-paper-2">{{ finding.snippet }}</pre>
                  <p class="mt-2 text-sm text-paper-2">
                    <span class="text-paper-3">修复建议</span>
                    {{ finding.suggestion }}
                  </p>
                  <button
                    class="mt-2 h-7 rounded-control border hairline px-2.5 text-xs text-paper-2 hover:bg-ink-700 hover:text-paper"
                    @click.stop="emit('jump', finding)"
                  >
                    在代码中查看
                  </button>
                </div>
              </div>
            </td>
          </tr>
        </template>
        <tr v-if="findings.length === 0">
          <td colspan="6" class="h-16 px-3 text-center text-sm text-paper-3">暂无风险数据</td>
        </tr>
      </tbody>
    </table>
  </div>
</template>
