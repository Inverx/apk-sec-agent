// 极简安全 Markdown 渲染器：先整体 HTML 转义，再做受限语法转换。
// 支持：标题、粗体、行内代码、围栏代码块、表格、无序/有序列表、分隔线。
// 不引入任何原始 HTML，杜绝 Agent 输出注入 XSS。

export function renderMarkdown(source: string): string {
  const escaped = escapeHtml(source);
  const lines = escaped.split(/\r?\n/);
  const out: string[] = [];
  let inCode = false;
  let codeLines: string[] = [];
  let tableLines: string[] = [];

  const flushTable = () => {
    if (tableLines.length >= 2) {
      const rows = tableLines.map((l) =>
        l.replace(/^\|/, "").replace(/\|$/, "").split("|").map((c) => c.trim()),
      );
      const bodyRows = rows.filter((cells) => !cells.every((c) => /^:?-{2,}:?$/.test(c) || c === ""));
      const [head, ...body] = bodyRows;
      out.push('<table class="md-table">');
      if (head) {
        out.push("<thead><tr>" + head.map((c) => `<th>${inline(c)}</th>`).join("") + "</tr></thead>");
      }
      out.push("<tbody>");
      for (const cells of body) {
        out.push("<tr>" + cells.map((c) => `<td>${inline(c)}</td>`).join("") + "</tr>");
      }
      out.push("</tbody></table>");
    }
    tableLines = [];
  };

  for (const line of lines) {
    if (line.trim().startsWith("```")) {
      if (inCode) {
        out.push(`<pre class="md-pre"><code>${codeLines.join("\n")}</code></pre>`);
        codeLines = [];
        inCode = false;
      } else {
        flushTable();
        inCode = true;
      }
      continue;
    }
    if (inCode) {
      codeLines.push(line);
      continue;
    }
    if (/^\s*\|.*\|\s*$/.test(line)) {
      tableLines.push(line.trim());
      continue;
    }
    flushTable();

    const heading = line.match(/^(#{1,4})\s+(.*)$/);
    if (heading) {
      const level = heading[1].length;
      out.push(`<h${level} class="md-h${level}">${inline(heading[2])}</h${level}>`);
      continue;
    }
    if (/^\s*(---+|\*\*\*+)\s*$/.test(line)) {
      out.push('<hr class="md-hr" />');
      continue;
    }
    const bullet = line.match(/^\s*[-*]\s+(.*)$/);
    if (bullet) {
      out.push(`<div class="md-li">${inline(bullet[1])}</div>`);
      continue;
    }
    const ordered = line.match(/^\s*\d+\.\s+(.*)$/);
    if (ordered) {
      out.push(`<div class="md-li">${inline(ordered[1])}</div>`);
      continue;
    }
    if (line.trim() === "") {
      out.push('<div class="md-gap"></div>');
      continue;
    }
    out.push(`<p class="md-p">${inline(line)}</p>`);
  }
  if (inCode && codeLines.length) {
    out.push(`<pre class="md-pre"><code>${codeLines.join("\n")}</code></pre>`);
  }
  flushTable();
  return out.join("");
}

function escapeHtml(text: string): string {
  return text
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function inline(text: string): string {
  let result = text;
  result = result.replace(/`([^`]+)`/g, '<code class="md-code">$1</code>');
  result = result.replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>");
  return result;
}
