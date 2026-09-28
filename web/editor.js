// In-page translation editor: one section at a time, source beside an
// editable target, checked by the Python tool as you type, and saved in
// this browser (store.js).

import { loadSections, openStore, saveSection } from "./store.js";

const PAGE_SIZE = 25;
const SAVE_DELAY = 400; // ms after the last keystroke
const CHECK_DELAY = 250;

const $ = (id) => document.getElementById(id);

// Issues that do not count as warnings: the text is fine, just shown
// differently in game.
const INFO_KINDS = new Set(["folded"]);

export function createEditor({ call, busy, t, getFold, onChange = () => {} }) {
  let game = null; // Summary of the open game file.
  let persistent = false;
  let saved = new Map(); // xpath -> { index: { target, source } }
  let xpath = null;
  let sources = [];
  let limits = { max_width: 0, max_subs: 0 };
  let issues = new Map(); // index -> issue list, for the open section
  let query = "";
  let filter = "all";
  let page = 0;
  let saveState = "saved";
  const saveTimers = new Map();
  const checkTimers = new Map();

  const storeReady = openStore().then((ok) => (persistent = ok));

  const rowsOf = (section) => saved.get(section) ?? {};
  const targetOf = (index) => rowsOf(xpath)[index]?.target ?? "";
  const hasWarning = (index) =>
    (issues.get(index) ?? []).some((issue) => !INFO_KINDS.has(issue.kind));

  // ---- Saving ----

  function renderSaveState() {
    $("editor-save").textContent = persistent
      ? t(saveState === "saving" ? "editor.saving" : "editor.saved")
      : t("editor.notSaved");
    $("editor-save").classList.toggle("error", !persistent);
  }

  function scheduleSave(section) {
    saveState = "saving";
    renderSaveState();
    clearTimeout(saveTimers.get(section));
    saveTimers.set(section, setTimeout(async () => {
      saveTimers.delete(section);
      await saveSection(section, rowsOf(section));
      onChange();
      if (saveTimers.size === 0) {
        saveState = "saved";
        renderSaveState();
      }
    }, SAVE_DELAY));
  }

  // ---- Checks ----

  // Checks run in Python, for the rows given, and replace their issues.
  async function check(indices) {
    const section = xpath;
    const rows = indices.map((i) => [sources[i], targetOf(i)]);
    const results = rows.length
      ? await call("check", { xpath: section, rows, fold: getFold() })
      : [];
    if (section !== xpath) return; // The section changed meanwhile.
    indices.forEach((index, i) => {
      const found = results[i];
      const recorded = rowsOf(xpath)[index]?.source;
      if (recorded != null && recorded !== sources[index]) {
        found.push({ kind: "source_changed" });
      }
      if (targetOf(index)) issues.set(index, found);
      else issues.delete(index);
    });
  }

  function scheduleCheck(index) {
    clearTimeout(checkTimers.get(index));
    checkTimers.set(index, setTimeout(async () => {
      checkTimers.delete(index);
      await check([index]);
      renderRowState(index);
      renderProgress();
    }, CHECK_DELAY));
  }

  function describe(issue) {
    switch (issue.kind) {
      case "placeholder":
        return t("editor.issue.placeholder", issue);
      case "folded":
        return t("editor.issue.folded", issue);
      case "unencodable":
        return t("editor.issue.unencodable", issue);
      case "width":
        return limits.max_subs > 1
          ? t("editor.issue.widthPart", { ...issue, part: issue.sub + 1 })
          : t("editor.issue.width", issue);
      case "subs":
        return t("editor.issue.subs", issue);
      case "source_changed":
        return t("editor.issue.sourceChanged");
      default:
        return issue.kind;
    }
  }

  // ---- Rendering ----

  function visibleIndices() {
    const needle = query.trim().toLocaleLowerCase();
    const shown = [];
    for (let i = 0; i < sources.length; i++) {
      const target = targetOf(i);
      if (filter === "todo" && target) continue;
      if (filter === "done" && !target) continue;
      if (filter === "warnings" && !hasWarning(i)) continue;
      if (needle && !sources[i].toLocaleLowerCase().includes(needle)
          && !target.toLocaleLowerCase().includes(needle)) continue;
      shown.push(i);
    }
    return shown;
  }

  function translatedCount(section) {
    return Object.values(rowsOf(section)).filter((row) => row.target).length;
  }

  function renderSectionOptions() {
    const select = $("editor-section");
    select.replaceChildren(...game.sections.map((section) => {
      const count = translatedCount(section);
      const label = count ? `${section} · ${t("editor.translatedShort", { count })}` : section;
      return new Option(label, section);
    }));
    if (xpath) select.value = xpath;
  }

  function renderProgress() {
    const done = translatedCount(xpath);
    const warnings = [...issues.keys()].filter(hasWarning).length;
    $("editor-progress").textContent = t("editor.progress", {
      done: done.toLocaleString(), total: sources.length.toLocaleString(), warnings,
    });
    const option = [...$("editor-section").options].find((o) => o.value === xpath);
    if (option) {
      option.textContent = done ? `${xpath} · ${t("editor.translatedShort", { count: done })}` : xpath;
    }
  }

  function renderRowState(index) {
    const row = $("editor-rows").querySelector(`[data-index="${index}"]`);
    if (!row) return;
    const list = issues.get(index) ?? [];
    row.classList.toggle("done", Boolean(targetOf(index)));
    row.classList.toggle("warning", hasWarning(index));
    row.querySelector(".issues").replaceChildren(...list.map((issue) => {
      const li = document.createElement("li");
      li.textContent = describe(issue);
      li.className = INFO_KINDS.has(issue.kind) ? "info" : "warn";
      return li;
    }));
  }

  function fitHeight(textarea) {
    textarea.style.height = "auto";
    textarea.style.height = `${textarea.scrollHeight + 2}px`;
  }

  function renderRow(index) {
    const li = document.createElement("li");
    li.className = "row";
    li.dataset.index = index;

    const number = document.createElement("span");
    number.className = "row-index";
    number.textContent = `#${index}`;

    const source = document.createElement("p");
    source.className = "row-source";
    source.textContent = sources[index] || t("editor.emptySource");

    const target = document.createElement("textarea");
    target.className = "row-target";
    target.rows = 1;
    target.value = targetOf(index);
    target.setAttribute("aria-label", t("editor.targetLabel", { index }));
    target.addEventListener("input", () => {
      update(index, target.value);
      fitHeight(target);
    });

    const list = document.createElement("ul");
    list.className = "issues";
    li.append(number, source, target, list);
    requestAnimationFrame(() => fitHeight(target));
    return li;
  }

  function render() {
    renderSaveState();
    if (!xpath) return;
    const shown = visibleIndices();
    const pages = Math.max(1, Math.ceil(shown.length / PAGE_SIZE));
    page = Math.min(page, pages - 1);
    const slice = shown.slice(page * PAGE_SIZE, (page + 1) * PAGE_SIZE);
    $("editor-rows").replaceChildren(...slice.map(renderRow));
    slice.forEach(renderRowState);
    $("editor-empty").hidden = slice.length > 0;
    $("editor-empty").textContent = sources.length ? t("editor.noMatch") : t("editor.emptySection");
    $("editor-page").value = page + 1;
    $("editor-page").max = pages;
    $("editor-pages").textContent = t("editor.pageOf", { pages });
    $("editor-prev").disabled = page === 0;
    $("editor-next").disabled = page >= pages - 1;
    renderProgress();
  }

  // ---- Editing ----

  function update(index, value) {
    const rows = { ...rowsOf(xpath) };
    if (value) rows[index] = { target: value, source: rows[index]?.source ?? sources[index] };
    else delete rows[index];
    saved.set(xpath, rows);
    scheduleSave(xpath);
    scheduleCheck(index);
  }

  async function openSection(section) {
    const data = await busy(t("busy.section", { xpath: section }), () =>
      call("section", { name: game.name, xpath: section }),
    );
    xpath = section;
    $("editor-section").value = section;
    sources = data.sources;
    limits = { max_width: data.max_width, max_subs: data.max_subs };
    issues = new Map();
    page = 0;
    // Record the source of imported rows, which arrive without one.
    const rows = rowsOf(xpath);
    let filled = false;
    for (const [index, row] of Object.entries(rows)) {
      if (row.source == null && index < sources.length) {
        row.source = sources[index];
        filled = true;
      }
    }
    if (filled) scheduleSave(xpath);
    await check(Object.keys(rows).map(Number).filter((i) => i < sources.length));
    render();
  }

  // ---- Wiring ----

  $("editor-section").addEventListener("change", (event) => {
    openSection(event.target.value).catch(() => {});
  });
  $("editor-search").addEventListener("input", (event) => {
    query = event.target.value;
    page = 0;
    render();
  });
  $("editor-filter").addEventListener("change", (event) => {
    filter = event.target.value;
    page = 0;
    render();
  });
  $("editor-prev").addEventListener("click", () => { page -= 1; render(); });
  $("editor-next").addEventListener("click", () => { page += 1; render(); });
  $("editor-page").addEventListener("change", (event) => {
    page = Math.max(0, (Number(event.target.value) || 1) - 1);
    render();
  });

  return {
    // Show the editor for a newly opened game file.
    async open(gameFile) {
      await storeReady;
      game = gameFile;
      saved = await loadSections(game.file_type);
      xpath = null;
      renderSectionOptions();
      const started = game.sections.find((section) => translatedCount(section));
      if (game.sections.length) await openSection(started ?? game.sections[0]);
      renderSectionOptions();
    },

    // The work for this game file, as the build expects it.
    edits() {
      const edits = {};
      for (const section of game?.sections ?? []) {
        const targets = {};
        for (const [index, row] of Object.entries(rowsOf(section))) {
          if (row.target) targets[index] = row.target;
        }
        if (Object.keys(targets).length) edits[section] = targets;
      }
      return edits;
    },

    count() {
      return (game?.sections ?? []).reduce((sum, section) => sum + translatedCount(section), 0);
    },

    // Merge targets read from files into rows not translated yet: the
    // translator's own work is never overwritten.
    // Returns { added, kept } counts.
    async importEdits(edits) {
      let added = 0;
      let kept = 0;
      for (const [section, targets] of Object.entries(edits)) {
        const rows = { ...rowsOf(section) };
        for (const [index, target] of Object.entries(targets)) {
          const current = rows[index]?.target;
          if (current) {
            if (current !== target) kept += 1;
            continue;
          }
          rows[index] = { target, source: section === xpath ? sources[index] : null };
          added += 1;
        }
        saved.set(section, rows);
        await saveSection(section, rows);
      }
      renderSectionOptions();
      onChange();
      const first = Object.keys(edits)[0];
      if (first) await openSection(first);
      return { added, kept };
    },

    async exportZip() {
      return call("exportEdits", { name: game.name, edits: this.edits() });
    },

    // Re-run checks, e.g. after the folding option changed.
    async recheck() {
      if (!xpath) return;
      await check(Object.keys(rowsOf(xpath)).map(Number).filter((i) => i < sources.length));
      render();
    },

    // Re-render text after a language switch.
    relabel() {
      if (!game) return;
      renderSectionOptions();
      render();
    },
  };
}
