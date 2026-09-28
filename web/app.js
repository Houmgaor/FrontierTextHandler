// Page logic: forwards user files to the Pyodide worker and offers the
// results as downloads.

import { createEditor } from "./editor.js";
import { currentLanguage, setLanguage, t } from "./i18n.js";

const $ = (id) => document.getElementById(id);

const worker = new Worker("worker.js", { type: "module" });
const pending = new Map();
let nextId = 0;
let gameFile = null; // Summary returned by the worker's "load" command.
let staged = []; // Translation files as described by the worker's "stage" command.

worker.onmessage = ({ data }) => {
  if (data.type === "log") {
    log(data.message);
    return;
  }
  const { resolve, reject } = pending.get(data.id);
  pending.delete(data.id);
  data.ok ? resolve(data.result) : reject(new Error(data.error));
};

function call(command, args = {}, transfer = []) {
  const id = nextId++;
  return new Promise((resolve, reject) => {
    pending.set(id, { resolve, reject });
    worker.postMessage({ id, command, args }, transfer);
  });
}

function log(message) {
  const time = new Date().toLocaleTimeString(currentLanguage());
  const output = $("log");
  output.textContent += `[${time}] ${message}\n`;
  output.scrollTop = output.scrollHeight;
}

function showStatus(text, isError = false) {
  const status = $("busy");
  status.hidden = false;
  status.textContent = text;
  status.classList.toggle("error", isError);
}

// Runs *task* while showing an elapsed-time counter and locking inputs,
// since the slow steps take up to a couple of minutes on mhfdat.bin.
async function busy(label, task) {
  const controls = document.querySelectorAll("main input, main button, main select, main textarea");
  const previous = new Map([...controls].map((el) => [el, el.disabled]));
  controls.forEach((el) => (el.disabled = true));
  const start = performance.now();
  const seconds = (digits) =>
    ((performance.now() - start) / 1000).toLocaleString(currentLanguage(), {
      minimumFractionDigits: digits,
      maximumFractionDigits: digits,
    });
  const tick = () => showStatus(t("busy.running", { label, seconds: seconds(0) }));
  tick();
  const timer = setInterval(tick, 1000);
  try {
    const result = await task();
    showStatus(t("busy.done", { label, seconds: seconds(1) }));
    return result;
  } catch (error) {
    showStatus(t("busy.failed", { label, error: error.message }), true);
    log(`error: ${error.message}`);
    throw error;
  } finally {
    clearInterval(timer);
    previous.forEach((disabled, el) => (el.disabled = disabled));
  }
}

function download(bytes, fileName, type = "application/octet-stream") {
  const url = URL.createObjectURL(new Blob([bytes], { type }));
  const link = Object.assign(document.createElement("a"), { href: url, download: fileName });
  link.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function formatSize(bytes) {
  const format = (value, digits) =>
    value.toLocaleString(currentLanguage(), { maximumFractionDigits: digits });
  return bytes >= 1e6
    ? t("unit.mb", { value: format(bytes / 1e6, 1) })
    : t("unit.kb", { value: format(bytes / 1e3, 0) });
}

// ---- Step 1: open a game file ----

function renderFileInfo() {
  if (!gameFile) return;
  const layers =
    gameFile.encrypted && gameFile.compressed ? "both"
      : gameFile.encrypted ? "encrypted"
        : gameFile.compressed ? "compressed" : "plain";
  $("file-info").textContent = t("file.info", {
    name: gameFile.name,
    layers: t(`file.layers.${layers}`),
    size: formatSize(gameFile.decoded_size),
    count: gameFile.sections.length,
  });
}

async function openGameFile(file) {
  const data = await file.arrayBuffer();
  gameFile = await busy(t("busy.open", { name: file.name }), () =>
    call("load", { name: file.name, data }, [data]),
  );
  renderFileInfo();
  renderSections(gameFile.sections);
  $("step-translate").hidden = false;
  $("step-build").hidden = false;
  $("translations").value = "";
  staged = [];
  renderTranslations();
  $("build").disabled = false; // The editor alone can provide translations.
  await editor.open(gameFile);
  renderIncluded();
}

// ---- Step 2: translate in the page, or as files ----

const editor = createEditor({
  call,
  busy,
  t,
  getFold: () => $("opt-fold").checked,
  onChange: () => renderIncluded(),
});

function showTab(tab) {
  for (const name of ["editor", "files"]) {
    $(`tab-${name}`).setAttribute("aria-selected", String(name === tab));
    $(`tab-${name}`).setAttribute("aria-pressed", String(name === tab));
    $(`panel-${name}`).hidden = name !== tab;
  }
}

async function exportEdits() {
  const result = await busy(t("busy.exportEdits"), () => editor.exportZip());
  const stem = gameFile.name.replace(/\.bin$/i, "");
  download(result.zip, `${stem}-translations.zip`, "application/zip");
}

// ---- Step 2: extract text ----

function selectedSections() {
  return [...document.querySelectorAll("#sections input:checked")].map((el) => el.value);
}

function updateSelectedCount() {
  const count = selectedSections().length;
  $("selected-count").textContent = t("step2.selected", { count });
  $("extract").disabled = count === 0;
}

function renderSections(sections) {
  $("sections").replaceChildren(
    ...sections.map((xpath) => {
      const label = document.createElement("label");
      const box = Object.assign(document.createElement("input"), {
        type: "checkbox",
        value: xpath,
        checked: true,
      });
      label.append(box, xpath);
      return label;
    }),
  );
  updateSelectedCount();
}

function setAllSections(checked) {
  document.querySelectorAll("#sections input").forEach((el) => (el.checked = checked));
  updateSelectedCount();
}

async function extractText() {
  const xpaths = selectedSections();
  const result = await busy(t("busy.extract", { count: xpaths.length }), () =>
    call("extract", { name: gameFile.name, xpaths }),
  );
  const stem = gameFile.name.replace(/\.bin$/i, "");
  download(result.zip, `${stem}-text.zip`, "application/zip");
  if (result.failed.length) log(t("log.skipped", { list: result.failed.join(", ") }));
}

// ---- Step 3: build the translated file ----

// Default release language: the page's, else the one with the most
// sections for this game file.
function defaultReleaseLanguage(languages) {
  if ((languages[currentLanguage()] ?? 0) > 0) return currentLanguage();
  return Object.entries(languages).sort((a, b) => b[1] - a[1])[0]?.[0];
}

function renderTranslations() {
  const items = staged.map((item) => {
    const li = document.createElement("li");
    if (item.kind !== "release") {
      li.textContent = item.name;
      return li;
    }
    const select = document.createElement("select");
    select.dataset.release = item.name;
    const label = t("step3.release", { name: item.name });
    select.setAttribute("aria-label", label);
    for (const [lang, count] of Object.entries(item.languages)) {
      select.append(new Option(t("step3.releaseOption", { lang, count }), lang));
    }
    select.value = item.language ?? defaultReleaseLanguage(item.languages);
    select.addEventListener("change", () => (item.language = select.value));
    item.language = select.value;
    li.append(`${label} `, select);
    return li;
  });
  $("translation-list").replaceChildren(...items);
  $("open-in-editor").hidden = staged.length === 0;
}

function renderIncluded() {
  const count = editor.count();
  $("editor-included").textContent = count ? t("step3.editorIncluded", { count }) : "";
}

function releaseLanguages() {
  return Object.fromEntries(
    staged.filter((item) => item.kind === "release").map((item) => [item.name, item.language]),
  );
}

async function openInEditor() {
  const result = await busy(t("busy.readEdits"), () =>
    call("readEdits", {
      name: gameFile.name,
      translations: staged.map((item) => item.name),
      releaseLanguages: releaseLanguages(),
    }),
  );
  for (const { name, reason } of result.skipped) {
    log(t(`log.skipped.${reason}`, { name }));
  }
  const { added, kept } = await editor.importEdits(result.edits);
  showTab("editor");
  showStatus(t("step3.opened", { count: added }) + (kept ? ` ${t("step3.kept", { count: kept })}` : ""));
  $("step-translate").scrollIntoView({ behavior: "smooth" });
}

async function stageTranslations(files) {
  const translations = await Promise.all(
    [...files].map(async (file) => ({ name: file.name, data: await file.arrayBuffer() })),
  );
  staged = await busy(t("busy.stage"), () =>
    call("stage", { name: gameFile.name, translations }, translations.map((f) => f.data)),
  );
  renderTranslations();
}

async function buildGameFile() {
  const options = {
    fold: $("opt-fold").checked,
    compress: $("opt-compress").checked,
    encrypt: $("opt-encrypt").checked,
  };
  const result = await busy(t("busy.build", { name: gameFile.name }), () =>
    call("build", {
      name: gameFile.name,
      translations: staged.map((item) => item.name),
      releaseLanguages: releaseLanguages(),
      edits: editor.edits(),
      options,
    }),
  );
  if (result.unchanged.length) log(t("log.unchanged", { list: result.unchanged.join(", ") }));
  if (result.applied.length === 0) {
    showStatus(t("step3.nothing"), true);
    return;
  }
  download(result.data, gameFile.name);
}

// ---- Language ----

function switchLanguage(language) {
  setLanguage(language);
  // Text built from data rather than markup is rendered again.
  renderFileInfo();
  if (gameFile) updateSelectedCount();
  renderTranslations();
  editor.relabel();
  renderIncluded();
}

// Errors are already shown by busy(); this keeps them out of the console
// as unhandled rejections.
const quietly = (task) => (...args) => task(...args).catch(() => {});

$("game-file").addEventListener("change", quietly(async (event) => {
  const [file] = event.target.files;
  if (file) await openGameFile(file);
}));
$("sections").addEventListener("change", updateSelectedCount);
$("select-all").addEventListener("click", () => setAllSections(true));
$("select-none").addEventListener("click", () => setAllSections(false));
$("extract").addEventListener("click", quietly(extractText));
$("translations").addEventListener("change", quietly(async (event) => {
  if (event.target.files.length) await stageTranslations(event.target.files);
}));
$("build").addEventListener("click", quietly(buildGameFile));
$("open-in-editor").addEventListener("click", quietly(openInEditor));
$("editor-export").addEventListener("click", quietly(exportEdits));
$("tab-editor").addEventListener("click", () => showTab("editor"));
$("tab-files").addEventListener("click", () => showTab("files"));
$("opt-fold").addEventListener("change", () => editor.recheck().catch(() => {}));
document.querySelectorAll("[data-language]").forEach((button) =>
  button.addEventListener("click", () => switchLanguage(button.dataset.language)),
);

setLanguage(currentLanguage());
showTab("editor");

busy(t("busy.engine"), () => call("init"))
  .then(({ pyodide, tool }) => {
    $("engine").dataset.i18n = "engine.ready";
    $("engine").textContent = t("engine.ready");
    $("versions").textContent = `${tool} (Pyodide ${pyodide})`;
    $("game-file").disabled = false;
  })
  .catch((error) => {
    delete $("engine").dataset.i18n;
    $("engine").textContent = t("engine.failed", { error: error.message });
    $("engine").classList.add("error");
  });
