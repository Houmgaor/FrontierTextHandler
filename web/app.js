// Page logic: forwards user files to the Pyodide worker and offers the
// results as downloads.

const $ = (id) => document.getElementById(id);

const worker = new Worker("worker.js", { type: "module" });
const pending = new Map();
let nextId = 0;
let gameFile = null; // Summary returned by the worker's "load" command.

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
  const time = new Date().toLocaleTimeString();
  const output = $("log");
  output.textContent += `[${time}] ${message}\n`;
  output.scrollTop = output.scrollHeight;
}

// Runs *task* while showing an elapsed-time counter and locking inputs,
// since the slow steps take up to a couple of minutes on mhfdat.bin.
async function busy(label, task) {
  const status = $("busy");
  const controls = document.querySelectorAll("main input, main button");
  const previous = new Map([...controls].map((el) => [el, el.disabled]));
  controls.forEach((el) => (el.disabled = true));
  const start = performance.now();
  const tick = () => {
    status.textContent = `${label}… ${Math.round((performance.now() - start) / 1000)} s`;
  };
  tick();
  status.hidden = false;
  status.classList.remove("error");
  const timer = setInterval(tick, 1000);
  try {
    const result = await task();
    const seconds = ((performance.now() - start) / 1000).toFixed(1);
    status.textContent = `${label}: done in ${seconds} s`;
    return result;
  } catch (error) {
    status.textContent = `${label} failed: ${error.message}`;
    status.classList.add("error");
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
  return bytes >= 1e6 ? `${(bytes / 1e6).toFixed(1)} MB` : `${Math.round(bytes / 1e3)} KB`;
}

function selectedSections() {
  return [...document.querySelectorAll("#sections input:checked")].map((el) => el.value);
}

function updateSelectedCount() {
  const count = selectedSections().length;
  $("selected-count").textContent = `${count} selected`;
  $("extract").disabled = count === 0;
}

function renderSections(sections) {
  const container = $("sections");
  container.replaceChildren(
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

async function openGameFile(file) {
  const data = await file.arrayBuffer();
  gameFile = await busy(`Opening ${file.name}`, () =>
    call("load", { name: file.name, data }, [data]),
  );
  const layers = [gameFile.encrypted && "encrypted", gameFile.compressed && "compressed"]
    .filter(Boolean)
    .join(" and ");
  $("file-info").textContent =
    `${gameFile.name}: ${layers || "plain"} file, ${formatSize(gameFile.decoded_size)} ` +
    `decoded, ${gameFile.sections.length} text sections.`;
  renderSections(gameFile.sections);
  $("step-extract").hidden = false;
  $("step-build").hidden = false;
  $("translations").value = "";
  $("translation-list").replaceChildren();
  $("build").disabled = true;
}

async function extractText() {
  const xpaths = selectedSections();
  const result = await busy(`Extracting ${xpaths.length} section(s)`, () =>
    call("extract", { name: gameFile.name, xpaths }),
  );
  const stem = gameFile.name.replace(/\.bin$/i, "");
  download(result.zip, `${stem}-text.zip`, "application/zip");
  if (result.failed.length) log(`Skipped: ${result.failed.join(", ")}`);
}

function listTranslations(files) {
  $("translation-list").replaceChildren(
    ...[...files].map((file) => Object.assign(document.createElement("li"), { textContent: file.name })),
  );
  $("build").disabled = files.length === 0;
}

async function buildGameFile() {
  const files = [...$("translations").files];
  const translations = await Promise.all(
    files.map(async (file) => ({ name: file.name, data: await file.arrayBuffer() })),
  );
  const options = {
    fold: $("opt-fold").checked,
    compress: $("opt-compress").checked,
    encrypt: $("opt-encrypt").checked,
  };
  const result = await busy(`Building ${gameFile.name}`, () =>
    call("build", { name: gameFile.name, translations, options }, translations.map((t) => t.data)),
  );
  if (result.unchanged.length) log(`No changes from: ${result.unchanged.join(", ")}`);
  if (result.applied.length === 0) {
    const status = $("busy");
    status.textContent =
      "Nothing to build: no filled-in target column in these files, " +
      "or the translations match the game file already.";
    status.classList.add("error");
    return;
  }
  download(result.data, gameFile.name);
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
$("translations").addEventListener("change", (event) => listTranslations(event.target.files));
$("build").addEventListener("click", quietly(buildGameFile));

busy("Loading the Python engine", () => call("init"))
  .then(({ pyodide, tool }) => {
    $("engine").textContent = "Ready.";
    $("versions").textContent = `${tool} (Pyodide ${pyodide})`;
    $("game-file").disabled = false;
  })
  .catch((error) => {
    $("engine").textContent = `The Python engine could not start: ${error.message}`;
    $("engine").classList.add("error");
  });
