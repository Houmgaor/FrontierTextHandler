// Runs FrontierTextHandler in Pyodide, off the main thread so the page
// stays responsive during the slow decrypt/compress steps.
import { loadPyodide } from "https://cdn.jsdelivr.net/pyodide/v314.0.7/full/pyodide.mjs";

const IN_DIR = "/work/in";
const TRANSLATION_DIR = "/work/translations";

const log = (message) => postMessage({ type: "log", message });

const ready = (async () => {
  const py = await loadPyodide();
  const archive = await fetch("app.zip");
  if (!archive.ok) throw new Error(`Could not download app.zip (${archive.status})`);
  py.unpackArchive(await archive.arrayBuffer(), "zip", { extractDir: "/app" });
  py.runPython("import sys; sys.path.insert(0, '/app')");
  for (const dir of [IN_DIR, TRANSLATION_DIR]) py.FS.mkdirTree(dir);
  const bridge = py.pyimport("bridge");
  bridge.set_reporter(log);
  const toolVersion = py.pyimport("src").__version__;
  return { py, bridge, toolVersion };
})();

// Python dicts become plain objects, lists arrays, bytes Uint8Array.
function toJs(proxy) {
  const value = proxy.toJs({ dict_converter: Object.fromEntries });
  proxy.destroy();
  return value;
}

function clearDir(py, dir) {
  for (const entry of py.FS.readdir(dir)) {
    if (entry !== "." && entry !== "..") py.FS.unlink(`${dir}/${entry}`);
  }
}

const commands = {
  async init({ py, toolVersion }) {
    return { pyodide: py.version, tool: toolVersion };
  },

  async load({ py, bridge }, { name, data }) {
    py.FS.writeFile(`${IN_DIR}/${name}`, new Uint8Array(data));
    return toJs(bridge.load_game_file(name));
  },

  async extract({ py, bridge }, { name, xpaths }) {
    return toJs(bridge.extract(name, py.toPy(xpaths)));
  },

  async stage({ py, bridge }, { name, translations }) {
    clearDir(py, TRANSLATION_DIR);
    for (const file of translations) {
      py.FS.writeFile(`${TRANSLATION_DIR}/${file.name}`, new Uint8Array(file.data));
    }
    return toJs(bridge.stage_translations(name, py.toPy(translations.map((f) => f.name))));
  },

  async build({ py, bridge }, { name, translations, releaseLanguages, options }) {
    return toJs(
      bridge.build.callKwargs(name, py.toPy(translations), {
        release_languages: py.toPy(releaseLanguages),
        compress: options.compress,
        encrypt_output: options.encrypt,
        fold_unsupported_chars: options.fold,
      }),
    );
  },
};

onmessage = async ({ data: { id, command, args } }) => {
  try {
    const context = await ready;
    const result = await commands[command](context, args);
    const transfer = [result?.zip, result?.data]
      .filter((value) => value instanceof Uint8Array)
      .map((value) => value.buffer);
    postMessage({ type: "result", id, ok: true, result }, transfer);
  } catch (error) {
    const text = String(error?.message ?? error).trim();
    // Python tracebacks end with the exception line, which is what the
    // user needs; the full traceback goes to the log for bug reports.
    if (text.includes("\n")) log(text);
    postMessage({ type: "result", id, ok: false, error: text.split("\n").pop() });
  }
};
