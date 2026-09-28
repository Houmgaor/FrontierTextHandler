// The editor's work, kept in this browser (IndexedDB), one record per
// section: xpath -> { index: { target, source } }. The source recorded
// with each target shows when a later game file changed the original text.
//
// Browsers can refuse storage (private windows, blocked site data). The
// page then keeps the work in memory only and says so; downloading the
// translations is the way to keep it.

const DATABASE = "frontier-text-handler";
const SECTIONS = "sections";

let database = null; // IDBDatabase, or null when storage is unavailable.
const memory = new Map(); // Fallback store.

function request(req) {
  return new Promise((resolve, reject) => {
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

// Resolves to true when the work will persist in this browser.
export async function openStore() {
  try {
    const open = indexedDB.open(DATABASE, 1);
    open.onupgradeneeded = () => open.result.createObjectStore(SECTIONS);
    database = await request(open);
    return true;
  } catch {
    database = null;
    return false;
  }
}

function sections(mode) {
  return database.transaction(SECTIONS, mode).objectStore(SECTIONS);
}

// Every saved section of one game file type ("dat", "pac", …).
export async function loadSections(fileType) {
  const found = new Map();
  if (!database) {
    for (const [xpath, rows] of memory) {
      if (xpath.startsWith(`${fileType}/`)) found.set(xpath, rows);
    }
    return found;
  }
  const range = IDBKeyRange.bound(`${fileType}/`, `${fileType}/￿`);
  const store = sections("readonly");
  const [keys, values] = await Promise.all([
    request(store.getAllKeys(range)),
    request(store.getAll(range)),
  ]);
  keys.forEach((key, i) => found.set(key, values[i]));
  return found;
}

export async function saveSection(xpath, rows) {
  const empty = Object.keys(rows).length === 0;
  if (!database) {
    if (empty) memory.delete(xpath);
    else memory.set(xpath, rows);
    return;
  }
  const store = sections("readwrite");
  await request(empty ? store.delete(xpath) : store.put(rows, xpath));
}
