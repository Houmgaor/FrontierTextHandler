// Sections of a game file, grouped by folder for menus and lists.
//
// A file can have hundreds of sections (mhfpac.bin: ~900 pac/text_<offset>),
// so they are grouped by their parent path ("pac", "pac/skills", ...) and
// sorted naturally: pac/text_98 before pac/text_103c, as the suffix is a
// hex offset.

const HEX_TABLE = /^text_([0-9a-f]+)$/;

function segmentKey(segment) {
  const hex = HEX_TABLE.exec(segment);
  // Named entries first, then hex-offset tables in offset order.
  return hex ? [1, parseInt(hex[1], 16), ""] : [0, 0, segment];
}

function compareXpaths(a, b) {
  const as = a.split("/");
  const bs = b.split("/");
  for (let i = 0; i < Math.min(as.length, bs.length); i++) {
    const [ak, an, at] = segmentKey(as[i]);
    const [bk, bn, bt] = segmentKey(bs[i]);
    const order = ak - bk || an - bn
      || at.localeCompare(bt, undefined, { numeric: true });
    if (order) return order;
  }
  return as.length - bs.length;
}

export const parentOf = (xpath) => xpath.slice(0, xpath.lastIndexOf("/"));
export const leafOf = (xpath) => xpath.slice(xpath.lastIndexOf("/") + 1);

// [[parent path, [xpath, ...]], ...], groups and members sorted.
export function groupSections(sections) {
  const groups = new Map();
  for (const xpath of [...sections].sort(compareXpaths)) {
    const parent = parentOf(xpath);
    if (!groups.has(parent)) groups.set(parent, []);
    groups.get(parent).push(xpath);
  }
  return [...groups].sort(([a], [b]) => compareXpaths(a, b));
}
