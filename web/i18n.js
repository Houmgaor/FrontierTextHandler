// Interface text in English and French. Elements carry data-i18n="key"
// (plain text) or data-i18n-html="key" (trusted markup from this file).
// Values are strings with {placeholders}, or functions for plurals.

const RELEASES_URL = "https://github.com/Mogapedia/MHFrontier-Translation/releases";
const NBSP = " "; // French typography: non-breaking space before ":".

const messages = {
  en: {
    "language": "Language",
    "notice.intro": "Extract the game's text for translation, then put your translations back into a game-ready file.",
    "notice.privacy": "Everything runs in this browser tab. Your game files are never uploaded.",
    "engine.loading": "Loading the Python engine…",
    "engine.ready": "Ready.",
    "engine.failed": "The Python engine could not start: {error}",

    "step1.title": "Open a game file",
    "step1.help": "Pick <code>mhfdat.bin</code>, <code>mhfpac.bin</code>, <code>mhfinf.bin</code> or another text file from your game's <code>dat/</code> folder. Large files such as <code>mhfdat.bin</code> take about a minute to open.",
    "step1.choose": "Choose a game file",
    "file.info": "{name}: {layers} file, {size} decoded, {count} text sections.",
    "file.layers.both": "encrypted and compressed",
    "file.layers.encrypted": "encrypted",
    "file.layers.compressed": "compressed",
    "file.layers.plain": "plain",
    "unit.mb": "{value} MB",
    "unit.kb": "{value} KB",

    "step2.title": "Extract text",
    "step2.help": "Download the sections you want to translate as CSV and JSON files. Fill in the <code>target</code> column and leave rows you are not translating empty.",
    "step2.selectAll": "Select all",
    "step2.selectNone": "Select none",
    "step2.selected": "{count} selected",
    "step2.download": "Download text (.zip)",

    "step3.title": "Build the translated file",
    "step3.help": `Add your translated CSV or JSON files, or a translation release from <a href="${RELEASES_URL}">MHFrontier-Translation</a> (<code>translations-fr.json.gz</code>, for instance). They must match the game file you opened in step 1.`,
    "step3.choose": "Choose translation files",
    "step3.release": "{name}: translation release, language",
    "step3.releaseOption": ({ lang, count }) =>
      `${lang} (${count} section${count === 1 ? "" : "s"} for this file)`,
    "step3.options": "Options",
    "step3.fold": "Replace characters the game font cannot show (é → e, œ → oe, « → \")",
    "step3.compress": "Compress (needed by the game)",
    "step3.encrypt": "Encrypt (needed by the game)",
    "step3.build": "Build and download",
    "step3.hint": "Replace the file in your game's <code>dat/</code> folder with the download. Keep a backup of the original.",
    "step3.nothing": "Nothing to build: no filled-in target column in these files, or the translations match the game file already.",

    "activity.title": "Activity",
    "activity.empty": "Nothing yet.",
    "footer.disclaimer": "A community tool. Not affiliated with the game's publisher.",

    "busy.engine": "Loading the Python engine",
    "busy.open": "Opening {name}",
    "busy.extract": "Extracting {count} section(s)",
    "busy.stage": "Reading translation files",
    "busy.build": "Building {name}",
    "busy.running": "{label}… {seconds} s",
    "busy.done": "{label}: done in {seconds} s",
    "busy.failed": "{label} failed: {error}",

    "log.skipped": "Skipped: {list}",
    "log.unchanged": "No changes from: {list}",
  },

  fr: {
    "language": "Langue",
    "notice.intro": "Extrayez les textes du jeu pour les traduire, puis réinjectez vos traductions dans un fichier prêt à jouer.",
    "notice.privacy": `Tout se passe dans cet onglet${NBSP}: vos fichiers de jeu ne sont jamais envoyés en ligne.`,
    "engine.loading": "Chargement du moteur Python…",
    "engine.ready": "Prêt.",
    "engine.failed": `Le moteur Python n'a pas pu démarrer${NBSP}: {error}`,

    "step1.title": "Ouvrir un fichier du jeu",
    "step1.help": "Choisissez <code>mhfdat.bin</code>, <code>mhfpac.bin</code>, <code>mhfinf.bin</code> ou un autre fichier de textes du dossier <code>dat/</code> de votre jeu. Les gros fichiers comme <code>mhfdat.bin</code> mettent environ une minute à s'ouvrir.",
    "step1.choose": "Choisir un fichier du jeu",
    "file.info": `{name}${NBSP}: fichier {layers}, {size} une fois décodé, {count} sections de texte.`,
    "file.layers.both": "chiffré et compressé",
    "file.layers.encrypted": "chiffré",
    "file.layers.compressed": "compressé",
    "file.layers.plain": "brut",
    "unit.mb": `{value}${NBSP}Mo`,
    "unit.kb": `{value}${NBSP}ko`,

    "step2.title": "Extraire les textes",
    "step2.help": "Téléchargez les sections à traduire au format CSV et JSON. Remplissez la colonne <code>target</code> et laissez vides les lignes que vous ne traduisez pas.",
    "step2.selectAll": "Tout sélectionner",
    "step2.selectNone": "Tout désélectionner",
    "step2.selected": ({ count }) => `${count} sélectionnée${count > 1 ? "s" : ""}`,
    "step2.download": "Télécharger les textes (.zip)",

    "step3.title": "Générer le fichier traduit",
    "step3.help": `Ajoutez vos fichiers CSV ou JSON traduits, ou une version publiée de <a href="${RELEASES_URL}">MHFrontier-Translation</a> (par exemple <code>translations-fr.json.gz</code>). Ils doivent correspondre au fichier ouvert à l'étape 1.`,
    "step3.choose": "Choisir les fichiers de traduction",
    "step3.release": `{name}${NBSP}: version publiée, langue`,
    "step3.releaseOption": ({ lang, count }) =>
      `${lang} (${count} section${count > 1 ? "s" : ""} pour ce fichier)`,
    "step3.options": "Options",
    "step3.fold": "Remplacer les caractères que la police du jeu ne sait pas afficher (é → e, œ → oe, « → \")",
    "step3.compress": "Compresser (requis par le jeu)",
    "step3.encrypt": "Chiffrer (requis par le jeu)",
    "step3.build": "Générer et télécharger",
    "step3.hint": "Remplacez le fichier du dossier <code>dat/</code> de votre jeu par celui téléchargé. Gardez une copie de l'original.",
    "step3.nothing": `Rien à générer${NBSP}: aucune colonne target remplie dans ces fichiers, ou les traductions correspondent déjà au fichier du jeu.`,

    "activity.title": "Journal",
    "activity.empty": "Rien pour l'instant.",
    "footer.disclaimer": "Outil communautaire, sans lien avec l'éditeur du jeu.",

    "busy.engine": "Chargement du moteur Python",
    "busy.open": "Ouverture de {name}",
    "busy.extract": "Extraction de {count} section(s)",
    "busy.stage": "Lecture des fichiers de traduction",
    "busy.build": "Génération de {name}",
    "busy.running": "{label}… {seconds} s",
    "busy.done": `{label}${NBSP}: terminé en {seconds} s`,
    "busy.failed": `{label}${NBSP}: échec — {error}`,

    "log.skipped": `Ignorées${NBSP}: {list}`,
    "log.unchanged": `Aucun changement apporté par${NBSP}: {list}`,
  },
};

export const LANGUAGES = Object.keys(messages);
const STORAGE_KEY = "fth-language";

function initialLanguage() {
  try {
    const saved = localStorage.getItem(STORAGE_KEY);
    if (LANGUAGES.includes(saved)) return saved;
  } catch {
    // Storage can be unavailable (private mode, blocked site data).
  }
  const preferred = navigator.languages ?? [navigator.language];
  return preferred.some((tag) => tag?.toLowerCase().startsWith("fr")) ? "fr" : "en";
}

let language = initialLanguage();

export const currentLanguage = () => language;

export function t(key, vars = {}) {
  const value = messages[language][key] ?? messages.en[key] ?? key;
  if (typeof value === "function") return value(vars);
  return value.replace(/\{(\w+)\}/g, (match, name) => (name in vars ? vars[name] : match));
}

// Translate every marked element and remember the choice.
export function setLanguage(next) {
  language = LANGUAGES.includes(next) ? next : "en";
  try {
    localStorage.setItem(STORAGE_KEY, language);
  } catch {
    // Not remembered, but the page still switches.
  }
  document.documentElement.lang = language;
  document.querySelectorAll("[data-i18n]").forEach((el) => {
    el.textContent = t(el.dataset.i18n);
  });
  document.querySelectorAll("[data-i18n-html]").forEach((el) => {
    el.innerHTML = t(el.dataset.i18nHtml);
  });
  document.querySelectorAll("[data-i18n-attr]").forEach((el) => {
    const [attribute, key] = el.dataset.i18nAttr.split(":");
    el.setAttribute(attribute, t(key));
  });
  document.querySelectorAll("[data-language]").forEach((el) => {
    el.setAttribute("aria-pressed", String(el.dataset.language === language));
  });
}
