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
    "step1.help": "Pick <code>mhfdat.bin</code>, <code>mhfpac.bin</code>, <code>mhfinf.bin</code> or another text file from your game's <code>dat/</code> folder.",
    "step1.choose": "Choose a game file",
    "file.info": "{name}: {layers} file, {size} decoded, {count} text sections.",
    "file.layers.both": "encrypted and compressed",
    "file.layers.encrypted": "encrypted",
    "file.layers.compressed": "compressed",
    "file.layers.plain": "plain",
    "unit.mb": "{value} MB",
    "unit.kb": "{value} KB",

    "step2.title": "Translate",
    "step2.tabEditor": "In this page",
    "step2.tabFiles": "As files",
    "editor.help": "Type your translation under each original text. Keep markers such as <code>{c05}</code> and <code>{j}</code> where they belong. Your work is saved in this browser and included when you build in step 3.",
    "editor.section": "Section",
    "editor.search": "Search",
    "editor.show": "Show",
    "editor.filterAll": "All",
    "editor.filterTodo": "To translate",
    "editor.filterDone": "Translated",
    "editor.filterWarnings": "With warnings",
    "editor.page": "Page",
    "editor.pageOf": "of {pages}",
    "editor.previous": "Previous page",
    "editor.next": "Next page",
    "editor.export": "Download my translations (.zip)",
    "editor.saving": "Saving…",
    "editor.saved": "Saved in this browser.",
    "editor.notSaved": "This browser does not allow saving: download your translations to keep them.",
    "editor.translatedShort": "{count} translated",
    "editor.progress": ({ done, total, warnings }) =>
      `${done} of ${total} translated` + (warnings ? `, ${warnings} with warnings.` : "."),
    "editor.emptySource": "(empty)",
    "editor.targetLabel": "Translation of #{index}",
    "editor.noMatch": "No text matches.",
    "editor.emptySection": "This section has no text.",
    "editor.issue.placeholder": ({ marker, source, target }) =>
      `Marker ${marker}: ${source} in the original, ${target} here.`,
    "editor.issue.folded": "Shown in game as: {text}",
    "editor.issue.unencodable": "The game cannot show: {chars}",
    "editor.issue.width": "Too long: {width} characters, the limit is {max}.",
    "editor.issue.widthPart": "Part {part} too long: {width} characters, the limit is {max}.",
    "editor.issue.subs": "{count} parts separated by {j}, the limit is {max}.",
    "editor.issue.sourceChanged": "The original text changed since this was translated.",
    "step3.openInEditor": "Open in the editor",
    "step3.editorIncluded": ({ count }) =>
      `${count.toLocaleString("en")} translation${count === 1 ? "" : "s"} from the editor will be included.`,
    "step3.opened": ({ count }) =>
      `${count.toLocaleString("en")} translation${count === 1 ? "" : "s"} opened in the editor.`,
    "step3.kept": ({ count }) =>
      `${count.toLocaleString("en")} already translated in the editor ${count === 1 ? "was" : "were"} kept.`,
    "busy.section": "Opening {xpath}",
    "busy.exportEdits": "Preparing your translations",
    "busy.readEdits": "Reading translation files",
    "log.skipped.legacy": "{name}: old offset-keyed format, cannot be opened in the editor (it still applies when you build).",
    "log.skipped.other_file": "{name}: belongs to another game file.",
    "log.skipped.unknown_section": "{name}: section not recognised.",
    "step2.help": "Download the sections you want to translate as CSV and JSON files. Fill in the <code>target</code> column and leave rows you are not translating empty.",
    "step2.selectAll": "Select all",
    "step2.selectNone": "Select none",
    "step2.selected": "{count} selected",
    "step2.download": "Download text (.zip)",

    "step3.title": "Build the translated file",
    "step3.help": `Translations from the editor are included. You can also add translated CSV or JSON files, or a translation release from <a href="${RELEASES_URL}">MHFrontier-Translation</a> (<code>translations-fr.json.gz</code>, for instance). They must match the game file you opened in step 1.`,
    "step3.choose": "Choose translation files",
    "step3.release": "{name}: translation release, language",
    "step3.releaseOption": ({ lang, count }) =>
      `${lang} (${count} section${count === 1 ? "" : "s"} for this file)`,
    "step3.options": "Options",
    "step3.fold": "Replace characters the game font cannot show (é → e, œ → oe, « → \")",
    "step3.compress": "Compress (needed by the game)",
    "step3.encrypt": "Encrypt (needed by the game)",
    "step3.build": "Build and download",
    "step3.hint": "Building <code>mhfdat.bin</code> takes about 40 seconds, smaller files a few seconds. Replace the file in your game's <code>dat/</code> folder with the download, and keep a backup of the original.",
    "step3.nothing": "Nothing to build: no translation in the editor or in these files, or they match the game file already.",

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
    "step1.help": "Choisissez <code>mhfdat.bin</code>, <code>mhfpac.bin</code>, <code>mhfinf.bin</code> ou un autre fichier de textes du dossier <code>dat/</code> de votre jeu.",
    "step1.choose": "Choisir un fichier du jeu",
    "file.info": `{name}${NBSP}: fichier {layers}, {size} une fois décodé, {count} sections de texte.`,
    "file.layers.both": "chiffré et compressé",
    "file.layers.encrypted": "chiffré",
    "file.layers.compressed": "compressé",
    "file.layers.plain": "brut",
    "unit.mb": `{value}${NBSP}Mo`,
    "unit.kb": `{value}${NBSP}ko`,

    "step2.title": "Traduire",
    "step2.tabEditor": "Dans la page",
    "step2.tabFiles": "En fichiers",
    "editor.help": "Saisissez votre traduction sous chaque texte original. Gardez les balises comme <code>{c05}</code> et <code>{j}</code> à leur place. Votre travail est enregistré dans ce navigateur et inclus lors de la génération à l'étape 3.",
    "editor.section": "Section",
    "editor.search": "Rechercher",
    "editor.show": "Afficher",
    "editor.filterAll": "Tout",
    "editor.filterTodo": "À traduire",
    "editor.filterDone": "Traduits",
    "editor.filterWarnings": "Avec avertissements",
    "editor.page": "Page",
    "editor.pageOf": "sur {pages}",
    "editor.previous": "Page précédente",
    "editor.next": "Page suivante",
    "editor.export": "Télécharger mes traductions (.zip)",
    "editor.saving": "Enregistrement…",
    "editor.saved": "Enregistré dans ce navigateur.",
    "editor.notSaved": `Ce navigateur ne permet pas d'enregistrer${NBSP}: téléchargez vos traductions pour les conserver.`,
    "editor.translatedShort": ({ count }) => `${count} traduit${count > 1 ? "s" : ""}`,
    "editor.progress": ({ done, total, warnings }) =>
      `${done} sur ${total} traduits`
      + (warnings ? `, dont ${warnings} avec avertissement${warnings > 1 ? "s" : ""}.` : "."),
    "editor.emptySource": "(vide)",
    "editor.targetLabel": "Traduction de #{index}",
    "editor.noMatch": "Aucun texte ne correspond.",
    "editor.emptySection": "Cette section ne contient aucun texte.",
    "editor.issue.placeholder": ({ marker, source, target }) =>
      `Balise ${marker}${NBSP}: ${source} dans l'original, ${target} ici.`,
    "editor.issue.folded": `Affiché en jeu${NBSP}: {text}`,
    "editor.issue.unencodable": `Le jeu ne peut pas afficher${NBSP}: {chars}`,
    "editor.issue.width": `Trop long${NBSP}: {width} caractères, la limite est de {max}.`,
    "editor.issue.widthPart": `Partie {part} trop longue${NBSP}: {width} caractères, la limite est de {max}.`,
    "editor.issue.subs": "{count} parties séparées par {j}, la limite est de {max}.",
    "editor.issue.sourceChanged": "Le texte original a changé depuis cette traduction.",
    "step3.openInEditor": "Ouvrir dans l'éditeur",
    "step3.editorIncluded": ({ count }) =>
      `${count.toLocaleString("fr")} traduction${count > 1 ? "s" : ""} de l'éditeur ser${count > 1 ? "ont" : "a"} incluse${count > 1 ? "s" : ""}.`,
    "step3.opened": ({ count }) =>
      `${count.toLocaleString("fr")} traduction${count > 1 ? "s" : ""} ouverte${count > 1 ? "s" : ""} dans l'éditeur.`,
    "step3.kept": ({ count }) =>
      `${count.toLocaleString("fr")} déjà traduite${count > 1 ? "s" : ""} dans l'éditeur ${count > 1 ? "ont été conservées" : "a été conservée"}.`,
    "busy.section": "Ouverture de {xpath}",
    "busy.exportEdits": "Préparation de vos traductions",
    "busy.readEdits": "Lecture des fichiers de traduction",
    "log.skipped.legacy": `{name}${NBSP}: ancien format à positions, impossible à ouvrir dans l'éditeur (il s'applique quand même à la génération).`,
    "log.skipped.other_file": `{name}${NBSP}: concerne un autre fichier du jeu.`,
    "log.skipped.unknown_section": `{name}${NBSP}: section non reconnue.`,
    "step2.help": "Téléchargez les sections à traduire au format CSV et JSON. Remplissez la colonne <code>target</code> et laissez vides les lignes que vous ne traduisez pas.",
    "step2.selectAll": "Tout sélectionner",
    "step2.selectNone": "Tout désélectionner",
    "step2.selected": ({ count }) => `${count} sélectionnée${count > 1 ? "s" : ""}`,
    "step2.download": "Télécharger les textes (.zip)",

    "step3.title": "Générer le fichier traduit",
    "step3.help": `Les traductions de l'éditeur sont incluses. Vous pouvez aussi ajouter des fichiers CSV ou JSON traduits, ou une version publiée de <a href="${RELEASES_URL}">MHFrontier-Translation</a> (par exemple <code>translations-fr.json.gz</code>). Ils doivent correspondre au fichier ouvert à l'étape 1.`,
    "step3.choose": "Choisir les fichiers de traduction",
    "step3.release": `{name}${NBSP}: version publiée, langue`,
    "step3.releaseOption": ({ lang, count }) =>
      `${lang} (${count} section${count > 1 ? "s" : ""} pour ce fichier)`,
    "step3.options": "Options",
    "step3.fold": "Remplacer les caractères que la police du jeu ne sait pas afficher (é → e, œ → oe, « → \")",
    "step3.compress": "Compresser (requis par le jeu)",
    "step3.encrypt": "Chiffrer (requis par le jeu)",
    "step3.build": "Générer et télécharger",
    "step3.hint": "La génération de <code>mhfdat.bin</code> prend environ 40 secondes, quelques secondes pour les fichiers plus petits. Remplacez le fichier du dossier <code>dat/</code> de votre jeu par celui téléchargé, en gardant une copie de l'original.",
    "step3.nothing": `Rien à générer${NBSP}: aucune traduction dans l'éditeur ni dans ces fichiers, ou elles correspondent déjà au fichier du jeu.`,

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
