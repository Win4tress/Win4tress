// What a program belongs to, when its own name doesn't say: helpers such as
// "Adobe AcroCEF" are part of a bigger app. The folder it's installed in ("in
// Adobe\Acrobat DC"), else its product name if that tells more ("Part of
// Steam"). Nothing for Windows' own programs (all "Microsoft Windows Operating
// System", in System32) or when the name already says it.

import type { PathClass } from "./api";

/** Folders programs are installed under; what follows names the app. */
const ROOTS = [
  /^[a-z]:\\program files( \(x86\))?\\/i,
  /^[a-z]:\\programdata\\/i,
  /\\appdata\\local\\programs\\/i,
  /\\appdata\\(local|roaming)\\/i,
];

/** Folder words that don't name anything. */
const GENERIC = new Set(["bin", "app", "apps", "application", "program", "programs", "common", "files", "x86", "x64"]);

/** Lower case, letters and digits only: "Edge WebView2" → "edgewebview2". */
function compact(text: string): string {
  return text.toLowerCase().replace(/[^\p{L}\p{N}]/gu, "");
}

/** Says something the name doesn't: a word of it the name lacks. */
function adds(name: string, folder: string): boolean {
  const n = compact(name);
  const words = folder.toLowerCase().match(/[\p{L}\p{N}]{2,}/gu) ?? [];
  return words.some((w) => !GENERIC.has(w) && !n.includes(w));
}

/** The first two folders under where programs are installed, e.g. "Adobe\Acrobat DC". */
export function installFolder(path: string): string | null {
  if (/\\windowsapps\\/i.test(path)) return null; // package folders: name_version_arch_publisher
  for (const root of ROOTS) {
    const m = root.exec(path);
    if (!m) continue;
    const folders = path.slice(m.index + m[0].length).split("\\").slice(0, -1);
    return folders.length ? folders.slice(0, 2).join("\\") : null;
  }
  return null;
}

export function appOrigin(
  name: string,
  path: string,
  product: string | null,
  pathClass: PathClass | undefined,
): string | null {
  if (pathClass === "windows") return null;
  // The folder first: people know where their apps are installed better than
  // what their files call the product (Defender's is "Microsoft Malware
  // Protection", Discord's updater's "Squirrel").
  const folder = installFolder(path);
  if (folder) return adds(name, folder) ? `in ${folder}` : null;
  if (!product) return null;
  const n = compact(name);
  const p = compact(product);
  return n.includes(p) || p.includes(n) ? null : `Part of ${product}`;
}
