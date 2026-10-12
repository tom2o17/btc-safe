/**
 * Theme preference: a per-browser choice kept in localStorage. "system" follows
 * prefers-color-scheme. The resolved theme lands on <html data-theme="light|dark">,
 * which is what globals.css keys its palette off.
 */
export type ThemePref = "system" | "light" | "dark";
export type Theme = "light" | "dark";

export const THEME_KEY = "btcsafe.theme";
export const THEME_PREFS: readonly ThemePref[] = ["system", "light", "dark"];

type StorageLike = Pick<Storage, "getItem" | "setItem" | "removeItem">;

/** Anything unknown (missing, garbage, an old value) reads as "system". */
export function parsePref(raw: string | null | undefined): ThemePref {
  return raw === "light" || raw === "dark" ? raw : "system";
}

export function resolveTheme(pref: ThemePref, systemDark: boolean): Theme {
  if (pref === "system") return systemDark ? "dark" : "light";
  return pref;
}

export function loadPref(storage: StorageLike | null | undefined): ThemePref {
  try {
    return parsePref(storage?.getItem(THEME_KEY));
  } catch {
    return "system"; // storage blocked (privacy mode, sandboxed iframe)
  }
}

/** "system" is the default, so it's stored as the absence of a value. */
export function savePref(storage: StorageLike | null | undefined, pref: ThemePref): void {
  try {
    if (pref === "system") storage?.removeItem(THEME_KEY);
    else storage?.setItem(THEME_KEY, pref);
  } catch {
    /* not persisted; the choice still applies to this page */
  }
}

/**
 * Runs in <head> before first paint, so the page never flashes the wrong theme.
 * Kept dependency-free and in sync with parsePref/resolveTheme above (the unit test
 * executes this string against the same cases).
 */
export const THEME_INIT_SCRIPT = `(function(){var t="light";try{var p=localStorage.getItem(${JSON.stringify(
  THEME_KEY,
)});t=p==="dark"||(p!=="light"&&window.matchMedia("(prefers-color-scheme: dark)").matches)?"dark":"light"}catch(e){}document.documentElement.setAttribute("data-theme",t)})();`;
