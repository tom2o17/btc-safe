"use client";

import { useEffect, useState } from "react";
import { loadPref, resolveTheme, savePref, THEME_KEY, THEME_PREFS, type ThemePref } from "@/lib/theme";

const DARK_MQ = "(prefers-color-scheme: dark)";
const CHANGE = "btcsafe:theme";

function apply(pref: ThemePref) {
  const dark = window.matchMedia(DARK_MQ).matches;
  document.documentElement.setAttribute("data-theme", resolveTheme(pref, dark));
}

/** Mounted once in the root layout: follows the OS while on "system", and other tabs' choices. */
export function ThemeSync() {
  useEffect(() => {
    const mq = window.matchMedia(DARK_MQ);
    const sync = () => apply(loadPref(window.localStorage));
    const onStorage = (e: StorageEvent) => {
      if (e.key === THEME_KEY || e.key === null) sync();
    };
    mq.addEventListener("change", sync);
    window.addEventListener("storage", onStorage);
    return () => {
      mq.removeEventListener("change", sync);
      window.removeEventListener("storage", onStorage);
    };
  }, []);
  return null;
}

const LABEL: Record<ThemePref, string> = { system: "System", light: "Light", dark: "Dark" };

/** System / Light / Dark. Per browser; nothing goes to the server. */
export function ThemePicker() {
  const [pref, setPref] = useState<ThemePref | null>(null);
  useEffect(() => {
    setPref(loadPref(window.localStorage));
    const on = () => setPref(loadPref(window.localStorage));
    window.addEventListener(CHANGE, on);
    window.addEventListener("storage", on);
    return () => {
      window.removeEventListener(CHANGE, on);
      window.removeEventListener("storage", on);
    };
  }, []);

  function choose(p: ThemePref) {
    savePref(window.localStorage, p);
    apply(p);
    setPref(p);
    window.dispatchEvent(new Event(CHANGE));
  }

  return (
    <div className="segmented" role="radiogroup" aria-label="Theme" data-testid="theme-picker">
      {THEME_PREFS.map((p) => (
        <button
          key={p}
          type="button"
          role="radio"
          aria-checked={pref === p}
          className={pref === p ? "on" : ""}
          onClick={() => choose(p)}
        >
          {LABEL[p]}
        </button>
      ))}
    </div>
  );
}

export function AppearanceCard() {
  return (
    <div className="card" data-testid="appearance">
      <h2>Appearance</h2>
      <div className="row between wrap">
        <span className="small muted">Theme for this browser. System follows your OS setting.</span>
        <ThemePicker />
      </div>
    </div>
  );
}
