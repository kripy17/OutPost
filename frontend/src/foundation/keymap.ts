import { useEffect, useRef } from "react";

export type KeyHandler = (e: KeyboardEvent) => void;

export interface KeymapBindings {
  [combo: string]: KeyHandler;
}

export interface UseKeymapOptions {
  scope?: string;
  enabled?: boolean;
}

const isInputFocused = (): boolean => {
  const el = document.activeElement;
  if (!el) return false;
  const tag = el.tagName.toLowerCase();
  if (tag === "input" || tag === "textarea" || tag === "select") return true;
  if ((el as HTMLElement).isContentEditable) return true;
  return false;
};

const isModalOrMenuOpen = (): boolean => {
  return !!document.querySelector(
    '[role="dialog"], [role="alertdialog"], [role="menu"][data-state="open"], [data-radix-popper-content-wrapper]'
  );
};

export const useKeymap = (
  bindings: KeymapBindings,
  options: UseKeymapOptions = {}
): void => {
  const { enabled = true } = options;
  const bindingsRef = useRef(bindings);
  bindingsRef.current = bindings;

  const sequenceRef = useRef<{ key: string; time: number } | null>(null);

  useEffect(() => {
    if (!enabled) return;

    const handleKeyDown = (e: KeyboardEvent) => {
      // Suppress global keybindings when typing in inputs or when a dialog/menu is open
      if ((isInputFocused() || isModalOrMenuOpen()) && e.key !== "Escape") {
        return;
      }

      const now = Date.now();
      const currentBindings = bindingsRef.current;

      // Handle two-key chord like "g a", "g e", "g h"
      if (sequenceRef.current && now - sequenceRef.current.time < 1000) {
        const chord = `${sequenceRef.current.key} ${e.key.toLowerCase()}`;
        sequenceRef.current = null;
        if (currentBindings[chord]) {
          e.preventDefault();
          currentBindings[chord](e);
          return;
        }
      }

      if (e.key === "g" && !e.ctrlKey && !e.metaKey && !e.altKey) {
        sequenceRef.current = { key: "g", time: now };
        return;
      }

      const key = e.key;
      let combo = key;
      if (e.ctrlKey) combo = `ctrl+${combo}`;
      if (e.metaKey) combo = `meta+${combo}`;
      if (e.altKey) combo = `alt+${combo}`;

      if (currentBindings[combo]) {
        e.preventDefault();
        currentBindings[combo](e);
        return;
      }

      const lowerKey = key.toLowerCase();
      if (currentBindings[lowerKey]) {
        e.preventDefault();
        currentBindings[lowerKey](e);
      }
    };

    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [enabled]);
};
