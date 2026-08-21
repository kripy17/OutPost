// IOC search page contracts — the draft-persistence pattern (a bare visit
// restores the last submitted query so the investigation resumes
// mid-thought) and the platform chip tone.

import { describe, expect, it } from "vitest";
import { platformTone, readSavedQuery, writeSavedQuery } from "../routes/searchHelpers";

describe("search draft persistence", () => {
  it("round-trips a submitted query", () => {
    writeSavedQuery("185.220.101.34");
    expect(readSavedQuery()).toBe("185.220.101.34");
  });

  it("clearing removes the draft", () => {
    writeSavedQuery("something");
    writeSavedQuery("");
    expect(readSavedQuery()).toBe("");
  });

  it("reads empty when nothing was ever saved", () => {
    writeSavedQuery("");
    expect(readSavedQuery()).toBe("");
  });
});

describe("platformTone", () => {
  it("maps windows to accent and linux to clean — others muted", () => {
    expect(platformTone("windows")).toContain("text-accent");
    expect(platformTone("linux")).toContain("text-risk-clean");
    for (const p of ["macos", "unknown", ""]) {
      const tone = platformTone(p);
      expect(tone).toContain("text-text-muted");
      expect(tone).not.toContain("text-accent");
    }
  });
});
