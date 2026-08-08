import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { Panel } from "../ui";
import { addRunNote, getRunNotes } from "../../lib/api";

/** Per-run analyst notes (docs/10 Tier 2 #7) — observations, hypotheses,
 *  reminders, attached to a single run. Full-width section on the detail page. */
export default function NotesPanel({ runId }: { runId: string }) {
  const queryClient = useQueryClient();
  const [draft, setDraft] = useState("");

  const { data: notes = [] } = useQuery({
    queryKey: ["notes", runId],
    queryFn: () => getRunNotes(runId),
  });

  const addNote = useMutation({
    mutationFn: () => addRunNote(runId, draft.trim()),
    onSuccess: () => {
      setDraft("");
      void queryClient.invalidateQueries({ queryKey: ["notes", runId] });
    },
  });

  return (
    <Panel kicker="Operate" title="Analyst notes">
      <div className="space-y-3">
        {notes.length === 0 && (
          <p className="text-xs text-text-muted">
            No notes yet — jot down observations, hypotheses, or reminders for a later report.
          </p>
        )}
        {notes.map((n, i) => (
          <div key={i} className="rounded border border-border-subtle bg-bg-base/60 p-3">
            <p className="text-sm leading-snug text-text-primary">{n.note}</p>
            <p className="mt-1 font-mono text-[10px] text-text-faint">
              {n.created_at.slice(0, 19).replace("T", " ")} UTC
            </p>
          </div>
        ))}
        <div className="flex gap-2">
          <textarea
            value={draft}
            onChange={(e) => setDraft(e.target.value)}
            rows={2}
            placeholder="Add an observation…"
            className="min-w-0 flex-1 resize-y rounded border border-border-subtle bg-bg-base px-3 py-2 text-sm text-text-primary placeholder:text-text-faint focus:border-accent/60 focus:outline-none"
          />
          <button
            onClick={() => {
              if (draft.trim()) addNote.mutate();
            }}
            disabled={!draft.trim() || addNote.isPending}
            className="press shrink-0 self-end rounded border border-border-subtle px-3 py-1.5 font-mono text-xs text-text-muted transition-colors duration-150 hover:border-accent/60 hover:text-accent disabled:cursor-not-allowed disabled:opacity-40"
          >
            {addNote.isPending ? "Adding…" : "Add note"}
          </button>
        </div>
      </div>
    </Panel>
  );
}
