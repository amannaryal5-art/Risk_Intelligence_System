import Link from "next/link";

export default function HomePage() {
  return (
    <main className="flex min-h-screen items-center justify-center bg-bg px-6">
      <div className="rounded-2xl border border-accent/15 bg-surface/80 p-10 text-center shadow-cyan-glow">
        <div className="font-heading text-4xl uppercase tracking-[0.12em] text-white">
          RiskintelAI
        </div>
        <p className="mt-3 max-w-xl font-data text-sm text-muted">
          Cyber operations war room interface scaffolded for the live feed status experience.
        </p>
        <Link
          href="/feeds/live"
          className="mt-6 inline-flex rounded-md border border-accent/30 bg-accent px-5 py-3 font-data text-sm uppercase tracking-[0.2em] text-slate-950 shadow-cyan-glow"
        >
          Open Live Feed Status
        </Link>
      </div>
    </main>
  );
}
