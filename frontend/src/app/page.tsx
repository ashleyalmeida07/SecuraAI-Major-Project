import { HeroSection } from "@/components/ui/glass-video-hero";
import { ScrollReveal } from "@/components/ui/scroll-reveal";
import Link from "next/link";
import {
  Globe, Lock, Code, Database, Shield, Activity,
  Fingerprint, Server, ArrowRight, CheckCircle2, Zap, Eye, Cpu
} from "lucide-react";

const sat = { fontFamily: '"Satoshi", sans-serif' } as const;

export default function HomePage() {
  return (
    <div className="dark bg-black text-white selection:bg-purple-500/30 overflow-x-hidden">

      {/* ── 1. HERO ── */}
      <HeroSection />

      {/* ── 2. TECH STRIP ── */}
      <ScrollReveal>
        <section className="border-y border-white/10 bg-white/[0.03] py-6">
          <div className="max-w-6xl mx-auto px-6 flex flex-wrap items-center justify-center gap-x-12 gap-y-4">
            {["LangGraph", "FastAPI", "Semgrep", "Upstash", "httpx", "Next.js 15"].map((t) => (
              <span key={t} style={sat} className="text-white/30 text-sm font-medium tracking-widest uppercase">{t}</span>
            ))}
          </div>
        </section>
      </ScrollReveal>

      {/* ── 3. HOW IT WORKS ── */}
      <section id="how-it-works" className="py-28 px-6">
        <div className="max-w-6xl mx-auto">
          <ScrollReveal>
            <div className="mb-16 text-center">
              <div className="inline-block text-xs font-medium tracking-[0.18em] uppercase text-purple-400 mb-4" style={sat}>How It Works</div>
              <h2 className="text-4xl lg:text-6xl text-white max-w-3xl mx-auto" style={{ ...sat, fontWeight: 400, letterSpacing: "-0.04em" }}>
                Three AI workflows.{" "}<em style={{ fontStyle: "italic", fontWeight: 400 }}>One</em>{" "}unified picture.
              </h2>
              <p className="text-white/50 text-lg mt-5 max-w-xl mx-auto leading-relaxed" style={{ ...sat, fontWeight: 400 }}>
                SecuraAI chains LangGraph agents across three specialised flows that hand off data to each other automatically.
              </p>
            </div>
          </ScrollReveal>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-5">
            {[
              { badge: "Flow 1", icon: Globe, color: "text-cyan-400", bg: "bg-cyan-400/10 border-cyan-400/20", title: "Recon & Surface Mapping", desc: "Crawls your target URL with httpx + BeautifulSoup, discovers every endpoint and link, then uses an LLM to classify them by type — API, Auth, Static, Form.", steps: ["Crawler Node", "Classifier Node", "Surface Report Node"] },
              { badge: "Flow 2", icon: Lock, color: "text-orange-400", bg: "bg-orange-400/10 border-orange-400/20", title: "Header & Cookie Audit", desc: "Takes the endpoint list from Flow 1, fetches all HTTP response headers, then runs 10 security rules (HSTS, CSP, X-Frame-Options, Secure cookies…).", steps: ["Header Fetcher", "Rule Checker", "Severity Scorer"] },
              { badge: "Flow 3", icon: Code, color: "text-purple-400", bg: "bg-purple-400/10 border-purple-400/20", title: "Static Code Analysis", desc: "Runs Semgrep over your codebase, retrieves similar vulnerability patterns from Upstash Vector DB (RAG), and triages findings with an LLM that writes fix suggestions.", steps: ["Semgrep Runner", "RAG Retriever", "LLM Triager"] },
            ].map((flow, i) => (
              <ScrollReveal key={flow.badge} delay={i * 0.12}>
                <div className="relative rounded-2xl border border-white/10 bg-white/[0.04] p-7 flex flex-col gap-5 hover:bg-white/[0.07] transition-colors h-full">
                  <div className={`inline-flex items-center gap-2 self-start px-3 py-1 rounded-full border text-xs font-medium ${flow.bg}`} style={sat}>
                    <flow.icon className={`h-3.5 w-3.5 ${flow.color}`} />
                    <span className={flow.color}>{flow.badge}</span>
                  </div>
                  <h3 className="text-xl text-white" style={{ ...sat, fontWeight: 500, letterSpacing: "-0.02em" }}>{flow.title}</h3>
                  <p className="text-white/50 text-sm leading-relaxed" style={{ ...sat, fontWeight: 400 }}>{flow.desc}</p>
                  <ul className="flex flex-col gap-2 mt-auto pt-4 border-t border-white/10">
                    {flow.steps.map((s) => (
                      <li key={s} className="flex items-center gap-2 text-sm text-white/60" style={sat}>
                        <CheckCircle2 className={`h-4 w-4 ${flow.color} shrink-0`} />{s}
                      </li>
                    ))}
                  </ul>
                </div>
              </ScrollReveal>
            ))}
          </div>
        </div>
      </section>

      {/* ── 4. FEATURES ── */}
      <section id="features" className="py-28 px-6 border-t border-white/10">
        <div className="max-w-6xl mx-auto">
          <ScrollReveal>
            <div className="mb-16 text-center">
              <div className="inline-block text-xs font-medium tracking-[0.18em] uppercase text-purple-400 mb-4" style={sat}>Features</div>
              <h2 className="text-4xl lg:text-6xl text-white max-w-2xl mx-auto" style={{ ...sat, fontWeight: 400, letterSpacing: "-0.04em" }}>
                Everything you need to{" "}<em style={{ fontStyle: "italic" }}>stay secure</em>
              </h2>
            </div>
          </ScrollReveal>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-5">
            {[
              { icon: Zap, color: "text-yellow-400", bg: "bg-yellow-400/10", title: "Live Streaming", desc: "Watch each agent node execute in real-time. See exactly what data was fetched and passed to the next node." },
              { icon: Eye, color: "text-blue-400", bg: "bg-blue-400/10", title: "Attack Surface Map", desc: "Every endpoint classified by type. Auth flows, API routes, and static assets — all mapped and categorised." },
              { icon: Database, color: "text-purple-400", bg: "bg-purple-400/10", title: "Vector RAG", desc: "Upstash Vector DB stores known vulnerability patterns. The LLM retrieves relevant context before triaging." },
              { icon: Shield, color: "text-green-400", bg: "bg-green-400/10", title: "10 Security Rules", desc: "HSTS, CSP, X-Frame-Options, Referrer-Policy, Secure cookies — validated on every endpoint." },
              { icon: Cpu, color: "text-cyan-400", bg: "bg-cyan-400/10", title: "LangGraph Agents", desc: "Multi-step, stateful AI workflows built on LangGraph. Each node has a defined role and output schema." },
              { icon: Code, color: "text-pink-400", bg: "bg-pink-400/10", title: "Semgrep Integration", desc: "Static analysis across your codebase. Pattern-matched findings with LLM-generated fix suggestions." },
              { icon: Fingerprint, color: "text-indigo-400", bg: "bg-indigo-400/10", title: "Auth Tracking", desc: "Identifies authentication endpoints, cookie flags, and session management flaws automatically." },
              { icon: Activity, color: "text-red-400", bg: "bg-red-400/10", title: "Severity Scoring", desc: "AI assigns critical/high/medium/low ratings and writes an executive summary you can share directly." },
            ].map((f, i) => (
              <ScrollReveal key={f.title} delay={(i % 4) * 0.08}>
                <div className="rounded-2xl border border-white/10 bg-white/[0.04] p-6 flex flex-col gap-3 hover:bg-white/[0.07] transition-colors h-full">
                  <div className={`w-10 h-10 rounded-xl ${f.bg} flex items-center justify-center`}>
                    <f.icon className={`h-5 w-5 ${f.color}`} />
                  </div>
                  <h4 className="text-white font-medium text-[15px]" style={sat}>{f.title}</h4>
                  <p className="text-white/45 text-sm leading-relaxed" style={{ ...sat, fontWeight: 400 }}>{f.desc}</p>
                </div>
              </ScrollReveal>
            ))}
          </div>
        </div>
      </section>

      {/* ── 5. STATS ── */}
      <section className="py-24 px-6 border-t border-white/10">
        <div className="max-w-5xl mx-auto grid grid-cols-2 md:grid-cols-4 gap-12 text-center">
          {[
            { num: "300+", label: "Clients secured" },
            { num: "99%", label: "Satisfaction rate" },
            { num: "3", label: "AI workflows" },
            { num: "$5M+", label: "Revenue protected" },
          ].map((s, i) => (
            <ScrollReveal key={s.label} delay={i * 0.1}>
              <div className="flex flex-col gap-1">
                <span className="text-5xl text-white" style={{ ...sat, fontWeight: 400, letterSpacing: "-0.04em" }}>{s.num}</span>
                <span className="text-white/40 text-sm tracking-wide uppercase" style={sat}>{s.label}</span>
              </div>
            </ScrollReveal>
          ))}
        </div>
      </section>

      {/* ── 6. CTA BANNER ── */}
      <section id="contact" className="py-28 px-6 border-t border-white/10">
        <ScrollReveal>
          <div className="max-w-4xl mx-auto text-center">
            <div className="inline-flex items-center gap-2.5 h-[38px] px-3.5 rounded-[10px] backdrop-blur-xl border border-[rgba(164,132,215,0.5)] bg-[rgba(85,80,110,0.4)] shadow-[0_0_20px_rgba(123,57,252,0.15)] mb-8">
              <span className="bg-primary text-primary-foreground text-xs px-2.5 py-1 rounded-[6px]" style={{ ...sat, fontWeight: 500 }}>Free</span>
              <span className="text-sm text-white" style={{ ...sat, fontWeight: 500 }}>No credit card required</span>
            </div>
            <h2 className="text-4xl lg:text-6xl xl:text-7xl text-white mb-6" style={{ ...sat, fontWeight: 400, letterSpacing: "-0.04em" }}>
              Ready to secure<br /><em style={{ fontStyle: "italic" }}>your</em> application?
            </h2>
            <p className="text-white/50 text-lg max-w-lg mx-auto mb-10 leading-relaxed" style={{ ...sat, fontWeight: 400 }}>
              Enter a URL and watch AI agents audit your site in under 60 seconds. No setup. No configuration. Just results.
            </p>
            <div className="flex flex-col sm:flex-row items-center justify-center gap-4">
              <Link href="/scan" className="inline-flex items-center gap-2 px-8 py-4 rounded-[10px] bg-white text-black text-base font-medium hover:bg-white/90 transition-all shadow-lg" style={sat}>
                Start Scanning Free <ArrowRight className="h-4 w-4" />
              </Link>
              <Link href="/signup" className="px-8 py-4 rounded-[10px] bg-[rgba(30,30,35,0.85)] border border-white/10 text-white text-base font-medium hover:bg-[rgba(45,45,55,0.9)] transition-all backdrop-blur-sm" style={sat}>
                Create Account
              </Link>
            </div>
          </div>
        </ScrollReveal>
      </section>

      {/* ── 7. FOOTER ── */}
      <footer className="border-t border-white/10 py-14 px-6">
        <div className="max-w-6xl mx-auto grid grid-cols-1 md:grid-cols-4 gap-10">
          <div className="flex flex-col gap-4 md:col-span-1">
            <div className="flex items-center gap-2.5">
              <svg viewBox="0 0 32 32" fill="none" className="w-7 h-7">
                <path d="M16 2v10" stroke="#fff" strokeWidth="2.5" strokeLinecap="round"/><path d="M10 7l6 6 6-6" stroke="#fff" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"/>
                <path d="M16 2v10" stroke="#fff" strokeWidth="2.5" strokeLinecap="round" transform="rotate(180 16 16)"/><path d="M10 7l6 6 6-6" stroke="#fff" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" transform="rotate(180 16 16)"/>
              </svg>
              <span className="text-white font-medium text-[17px]" style={sat}>SecuraAI</span>
            </div>
            <p className="text-white/40 text-sm leading-relaxed" style={sat}>Multi-Agent Security Scanner powered by LangGraph and FastAPI.</p>
          </div>
          {[
            { heading: "Product", items: [{ label: "Scanner", href: "/scan" }, { label: "Dashboard", href: "/dashboard" }, { label: "How It Works", href: "#how-it-works" }] },
            { heading: "Account", items: [{ label: "Sign In", href: "/login" }, { label: "Create Account", href: "/signup" }] },
            { heading: "Stack", items: [{ label: "LangGraph", href: "#" }, { label: "FastAPI", href: "#" }, { label: "Next.js 15", href: "#" }, { label: "Upstash", href: "#" }] },
          ].map((col) => (
            <div key={col.heading} className="flex flex-col gap-4">
              <h5 className="text-white/50 text-xs font-medium tracking-[0.14em] uppercase" style={sat}>{col.heading}</h5>
              <ul className="flex flex-col gap-3">
                {col.items.map((item) => (
                  <li key={item.label}><Link href={item.href} className="text-white/60 hover:text-white text-sm transition-colors" style={sat}>{item.label}</Link></li>
                ))}
              </ul>
            </div>
          ))}
        </div>
        <div className="max-w-6xl mx-auto mt-12 pt-8 border-t border-white/10 flex flex-col sm:flex-row items-center justify-between gap-4">
          <p className="text-white/30 text-sm" style={sat}>© 2026 SecuraAI. All rights reserved.</p>
          <div className="flex flex-wrap gap-x-8 gap-y-2">
            {["LangGraph", "FastAPI", "Semgrep", "Upstash"].map((t) => (
              <span key={t} className="text-white/20 text-xs tracking-widest uppercase" style={sat}>{t}</span>
            ))}
          </div>
        </div>
      </footer>

    </div>
  );
}
