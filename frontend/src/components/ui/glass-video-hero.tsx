'use client';

import { useState, useEffect, useRef } from "react";
import Link from "next/link";
import { Maximize2, Minimize2, Menu, X } from "lucide-react";

const VIDEO_URL =
  "https://d8j0ntlcm91z4.cloudfront.net/user_38xzZboKViGWJOttwIXH07lWA1P/hf_20260210_031346_d87182fb-b0af-4273-84d1-c6fd17d6bf0f.mp4";

const sat = { fontFamily: '"Satoshi", sans-serif' } as const;

/* ─── Navbar ─── */
function Navbar() {
  const [mobileOpen, setMobileOpen] = useState(false);
  const [scrolled, setScrolled] = useState(false);
  const [userEmail, setUserEmail] = useState<string | null>(null);

  useEffect(() => {
    const onScroll = () => setScrolled(window.scrollY > 20);
    window.addEventListener("scroll", onScroll, { passive: true });
    setUserEmail(localStorage.getItem('authtrack_user_email'));
    return () => window.removeEventListener("scroll", onScroll);
  }, []);

  const initials = userEmail ? userEmail[0].toUpperCase() : null;
  const displayName = userEmail ? userEmail.split('@')[0] : null;

  const links = [
    { label: "Scanner", href: "/scan" },
    { label: "How It Works", href: "#how-it-works" },
    { label: "Features", href: "#features" },
  ];

  return (
    <header className={`fixed top-0 inset-x-0 z-50 transition-all duration-300 ${scrolled ? "backdrop-blur-2xl bg-black/60 border-b border-white/10" : "bg-transparent"}`}>
      <nav className="max-w-7xl mx-auto px-6 h-16 flex items-center justify-between">
        {/* Logo */}
        <Link href="/" className="flex items-center gap-2.5">
          <svg viewBox="0 0 32 32" fill="none" className="w-7 h-7">
            <path d="M16 2v10" stroke="#fff" strokeWidth="2.5" strokeLinecap="round"/>
            <path d="M10 7l6 6 6-6" stroke="#fff" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"/>
            <path d="M16 2v10" stroke="#fff" strokeWidth="2.5" strokeLinecap="round" transform="rotate(90 16 16)"/>
            <path d="M10 7l6 6 6-6" stroke="#fff" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" transform="rotate(90 16 16)"/>
            <path d="M16 2v10" stroke="#fff" strokeWidth="2.5" strokeLinecap="round" transform="rotate(180 16 16)"/>
            <path d="M10 7l6 6 6-6" stroke="#fff" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" transform="rotate(180 16 16)"/>
            <path d="M16 2v10" stroke="#fff" strokeWidth="2.5" strokeLinecap="round" transform="rotate(270 16 16)"/>
            <path d="M10 7l6 6 6-6" stroke="#fff" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" transform="rotate(270 16 16)"/>
          </svg>
          <span className="text-white font-medium text-[17px] tracking-[-0.02em]" style={sat}>AuthTrack</span>
        </Link>

        {/* Desktop nav links */}
        <ul className="hidden md:flex items-center gap-8">
          {links.map((l) => (
            <li key={l.label}>
              <Link href={l.href} className="font-medium text-[14px] text-white/70 hover:text-white transition-colors" style={sat}>{l.label}</Link>
            </li>
          ))}
        </ul>

        {/* Desktop CTA — auth-aware */}
        <div className="hidden md:flex items-center gap-3">
          {userEmail ? (
            <>
              <Link href="/dashboard" className="font-medium text-[14px] text-white/70 hover:text-white transition-colors" style={sat}>
                Dashboard
              </Link>
              <Link
                href="/dashboard"
                className="flex items-center gap-2 px-3 py-1.5 rounded-[10px] backdrop-blur-xl border border-[rgba(164,132,215,0.5)] bg-[rgba(85,80,110,0.45)] text-white hover:bg-[rgba(85,80,110,0.65)] transition-all"
                style={sat}
              >
                <span className="w-5 h-5 rounded-full bg-purple-500 flex items-center justify-center text-[11px] font-bold text-white shrink-0">
                  {initials}
                </span>
                <span className="font-medium text-[13px] max-w-[120px] truncate">{displayName}</span>
              </Link>
            </>
          ) : (
            <>
              <Link href="/login" className="font-medium text-[14px] text-white/70 hover:text-white transition-colors" style={sat}>Sign In</Link>
              <Link href="/scan" className="font-medium text-[14px] px-4 py-2 rounded-[10px] backdrop-blur-xl border border-[rgba(164,132,215,0.5)] bg-[rgba(85,80,110,0.45)] text-white hover:bg-[rgba(85,80,110,0.65)] transition-all" style={sat}>
                Start Scanning
              </Link>
            </>
          )}
        </div>

        {/* Mobile burger */}
        <button className="md:hidden text-white/80 hover:text-white p-1" onClick={() => setMobileOpen(!mobileOpen)} aria-label="Toggle menu">
          {mobileOpen ? <X size={22} /> : <Menu size={22} />}
        </button>
      </nav>

      {/* Mobile menu */}
      {mobileOpen && (
        <div className="md:hidden backdrop-blur-2xl bg-black/90 border-b border-white/10 px-6 pb-6 pt-2 flex flex-col gap-5">
          {links.map((l) => (
            <Link key={l.label} href={l.href} className="font-medium text-base text-white/80 hover:text-white" style={sat} onClick={() => setMobileOpen(false)}>{l.label}</Link>
          ))}
          <div className="flex flex-col gap-3 pt-2 border-t border-white/10">
            {userEmail ? (
              <Link href="/dashboard" className="font-medium text-sm text-center px-4 py-2.5 rounded-[10px] border border-[rgba(164,132,215,0.5)] bg-[rgba(85,80,110,0.45)] text-white" style={sat} onClick={() => setMobileOpen(false)}>
                Dashboard
              </Link>
            ) : (
              <>
                <Link href="/login" className="font-medium text-base text-white/70" style={sat} onClick={() => setMobileOpen(false)}>Sign In</Link>
                <Link href="/scan" className="font-medium text-sm text-center px-4 py-2.5 rounded-[10px] border border-[rgba(164,132,215,0.5)] bg-[rgba(85,80,110,0.45)] text-white" style={sat} onClick={() => setMobileOpen(false)}>Start Scanning Free</Link>
              </>
            )}
          </div>
        </div>
      )}
    </header>
  );
}

/* ─── Hero ─── */
const HeroSection = () => {
  const [fullBleed, setFullBleed] = useState(true);
  const videoRef = useRef<HTMLVideoElement>(null);

  useEffect(() => {
    const v = videoRef.current;
    if (!v) return;
    v.style.opacity = "0";
    v.style.transition = "opacity 0.6s ease";
    const onLoaded = () => { v.style.opacity = "1"; };
    if (v.readyState >= 2) { v.style.opacity = "1"; }
    else { v.addEventListener("loadeddata", onLoaded, { once: true }); }
  }, []);

  return (
    <>
      <Navbar />
      <section className={`relative w-full overflow-hidden transition-all duration-500 ease-in-out ${fullBleed ? "min-h-screen" : "py-32 lg:py-40"}`}>

        <button
          onClick={() => setFullBleed(!fullBleed)}
          aria-label={fullBleed ? "Switch to fit-to-content" : "Switch to full-bleed"}
          className="absolute top-20 right-4 z-20 p-2.5 rounded-[10px] backdrop-blur-xl border border-[rgba(164,132,215,0.5)] bg-[rgba(85,80,110,0.4)] text-white hover:bg-[rgba(85,80,110,0.6)] transition-all focus:outline-none"
        >
          {fullBleed ? <Minimize2 size={16} /> : <Maximize2 size={16} />}
        </button>

        <video
          ref={videoRef}
          autoPlay loop muted playsInline preload="auto"
          className="absolute inset-0 w-full h-full object-cover z-0"
          style={{ willChange: "transform", transform: "translateZ(0)" }}
        >
          <source src={VIDEO_URL} type="video/mp4" />
        </video>

        <div className="absolute inset-0 z-[1] bg-gradient-to-b from-black/25 via-black/10 to-black/85 pointer-events-none" />

        <div className="relative z-10 flex flex-col items-center text-center mt-36 px-6 pb-32">
          <div className="inline-flex items-center gap-2.5 h-[38px] px-3.5 rounded-[10px] backdrop-blur-xl border border-[rgba(164,132,215,0.5)] bg-[rgba(85,80,110,0.4)] shadow-[0_0_20px_rgba(123,57,252,0.15),inset_0_1px_0_rgba(255,255,255,0.08)]">
            <span className="bg-primary text-primary-foreground font-medium text-xs px-2.5 py-1 rounded-[6px]" style={sat}>New</span>
            <span className="font-medium text-sm text-white tracking-wide" style={sat}>LangGraph Static Analysis flow is now live</span>
          </div>

          <h1 className="text-white text-5xl lg:text-[88px] xl:text-[96px] leading-[1.05] mt-8 max-w-5xl" style={{ ...sat, fontWeight: 400, letterSpacing: "-0.04em" }}>
            Scan your app for threats
            <br className="hidden lg:block" />
            instantly{" "}
            <em style={{ fontStyle: "italic", fontWeight: 400 }}>and</em>{" "}
            intelligently
          </h1>

          <p className="text-white/60 text-lg mt-6 max-w-[620px] leading-relaxed" style={{ ...sat, fontWeight: 400 }}>
            AuthTrack deploys a chain of AI agents to crawl your app, map its attack surface,
            audit security headers, and surface actionable findings — all in seconds.
          </p>

          <div className="flex flex-col sm:flex-row items-center gap-4 mt-10">
            <Link href="/scan" className="inline-flex items-center justify-center px-8 py-3.5 rounded-[10px] bg-white text-black text-base font-medium hover:bg-white/90 transition-all shadow-lg" style={sat}>
              Start Scanning Free
            </Link>
            <Link href="/signup" className="inline-flex items-center justify-center px-8 py-3.5 rounded-[10px] bg-[rgba(30,30,35,0.85)] border border-white/10 text-white text-base font-medium hover:bg-[rgba(45,45,55,0.9)] transition-all backdrop-blur-sm" style={sat}>
              Create Account
            </Link>
          </div>
        </div>
      </section>
    </>
  );
};

export { HeroSection };
