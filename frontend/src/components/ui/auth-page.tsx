"use client";

import React, { useState } from 'react';
import { motion } from 'framer-motion';
import { AtSignIcon, ChevronLeftIcon, Loader2Icon } from 'lucide-react';
import Link from 'next/link';
import { useRouter } from 'next/navigation';

const API_BASE = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000/api/v1';

/* ── icons ── */
const GoogleIcon = (props: React.ComponentProps<'svg'>) => (
  <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="currentColor" {...props}>
    <path d="M12.479,14.265v-3.279h11.049c0.108,0.571,0.164,1.247,0.164,1.979c0,2.46-0.672,5.502-2.84,7.669C18.744,22.829,16.051,24,12.483,24C5.869,24,0.308,18.613,0.308,12S5.869,0,12.483,0c3.659,0,6.265,1.436,8.223,3.307L18.392,5.62c-1.404-1.317-3.307-2.341-5.913-2.341C7.65,3.279,3.873,7.171,3.873,12s3.777,8.721,8.606,8.721c3.132,0,4.916-1.258,6.059-2.401c0.927-0.927,1.537-2.251,1.777-4.059L12.479,14.265z" />
  </svg>
);
const AppleIcon = (props: React.ComponentProps<'svg'>) => (
  <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 814 1000" fill="currentColor" {...props}>
    <path d="M788.1 340.9c-5.8 4.5-108.2 62.2-108.2 190.5 0 148.4 130.3 200.9 134.2 202.2-.6 3.2-20.7 71.9-68.7 141.9-42.8 61.6-87.5 123.1-155.5 123.1s-85.5-39.5-164-39.5c-76 0-103.7 40.8-165.9 40.8s-105.4-57.4-155-127.4C46.8 790 0 694.3 0 603.4c0-151.9 99.1-232.2 196.3-232.2 65.2 0 119.7 42.8 160.6 42.8 39.5 0 101.1-44.7 176.3-44.7 28.5 0 130.9 2.6 198.3 99.2zm-234-181.5c31.1-36.9 53.1-88.1 53.1-139.3 0-7.1-.6-14.3-1.9-20.1-50.6 1.9-110.8 33.7-147.1 75.8-28.5 32.4-55.1 83.6-55.1 135.5 0 7.8 1.3 15.6 1.9 18.1 3.2.6 8.4 1.3 13.6 1.3 45.4 0 102.5-30.4 135.5-71.3z" />
  </svg>
);
const GithubIcon = (props: React.ComponentProps<'svg'>) => (
  <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="currentColor" {...props}>
    <path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0024 12c0-6.63-5.37-12-12-12z" />
  </svg>
);
const AuthLogo = () => (
  <svg viewBox="0 0 32 32" fill="none" width={22} height={22}>
    <path d="M16 2v10" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" />
    <path d="M10 7l6 6 6-6" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" />
    <path d="M16 2v10" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" transform="rotate(90 16 16)" />
    <path d="M10 7l6 6 6-6" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" transform="rotate(90 16 16)" />
    <path d="M16 2v10" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" transform="rotate(180 16 16)" />
    <path d="M10 7l6 6 6-6" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" transform="rotate(180 16 16)" />
    <path d="M16 2v10" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" transform="rotate(270 16 16)" />
    <path d="M10 7l6 6 6-6" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" transform="rotate(270 16 16)" />
  </svg>
);

/* ── Animated paths (left panel decoration) ── */
function FloatingPaths({ position }: { position: number }) {
  const paths = Array.from({ length: 36 }, (_, i) => ({
    id: i,
    d: `M-${380 - i * 5 * position} -${189 + i * 6}C-${380 - i * 5 * position} -${189 + i * 6} -${312 - i * 5 * position} ${216 - i * 6} ${152 - i * 5 * position} ${343 - i * 6}C${616 - i * 5 * position} ${470 - i * 6} ${684 - i * 5 * position} ${875 - i * 6} ${684 - i * 5 * position} ${875 - i * 6}`,
    width: 0.5 + i * 0.03,
  }));
  return (
    <div className="pointer-events-none absolute inset-0">
      <svg className="h-full w-full text-white" viewBox="0 0 696 316" fill="none">
        <title>Background Paths</title>
        {paths.map((path) => (
          <motion.path
            key={path.id}
            d={path.d}
            stroke="currentColor"
            strokeWidth={path.width}
            strokeOpacity={0.1 + path.id * 0.03}
            initial={{ pathLength: 0.3, opacity: 0.6 }}
            animate={{ pathLength: 1, opacity: [0.3, 0.6, 0.3], pathOffset: [0, 1, 0] }}
            transition={{ duration: 20 + (path.id % 10), repeat: Infinity, ease: 'linear' }}
          />
        ))}
      </svg>
    </div>
  );
}

/* ── OR separator ── */
const AuthSeparator = () => (
  <div className="flex w-full items-center">
    <div className="h-px w-full" style={{ background: 'rgba(255,255,255,0.1)' }} />
    <span className="px-3 text-xs" style={{ color: 'rgba(255,255,255,0.3)', fontFamily: '"Satoshi", sans-serif' }}>OR</span>
    <div className="h-px w-full" style={{ background: 'rgba(255,255,255,0.1)' }} />
  </div>
);

/* ── Full-width button ── */
function AuthButton({ onClick, type = 'button', children, loading, white }: {
  onClick?: () => void;
  type?: 'button' | 'submit';
  children: React.ReactNode;
  loading?: boolean;
  white?: boolean;
}) {
  return (
    <button
      type={type}
      onClick={onClick}
      disabled={loading}
      style={{
        fontFamily: '"Satoshi", sans-serif',
        fontWeight: 500,
        width: '100%',
        height: '44px',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        gap: '8px',
        borderRadius: '8px',
        fontSize: '14px',
        cursor: loading ? 'not-allowed' : 'pointer',
        opacity: loading ? 0.6 : 1,
        transition: 'background 0.15s',
        border: white ? 'none' : '1px solid rgba(255,255,255,0.12)',
        background: white ? '#fff' : 'rgba(255,255,255,0.07)',
        color: white ? '#000' : 'rgba(255,255,255,0.85)',
      }}
      onMouseEnter={e => { (e.currentTarget as HTMLButtonElement).style.background = white ? '#f0f0f0' : 'rgba(255,255,255,0.12)'; }}
      onMouseLeave={e => { (e.currentTarget as HTMLButtonElement).style.background = white ? '#fff' : 'rgba(255,255,255,0.07)'; }}
    >
      {children}
    </button>
  );
}

/* ── Input ── */
function AuthInput({ placeholder, type = 'text', icon, value, onChange, disabled }: {
  placeholder: string; type?: string; icon?: React.ReactNode;
  value: string; onChange: (v: string) => void; disabled?: boolean;
}) {
  return (
    <div style={{ position: 'relative' }}>
      {icon && (
        <span style={{
          position: 'absolute', left: '12px', top: '50%', transform: 'translateY(-50%)',
          color: 'rgba(255,255,255,0.3)', pointerEvents: 'none', display: 'flex',
        }}>{icon}</span>
      )}
      <input
        type={type}
        placeholder={placeholder}
        value={value}
        onChange={e => onChange(e.target.value)}
        disabled={disabled}
        style={{
          fontFamily: '"Satoshi", sans-serif',
          width: '100%',
          height: '44px',
          background: 'rgba(255,255,255,0.05)',
          border: '1px solid rgba(255,255,255,0.1)',
          borderRadius: '8px',
          padding: icon ? '0 12px 0 36px' : '0 12px',
          color: 'rgba(255,255,255,0.85)',
          fontSize: '14px',
          outline: 'none',
          boxSizing: 'border-box',
        }}
        onFocus={e => { e.currentTarget.style.borderColor = 'rgba(255,255,255,0.3)'; }}
        onBlur={e => { e.currentTarget.style.borderColor = 'rgba(255,255,255,0.1)'; }}
      />
    </div>
  );
}

/* ── Main ── */
interface AuthPageProps { mode?: 'login' | 'signup'; }

export function AuthPage({ mode = 'login' }: AuthPageProps) {
  const router = useRouter();
  const isLogin = mode === 'login';
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!email.trim()) { setError('Enter your email.'); return; }
    if (!password.trim()) { setError('Enter your password.'); return; }
    setLoading(true); setError(null);
    try {
      const res = await fetch(`${API_BASE}${isLogin ? '/auth/login' : '/auth/signup'}`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password }),
      });
      const data = await res.json();
      if (!res.ok) { setError(data.detail || 'Something went wrong.'); return; }
      localStorage.setItem('authtrack_token', data.access_token);
      localStorage.setItem('authtrack_user_email', email);
      router.push('/scan');
    } catch { setError('Could not reach the server.'); }
    finally { setLoading(false); }
  };

  const panelBg = '#0a0a0a';
  const leftBg = '#0d0d0d';

  return (
    <main style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', minHeight: '100vh', background: panelBg }}>

      {/* ── Left panel ── */}
      <div style={{ background: leftBg, borderRight: '1px solid rgba(255,255,255,0.06)', position: 'relative', display: 'flex', flexDirection: 'column', padding: '40px' }}>
        {/* top fade */}
        <div style={{ position: 'absolute', inset: 0, background: 'linear-gradient(to top, #0d0d0d, transparent)', zIndex: 1, pointerEvents: 'none' }} />
        {/* floating paths */}
        <div style={{ position: 'absolute', inset: 0 }}>
          <FloatingPaths position={1} />
          <FloatingPaths position={-1} />
        </div>
        {/* logo */}
        <div style={{ position: 'relative', zIndex: 2, display: 'flex', alignItems: 'center', gap: '8px', color: '#fff' }}>
          <AuthLogo />
          <span style={{ fontFamily: '"Satoshi", sans-serif', fontWeight: 600, fontSize: '18px' }}>AuthTrack</span>
        </div>
        {/* quote */}
        <div style={{ position: 'relative', zIndex: 2, marginTop: 'auto' }}>
          <blockquote style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
            <p style={{ fontFamily: '"Satoshi", sans-serif', fontSize: '18px', color: 'rgba(255,255,255,0.75)', lineHeight: 1.6 }}>
              &ldquo;AuthTrack found three critical header misconfigurations in our app within
              the first 30 seconds. Incredibly useful for any security-conscious team.&rdquo;
            </p>
            <footer style={{ fontFamily: 'monospace', fontSize: '13px', fontWeight: 600, color: 'rgba(255,255,255,0.35)' }}>
              ~ Security Engineer, FinTech startup
            </footer>
          </blockquote>
        </div>
      </div>

      {/* ── Right panel ── */}
      <div style={{ background: panelBg, position: 'relative', display: 'flex', flexDirection: 'column', justifyContent: 'center', padding: '32px 24px' }}>
        {/* subtle glow */}
        <div style={{ position: 'absolute', inset: 0, zIndex: 0, pointerEvents: 'none' }}>
          <div style={{ position: 'absolute', top: 0, right: 0, width: '420px', height: '420px', transform: 'translate(20%, -40%)', borderRadius: '50%', background: 'radial-gradient(circle, rgba(255,255,255,0.025) 0%, transparent 70%)' }} />
        </div>

        {/* Back link */}
        <Link href="/" style={{ position: 'absolute', top: '28px', left: '20px', display: 'inline-flex', alignItems: 'center', gap: '4px', fontFamily: '"Satoshi", sans-serif', fontSize: '14px', color: 'rgba(255,255,255,0.4)', textDecoration: 'none', zIndex: 1 }}
          onMouseEnter={e => (e.currentTarget as HTMLAnchorElement).style.color = 'rgba(255,255,255,0.8)'}
          onMouseLeave={e => (e.currentTarget as HTMLAnchorElement).style.color = 'rgba(255,255,255,0.4)'}
        >
          <ChevronLeftIcon size={15} /> Home
        </Link>

        <div style={{ position: 'relative', zIndex: 1, width: '100%', maxWidth: '360px', margin: '0 auto', display: 'flex', flexDirection: 'column', gap: '18px' }}>

          {/* Heading */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
            <h1 style={{ fontFamily: '"Satoshi", sans-serif', fontWeight: 700, fontSize: '24px', color: '#fff', letterSpacing: '0.01em', margin: 0 }}>
              Sign In or Join Now!
            </h1>
            <p style={{ fontFamily: '"Satoshi", sans-serif', fontSize: '15px', color: 'rgba(255,255,255,0.4)', margin: 0 }}>
              {isLogin ? 'Login or create your AuthTrack account.' : 'Create your AuthTrack account.'}
            </p>
          </div>

          {/* Social buttons */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
            <AuthButton onClick={() => { window.location.href = `${API_BASE}/auth/google`; }}>
              <GoogleIcon style={{ width: '15px', height: '15px' }} />
              Continue with Google
            </AuthButton>
          </div>

          <AuthSeparator />

          {/* Email form */}
          <form onSubmit={handleSubmit} style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
            <p style={{ fontFamily: '"Satoshi", sans-serif', fontSize: '12px', color: 'rgba(255,255,255,0.3)', margin: 0, textAlign: 'left' }}>
              Enter your email address to sign in or create an account
            </p>

            <AuthInput
              placeholder="your.email@example.com"
              type="email"
              icon={<AtSignIcon size={15} />}
              value={email}
              onChange={setEmail}
              disabled={loading}
            />
            <AuthInput
              placeholder="Password"
              type="password"
              value={password}
              onChange={setPassword}
              disabled={loading}
            />

            {error && (
              <div style={{ fontFamily: '"Satoshi", sans-serif', fontSize: '13px', color: '#f87171', background: 'rgba(239,68,68,0.1)', border: '1px solid rgba(239,68,68,0.2)', borderRadius: '8px', padding: '10px 12px' }}>
                {error}
              </div>
            )}

            <AuthButton type="submit" loading={loading} white>
              {loading && <Loader2Icon size={15} style={{ animation: 'spin 1s linear infinite' }} />}
              {loading ? 'Please wait...' : isLogin ? 'Continue With Email' : 'Create Account'}
            </AuthButton>
          </form>

          {/* Switch */}
          <p style={{ fontFamily: '"Satoshi", sans-serif', fontSize: '14px', color: 'rgba(255,255,255,0.3)', textAlign: 'center', margin: 0 }}>
            {isLogin ? "Don't have an account? " : 'Already have an account? '}
            <Link href={isLogin ? '/signup' : '/login'} style={{ color: 'rgba(255,255,255,0.7)', textDecoration: 'underline', textUnderlineOffset: '3px' }}>
              {isLogin ? 'Sign up' : 'Sign in'}
            </Link>
          </p>

          {/* Legal */}
          <p style={{ fontFamily: '"Satoshi", sans-serif', fontSize: '13px', color: 'rgba(255,255,255,0.25)', margin: 0 }}>
            By clicking continue, you agree to our{' '}
            <a href="#" style={{ color: 'rgba(255,255,255,0.45)', textDecoration: 'underline', textUnderlineOffset: '3px' }}>Terms of Service</a>
            {' '}and{' '}
            <a href="#" style={{ color: 'rgba(255,255,255,0.45)', textDecoration: 'underline', textUnderlineOffset: '3px' }}>Privacy Policy</a>.
          </p>
        </div>
      </div>
    </main>
  );
}
