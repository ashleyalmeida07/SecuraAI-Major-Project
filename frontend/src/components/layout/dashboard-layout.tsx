'use client';

import React, { useState } from 'react';
import {
  Search, LayoutDashboard, Shield, Globe, FileText,
  LogOut, ChevronDown, ChevronRight,
  Activity, PanelLeftClose, PanelLeftOpen,
  Command, X, Zap, Bell, PieChart, ShieldCheck
} from 'lucide-react';
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { isAuthenticated } from '@/utils/auth';

export type NavItemData = {
  id: string;
  title: string;
  icon: React.ElementType;
  href?: string;
  badge?: number | string;
  shortcut?: string;
  children?: NavItemData[];
};

export type NavGroupData = {
  heading?: string;
  items: NavItemData[];
};

/* AuthTrack-specific navigation */
const navGroups: NavGroupData[] = [
  {
    items: [
      { id: 'search',    title: 'Search',      icon: Search,          shortcut: '⌘K' },
      { id: 'dashboard', title: 'Dashboard',   icon: LayoutDashboard, href: '/dashboard' },
      { id: 'analytics', title: 'Analytics',   icon: PieChart,        href: '/analytics' },
      { id: 'activity',  title: 'Recent Scans',icon: Activity,        href: '/dashboard' },
    ],
  },
  {
    heading: 'Security',
    items: [
      { id: 'scan-static',    title: 'Static Analysis', icon: Shield,      href: '/scan/static' },
      { id: 'scan-recon',     title: 'Recon',           icon: Globe,       href: '/scan/recon' },
      { id: 'scan-headers',   title: 'Header Audit',    icon: ShieldCheck, href: '/scan/full' },
      { id: 'scan-injection', title: 'Injection Test',  icon: Zap,         href: '/scan/injection' },
      { id: 'reports',  title: 'Reports',       icon: FileText, href: '/reports' },
    ],
  },
];

const bottomItems: NavItemData[] = [
  { id: 'logout',       title: 'Sign Out',  icon: LogOut },
];

/* ── flatten for active lookup ── */
const flatten = (items: NavItemData[]): NavItemData[] =>
  items.reduce<NavItemData[]>((acc, i) => {
    acc.push(i);
    if (i.children) acc.push(...flatten(i.children));
    return acc;
  }, []);

export const flatMockData = flatten([
  ...navGroups.flatMap(g => g.items),
  ...bottomItems,
]);

/* ── Logo with Dropdown ── */
function SidebarLogo() {
  const [open, setOpen] = useState(false);
  return (
    <div className="relative mb-6 mt-2 px-2">
      <div 
        onClick={() => setOpen(!open)}
        className="flex items-center gap-2.5 cursor-pointer select-none group"
      >
        <svg viewBox="0 0 32 32" fill="none" className="w-6 h-6">
          <path d="M16 2v10" stroke="#fff" strokeWidth="2.5" strokeLinecap="round"/>
          <path d="M10 7l6 6 6-6" stroke="#fff" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"/>
          <path d="M16 2v10" stroke="#fff" strokeWidth="2.5" strokeLinecap="round" transform="rotate(90 16 16)"/>
          <path d="M10 7l6 6 6-6" stroke="#fff" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" transform="rotate(90 16 16)"/>
          <path d="M16 2v10" stroke="#fff" strokeWidth="2.5" strokeLinecap="round" transform="rotate(180 16 16)"/>
          <path d="M10 7l6 6 6-6" stroke="#fff" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" transform="rotate(180 16 16)"/>
          <path d="M16 2v10" stroke="#fff" strokeWidth="2.5" strokeLinecap="round" transform="rotate(270 16 16)"/>
          <path d="M10 7l6 6 6-6" stroke="#fff" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" transform="rotate(270 16 16)"/>
        </svg>
        <span className="text-white font-medium text-[16px] tracking-[-0.02em]">AuthTrack</span>
        <ChevronDown className="w-3.5 h-3.5 ml-auto text-white/30 group-hover:text-white/70 transition-colors" strokeWidth={2} />
      </div>

      {open && (
        <>
          <div className="fixed inset-0 z-40" onClick={() => setOpen(false)} />
          <div className="absolute top-[36px] left-0 right-0 z-50 rounded-lg py-1 border overflow-hidden"
            style={{ background: '#141418', borderColor: 'rgba(255,255,255,0.1)', boxShadow: '0 8px 32px rgba(0,0,0,0.5)' }}>
            <Link href="/" className="flex items-center gap-2 px-3 py-2 mx-1 rounded-md text-[13px] cursor-pointer transition-colors text-white/70 hover:text-white hover:bg-white/5" onClick={() => setOpen(false)}>
              <Globe className="w-4 h-4" /> Go to Home Page
            </Link>
          </div>
        </>
      )}
    </div>
  );
}

/* ── Nav Item ── */
function NavItem({ item, activeId, onSelect, level = 0 }: {
  item: NavItemData; activeId: string; onSelect: (id: string) => void; level?: number;
}) {
  const isActive = activeId === item.id;
  const hasChildren = !!item.children;
  const [childOpen, setChildOpen] = useState(false);

  const handleClick = () => {
    if (hasChildren) { setChildOpen(!childOpen); return; }
    onSelect(item.id);
  };

  const activeBg = 'rgba(164,132,215,0.15)';
  const activeColor = 'rgba(200,170,255,1)';

  return (
    <div className="flex flex-col w-full">
      <div
        onClick={handleClick}
        className="group flex items-center justify-between rounded-[6px] cursor-pointer transition-all duration-150 select-none"
        style={{
          padding: `7px 10px 7px ${level * 12 + 10}px`,
          background: isActive ? activeBg : 'transparent',
          color: isActive ? activeColor : 'rgba(255,255,255,0.5)',
        }}
        onMouseEnter={e => { if (!isActive) (e.currentTarget as HTMLDivElement).style.background = 'rgba(255,255,255,0.04)'; if (!isActive) (e.currentTarget as HTMLDivElement).style.color = 'rgba(255,255,255,0.85)'; }}
        onMouseLeave={e => { if (!isActive) (e.currentTarget as HTMLDivElement).style.background = 'transparent'; if (!isActive) (e.currentTarget as HTMLDivElement).style.color = 'rgba(255,255,255,0.5)'; }}
      >
        <div className="flex items-center gap-2.5">
          <item.icon style={{ width: 15, height: 15, color: isActive ? activeColor : 'rgba(255,255,255,0.35)' }} strokeWidth={1.5} />
          <span style={{ fontSize: 13, letterSpacing: '0.01em', fontFamily: '"Satoshi", sans-serif' }}>{item.title}</span>
        </div>
        <div className="flex items-center gap-2">
          {item.shortcut && (
            <kbd className="hidden group-hover:inline-flex items-center h-5 px-1.5 text-[10px] font-mono rounded-[4px]"
              style={{ color: 'rgba(255,255,255,0.3)', background: 'rgba(255,255,255,0.06)', border: '1px solid rgba(255,255,255,0.08)' }}>
              {item.shortcut}
            </kbd>
          )}
          {item.badge && (
            <span className="flex items-center justify-center min-w-[18px] h-[18px] px-1 text-[10px] font-medium rounded-full"
              style={{ background: 'rgba(164,132,215,0.2)', color: 'rgba(200,170,255,1)' }}>
              {item.badge}
            </span>
          )}
          {hasChildren && (
            <ChevronRight style={{ width: 12, height: 12, color: 'rgba(255,255,255,0.25)', transform: childOpen ? 'rotate(90deg)' : 'rotate(0deg)', transition: 'transform 0.2s' }} strokeWidth={2} />
          )}
        </div>
      </div>

      {hasChildren && (
        <div className={`grid transition-[grid-template-rows,opacity] duration-200 ease-in-out ${childOpen ? 'grid-rows-[1fr] opacity-100' : 'grid-rows-[0fr] opacity-0'}`}>
          <div className="overflow-hidden min-h-0 flex flex-col gap-0.5 mt-0.5 relative">
            <div className="absolute top-0 bottom-0 border-l" style={{ left: `${level * 12 + 17}px`, borderColor: 'rgba(164,132,215,0.15)' }} />
            {item.children!.map(child => (
              <NavItem key={child.id} item={child} activeId={activeId} onSelect={onSelect} level={level + 1} />
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

/* ── Sidebar Nav ── */
export function SidebarNav({
  activeId, onSelect,
}: {
  activeId?: string;
  onSelect?: (id: string) => void;
}) {
  const [internalId, setInternalId] = useState('dashboard');
  const currentId = activeId ?? internalId;
  const handleSelect = onSelect ?? setInternalId;

  return (
    <div className="flex flex-col h-full py-3 px-2" style={{ width: 260, fontFamily: '"Satoshi", sans-serif' }}>
      <SidebarLogo />

      <div className="flex-1 overflow-y-auto flex flex-col gap-4 mt-1 px-1" style={{ scrollbarWidth: 'none' }}>
        {navGroups.map((g, i) => (
          <div key={i} className="flex flex-col gap-0.5">
            {g.heading && (
              <span className="px-2.5 mb-1 text-[11px] font-semibold uppercase tracking-wider"
                style={{ color: 'rgba(255,255,255,0.2)' }}>
                {g.heading}
              </span>
            )}
            {g.items.map(item => (
              <NavItem key={item.id} item={item} activeId={currentId} onSelect={handleSelect} />
            ))}
          </div>
        ))}
      </div>

      <div className="mt-auto pt-4 px-1 flex flex-col gap-0.5" style={{ borderTop: '1px solid rgba(255,255,255,0.06)' }}>
        {bottomItems.map(item => (
          <NavItem key={item.id} item={item} activeId={currentId} onSelect={handleSelect} />
        ))}
      </div>
    </div>
  );
}

/* ── Dashboard Layout ── */
export function DashboardLayout({ children, activeId = 'dashboard' }: {
  children: React.ReactNode;
  activeId?: string;
}) {
  const router = useRouter();
  const [sidebarOpen, setSidebarOpen] = useState(true);
  const [searchOpen, setSearchOpen] = useState(false);
  const [activeNav, setActiveNav] = useState(activeId);
  const [userEmail, setUserEmail] = useState<string | null>(null);
  const [isMounted, setIsMounted] = useState(false);
  const [isAuth, setIsAuth] = useState(false);

  const activeItem = flatMockData.find(i => i.id === activeNav);
  const activeTitle = activeItem?.title ?? 'Dashboard';
  const initials = userEmail ? userEmail[0].toUpperCase() : 'U';
  const displayName = userEmail ? userEmail.split('@')[0] : 'User';

  React.useEffect(() => {
    setIsMounted(true);
    if (!isAuthenticated()) {
      router.push('/login');
    } else {
      setIsAuth(true);
      setUserEmail(localStorage.getItem('authtrack_user_email'));
    }
  }, [router]);

  const handleNavSelect = (id: string) => {
    if (id === 'search') { setSearchOpen(true); return; }
    if (id === 'logout') {
      localStorage.removeItem('authtrack_token');
      localStorage.removeItem('authtrack_user_email');
      router.push('/login');
      return;
    }
    setActiveNav(id);
    const item = flatMockData.find(i => i.id === id);
    if (item?.href) router.push(item.href);
  };

  if (!isMounted || !isAuth) {
    return <div style={{ background: '#0a0a0a', width: '100vw', height: '100vh' }} />;
  }

  return (
    <div className="flex h-screen overflow-hidden" style={{ background: '#0a0a0a' }}>
      {/* Sidebar */}
      <div
        className="h-full shrink-0 overflow-hidden transition-all duration-300 ease-in-out"
        style={{
          width: sidebarOpen ? 260 : 0,
          opacity: sidebarOpen ? 1 : 0,
          background: '#0d0d0f',
          borderRight: sidebarOpen ? '1px solid rgba(255,255,255,0.06)' : 'none',
        }}
      >
        <SidebarNav activeId={activeNav} onSelect={handleNavSelect} />
      </div>

      {/* Main content */}
      <div className="flex-1 flex flex-col min-w-0 overflow-hidden">

        {/* Top bar */}
        <div className="h-14 shrink-0 flex items-center justify-between px-4"
          style={{ background: '#0d0d0f', borderBottom: '1px solid rgba(255,255,255,0.06)' }}>
          <div className="flex items-center gap-3">
            <button onClick={() => setSidebarOpen(!sidebarOpen)}
              className="p-1.5 rounded-md transition-colors"
              style={{ color: 'rgba(255,255,255,0.4)' }}
              onMouseEnter={e => (e.currentTarget as HTMLButtonElement).style.background = 'rgba(255,255,255,0.06)'}
              onMouseLeave={e => (e.currentTarget as HTMLButtonElement).style.background = 'transparent'}>
              {sidebarOpen
                ? <PanelLeftClose className="w-[18px] h-[18px]" strokeWidth={1.5} />
                : <PanelLeftOpen className="w-[18px] h-[18px]" strokeWidth={1.5} />}
            </button>
            <div className="flex items-center gap-2 text-sm" style={{ fontFamily: '"Satoshi", sans-serif' }}>
              <span style={{ color: 'rgba(255,255,255,0.35)' }}>AuthTrack</span>
              <span style={{ color: 'rgba(255,255,255,0.2)' }}>/</span>
              <span className="font-medium" style={{ color: 'rgba(255,255,255,0.85)' }}>{activeTitle}</span>
            </div>
          </div>

          <div className="flex items-center gap-3">
            {/* Search trigger */}
            <button onClick={() => setSearchOpen(true)}
              className="hidden md:flex items-center gap-2 h-8 px-3 rounded-md text-[13px] transition-colors"
              style={{ background: 'rgba(255,255,255,0.05)', color: 'rgba(255,255,255,0.35)', border: '1px solid rgba(255,255,255,0.07)', fontFamily: '"Satoshi", sans-serif' }}
              onMouseEnter={e => (e.currentTarget as HTMLButtonElement).style.background = 'rgba(255,255,255,0.08)'}
              onMouseLeave={e => (e.currentTarget as HTMLButtonElement).style.background = 'rgba(255,255,255,0.05)'}>
              <Search className="w-3.5 h-3.5" />
              Search...
              <kbd className="text-[10px] font-mono ml-2" style={{ color: 'rgba(255,255,255,0.2)' }}>⌘K</kbd>
            </button>

            {/* Notifications */}
            <button className="p-1.5 rounded-md relative transition-colors"
              style={{ color: 'rgba(255,255,255,0.35)' }}
              onMouseEnter={e => (e.currentTarget as HTMLButtonElement).style.background = 'rgba(255,255,255,0.06)'}
              onMouseLeave={e => (e.currentTarget as HTMLButtonElement).style.background = 'transparent'}>
              <Bell className="w-[17px] h-[17px]" strokeWidth={1.5} />
              <span className="absolute top-1 right-1 w-1.5 h-1.5 rounded-full" style={{ background: 'rgba(164,132,215,1)' }} />
            </button>

            {/* User avatar */}
            <Link href="/dashboard">
              <div className="flex items-center gap-2 px-2 py-1.5 rounded-[8px] cursor-pointer transition-colors"
                style={{ background: 'rgba(164,132,215,0.12)', border: '1px solid rgba(164,132,215,0.2)' }}
                onMouseEnter={e => (e.currentTarget as HTMLDivElement).style.background = 'rgba(164,132,215,0.2)'}
                onMouseLeave={e => (e.currentTarget as HTMLDivElement).style.background = 'rgba(164,132,215,0.12)'}>
                <div className="w-6 h-6 rounded-full flex items-center justify-center text-[11px] font-bold text-white"
                  style={{ background: 'linear-gradient(135deg, rgba(164,132,215,0.9) 0%, rgba(123,57,252,0.9) 100%)' }}>
                  {initials}
                </div>
                <span className="text-[13px] font-medium hidden md:block" style={{ color: 'rgba(255,255,255,0.75)', fontFamily: '"Satoshi", sans-serif' }}>
                  {displayName}
                </span>
              </div>
            </Link>
          </div>
        </div>

        {/* Page content */}
        <div className="flex-1 overflow-y-auto p-6 md:p-8" style={{ scrollbarWidth: 'none' }}>
          {children}
        </div>
      </div>

      {/* Search modal */}
      {searchOpen && (
        <div className="absolute inset-0 z-[60] flex items-start justify-center pt-[15vh] px-4"
          style={{ background: 'rgba(0,0,0,0.6)', backdropFilter: 'blur(8px)' }}>
          <div className="absolute inset-0" onClick={() => setSearchOpen(false)} />
          <div className="relative w-full max-w-xl rounded-xl overflow-hidden"
            style={{ background: '#141418', border: '1px solid rgba(255,255,255,0.1)', boxShadow: '0 24px 64px rgba(0,0,0,0.6)' }}>
            <div className="flex items-center px-4" style={{ borderBottom: '1px solid rgba(255,255,255,0.08)' }}>
              <Search className="w-[17px] h-[17px] mr-3 shrink-0" strokeWidth={1.5} style={{ color: 'rgba(255,255,255,0.3)' }} />
              <input autoFocus placeholder="Search scans, findings, endpoints..."
                className="flex-1 py-4 outline-none text-[14px] bg-transparent"
                style={{ color: '#fff', fontFamily: '"Satoshi", sans-serif' }}
              />
              <kbd onClick={() => setSearchOpen(false)}
                className="hidden sm:inline-flex items-center h-5 px-1.5 ml-2 text-[10px] font-mono rounded-[4px] cursor-pointer"
                style={{ color: 'rgba(255,255,255,0.3)', background: 'rgba(255,255,255,0.06)', border: '1px solid rgba(255,255,255,0.1)' }}>
                ESC
              </kbd>
              <button onClick={() => setSearchOpen(false)} className="ml-3 p-1 rounded-md"
                style={{ color: 'rgba(255,255,255,0.3)' }}
                onMouseEnter={e => (e.currentTarget as HTMLButtonElement).style.color = '#fff'}
                onMouseLeave={e => (e.currentTarget as HTMLButtonElement).style.color = 'rgba(255,255,255,0.3)'}>
                <X className="w-[17px] h-[17px]" strokeWidth={1.5} />
              </button>
            </div>
            <div className="p-8 flex flex-col items-center justify-center">
              <Command className="w-6 h-6 mb-2" strokeWidth={1.5} style={{ color: 'rgba(255,255,255,0.15)' }} />
              <p className="text-[13px]" style={{ color: 'rgba(255,255,255,0.3)', fontFamily: '"Satoshi", sans-serif' }}>
                Type a command or search...
              </p>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

export default DashboardLayout;
