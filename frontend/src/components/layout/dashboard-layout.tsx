'use client';

import React, { useState } from 'react';
import { SidebarNav, flatMockData } from '@/components/ui/dashboard-sidebar';
import { PanelLeftClose, PanelLeftOpen, Search, X, Command } from 'lucide-react';
import { useRouter } from 'next/navigation';

interface DashboardLayoutProps {
  children: React.ReactNode;
  activeId?: string;
  activeWorkspace?: string;
}

export function DashboardLayout({ 
  children, 
  activeId = 'dashboard', 
  activeWorkspace = 'AuthTrack SecOps' 
}: DashboardLayoutProps) {
  const router = useRouter();
  const [isOpen, setIsOpen] = useState(true);
  const [isSearchOpen, setIsSearchOpen] = useState(false);
  const [workspace, setWorkspace] = useState(activeWorkspace);

  const activeItem = flatMockData.find(i => i.id === activeId);
  const activeTitle = activeItem ? activeItem.title : 'Dashboard';

  const handleSelect = (id: string) => {
    if (id === 'search') {
      setIsSearchOpen(true);
      return;
    }
    if (id === 'dashboard') router.push('/dashboard');
    if (id === 'scan-static' || id === 'scan-headers' || id === 'scan-recon') router.push('/scan');
    if (id === 'logout') router.push('/login');
  };

  return (
    <div className="flex flex-col items-center justify-center w-full min-h-screen bg-background dark">
      <div className="relative w-full h-screen bg-card flex overflow-hidden">
        
        {/* Sidebar */}
        <div 
          className={`h-full transition-all duration-300 ease-in-out shrink-0 overflow-hidden bg-card/50 border-r border-border/50 ${
            isOpen ? 'w-[260px] opacity-100' : 'w-0 opacity-0 border-none'
          }`}
        >
          <SidebarNav 
            className="w-[260px] border-none bg-transparent" 
            activeId={activeId}
            onSelect={handleSelect}
            activeWorkspace={workspace}
            onWorkspaceSelect={setWorkspace}
          />
        </div>
        
        {/* Main Content Area */}
        <div className="flex-1 bg-background flex flex-col min-w-0 transition-all duration-300">
           {/* Top Header */}
           <div className="h-14 border-b border-border/50 flex items-center px-4 justify-between bg-card shrink-0">
             <div className="flex items-center gap-3">
               <button 
                 onClick={() => setIsOpen(!isOpen)}
                 className="p-1.5 rounded-md text-muted-foreground hover:bg-black/5 dark:hover:bg-white/5 hover:text-foreground transition-colors"
               >
                 {isOpen ? <PanelLeftClose className="w-[18px] h-[18px]" strokeWidth={1.5} /> : <PanelLeftOpen className="w-[18px] h-[18px]" strokeWidth={1.5} />}
               </button>
               <div className="flex items-center gap-2 text-sm text-muted-foreground">
                 <span className="truncate">{workspace}</span>
                 <span>/</span>
                 <span className="font-medium text-foreground truncate">{activeTitle}</span>
               </div>
             </div>
             
             <div className="flex items-center gap-3">
               <div className="flex items-center text-sm font-medium text-muted-foreground cursor-pointer hover:text-foreground">
                 <Search className="w-4 h-4 mr-2" onClick={() => setIsSearchOpen(true)} />
                 <span onClick={() => setIsSearchOpen(true)}>Search...</span>
               </div>
             </div>
           </div>

           {/* Page Content */}
           <div className="p-6 md:p-8 overflow-y-auto [&::-webkit-scrollbar]:hidden [-ms-overflow-style:none] [scrollbar-width:none] flex-1">
             {children}
           </div>
        </div>

        {/* Search Modal */}
        {isSearchOpen && (
          <div className="absolute inset-0 z-[60] flex items-start justify-center pt-[15vh] bg-background/80 backdrop-blur-sm px-4">
            <div className="absolute inset-0" onClick={() => setIsSearchOpen(false)} />
            <div className="relative w-full max-w-xl bg-card border border-border/50 rounded-xl shadow-2xl overflow-hidden animate-in fade-in zoom-in-95 duration-200">
              <div className="flex items-center px-4 border-b border-border/50">
                <Search className="w-[18px] h-[18px] text-muted-foreground/70 mr-3 shrink-0" strokeWidth={1.5} />
                <input 
                  autoFocus
                  className="flex-1 bg-transparent py-4 outline-none text-[14px] text-foreground placeholder:text-muted-foreground/50"
                  placeholder="Search vulnerabilities, projects, or endpoints..."
                />
                <kbd 
                  onClick={() => setIsSearchOpen(false)}
                  className="hidden sm:inline-flex items-center justify-center h-5 px-1.5 ml-2 text-[10px] font-medium font-mono text-muted-foreground/70 bg-black/5 dark:bg-white/10 border border-black/10 dark:border-white/10 rounded-[4px] cursor-pointer hover:text-foreground hover:bg-black/10 dark:hover:bg-white/20 transition-colors"
                >
                  ESC
                </kbd>
                <button 
                  onClick={() => setIsSearchOpen(false)}
                  className="ml-3 p-1 rounded-md text-muted-foreground/70 hover:bg-black/5 dark:hover:bg-white/10 hover:text-foreground transition-colors"
                >
                  <X className="w-[18px] h-[18px]" strokeWidth={1.5} />
                </button>
              </div>
              <div className="p-2 py-8 flex flex-col items-center justify-center">
                 <Command className="w-6 h-6 text-muted-foreground/30 mb-2" strokeWidth={1.5} />
                 <p className="text-[13px] text-muted-foreground font-medium">Type a command or search...</p>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
