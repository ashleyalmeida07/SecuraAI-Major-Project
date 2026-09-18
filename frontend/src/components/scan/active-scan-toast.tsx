"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { Loader2, ArrowRight } from "lucide-react";
import { useScanContext } from "@/contexts/scan-context";
import { flowByMode } from "@/lib/scan-flows";

export function ActiveScanToast() {
  const { activeMode, getState } = useScanContext();
  const pathname = usePathname();

  if (!activeMode) return null;

  const activeHref = `/scan/${activeMode}`;
  
  // Don't show the toast if we're already on the active scan's page
  if (pathname === activeHref) return null;

  const flow = flowByMode(activeMode);
  const state = getState(activeMode);
  const Icon = flow.icon;

  return (
    <Link 
      href={activeHref}
      className="fixed bottom-6 right-6 z-50 flex items-center gap-4 rounded-lg border border-border/50 bg-card/95 p-4 shadow-xl backdrop-blur-sm transition-transform hover:-translate-y-1"
    >
      <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-full bg-secondary">
        <Icon className="h-5 w-5" style={{ color: flow.accent }} />
      </div>
      <div className="flex flex-col">
        <div className="flex items-center gap-2">
          <span className="text-sm font-semibold">{flow.short} Running</span>
          <Loader2 className="h-3.5 w-3.5 animate-spin text-primary" />
        </div>
        <span className="text-xs text-muted-foreground line-clamp-1 max-w-[200px]">
          {state.activity || "Initializing..."}
        </span>
      </div>
      <ArrowRight className="h-4 w-4 text-muted-foreground ml-2" />
    </Link>
  );
}
