"use client";

/**
 * The tab bar across the top of every scan page.
 *
 * Renders one link per flow in a single horizontally-scrollable row.
 * A chevron arrow button appears on the right when there is overflow to scroll.
 */

import { useRef, useState, useEffect } from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { ChevronRight, Loader2 } from "lucide-react";
import { SCAN_FLOWS } from "@/lib/scan-flows";
import { useScanContext } from "@/contexts/scan-context";
import { cn } from "@/lib/utils";

export function ScanTabs() {
  const pathname = usePathname();
  const { getState } = useScanContext();
  const scrollRef = useRef<HTMLDivElement>(null);
  const [canScrollRight, setCanScrollRight] = useState(false);

  const checkScroll = () => {
    const el = scrollRef.current;
    if (!el) return;
    setCanScrollRight(el.scrollLeft + el.clientWidth < el.scrollWidth - 2);
  };

  useEffect(() => {
    checkScroll();
    const el = scrollRef.current;
    if (!el) return;
    el.addEventListener("scroll", checkScroll, { passive: true });
    const ro = new ResizeObserver(checkScroll);
    ro.observe(el);
    return () => { el.removeEventListener("scroll", checkScroll); ro.disconnect(); };
  }, []);

  const scrollRight = () => {
    scrollRef.current?.scrollBy({ left: 160, behavior: "smooth" });
  };

  return (
    <div className="relative flex items-center rounded-lg border border-border/60 bg-card/60">
      {/* Scrollable tab strip */}
      <div
        ref={scrollRef}
        className="flex gap-1 overflow-x-auto scroll-smooth p-1 [scrollbar-width:none] [&::-webkit-scrollbar]:hidden"
      >
        {SCAN_FLOWS.map((flow) => {
          const href = `/scan/${flow.slug}`;
          const active = pathname === href;
          const isRunning = getState(flow.mode).scanning;
          const Icon = flow.icon;
          return (
            <Link
              key={flow.slug}
              href={href}
              className={cn(
                "flex shrink-0 items-center gap-2 rounded-md px-3 py-2 text-[13px] font-medium transition-colors",
                active
                  ? "bg-secondary text-foreground shadow-sm"
                  : "text-muted-foreground hover:bg-secondary/50 hover:text-foreground",
              )}
              style={active ? { color: flow.accent } : undefined}
              aria-current={active ? "page" : undefined}
            >
              <Icon className="h-4 w-4" style={active ? { color: flow.accent } : undefined} />
              {flow.short}
              {isRunning ? (
                <span className="flex items-center gap-1 rounded border border-primary/30 bg-primary/10 px-1.5 py-0.5 text-[9px] font-semibold uppercase tracking-wider text-primary">
                  <Loader2 className="h-2.5 w-2.5 animate-spin" />
                  Running
                </span>
              ) : flow.badge ? (
                <span
                  className={cn(
                    "rounded border px-1.5 py-0.5 text-[9px] font-semibold uppercase tracking-wider",
                    flow.badgeClass || "border-border bg-secondary/60 text-muted-foreground",
                  )}
                >
                  {flow.badge}
                </span>
              ) : null}
            </Link>
          );
        })}
      </div>

      {/* Right fade + scroll arrow */}
      {canScrollRight && (
        <>
          {/* Gradient fade */}
          <div className="pointer-events-none absolute right-8 top-0 h-full w-10 bg-gradient-to-r from-transparent to-card/90" />
          {/* Arrow button */}
          <button
            onClick={scrollRight}
            className="absolute right-1 flex h-7 w-7 shrink-0 items-center justify-center rounded-md border border-border/60 bg-card text-muted-foreground transition-colors hover:bg-secondary hover:text-foreground"
            aria-label="Scroll tabs right"
          >
            <ChevronRight className="h-4 w-4" />
          </button>
        </>
      )}
    </div>
  );
}

export default ScanTabs;
