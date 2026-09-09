"use client";

/**
 * The tab bar across the top of every scan page.
 *
 * Each of the four flows now has its own route under /scan/<slug>; this renders
 * one link per flow and highlights the active one from the current pathname.
 * Splitting the flows into routes means a user can bookmark or link straight to,
 * say, the injection tab, which the old single-page radio group could not do.
 */

import Link from "next/link";
import { usePathname } from "next/navigation";
import { SCAN_FLOWS } from "@/lib/scan-flows";
import { cn } from "@/lib/utils";

export function ScanTabs() {
  const pathname = usePathname();

  return (
    <div className="flex flex-wrap gap-1 rounded-lg border border-border/60 bg-card/60 p-1">
      {SCAN_FLOWS.map((flow) => {
        const href = `/scan/${flow.slug}`;
        const active = pathname === href;
        const Icon = flow.icon;
        return (
          <Link
            key={flow.slug}
            href={href}
            className={cn(
              "flex items-center gap-2 rounded-md px-3 py-2 text-[13px] font-medium transition-colors",
              active
                ? "bg-secondary text-foreground shadow-sm"
                : "text-muted-foreground hover:bg-secondary/50 hover:text-foreground",
            )}
            style={active ? { color: flow.accent } : undefined}
            aria-current={active ? "page" : undefined}
          >
            <Icon className="h-4 w-4" style={active ? { color: flow.accent } : undefined} />
            {flow.short}
            {flow.badge && (
              <span
                className={cn(
                  "rounded border px-1.5 py-0.5 text-[9px] font-semibold uppercase tracking-wider",
                  flow.badgeClass || "border-border bg-secondary/60 text-muted-foreground",
                )}
              >
                {flow.badge}
              </span>
            )}
          </Link>
        );
      })}
    </div>
  );
}

export default ScanTabs;
