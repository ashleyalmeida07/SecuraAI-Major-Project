"use client";

/**
 * Reusable Recharts primitives for security reports and the dashboard.
 * Kept in one client module so chart rendering (which must run client-side)
 * is isolated from the rest of the app.
 */

import {
  PieChart, Pie, Cell, ResponsiveContainer, Tooltip,
  BarChart, Bar, XAxis, YAxis, CartesianGrid, LabelList,
  RadialBarChart, RadialBar, PolarAngleAxis,
} from "recharts";

export const SEVERITY_COLORS: Record<string, string> = {
  critical: "#ef4444",
  high: "#f97316",
  medium: "#f59e0b",
  low: "#3b82f6",
  info: "#8b5cf6",
};

/** Numeric weight per severity — used for a simple aggregate risk score. */
export const SEVERITY_WEIGHT: Record<string, number> = {
  critical: 40,
  high: 20,
  medium: 8,
  low: 3,
  info: 1,
};

export const TYPE_COLORS: string[] = [
  "#00d4ff", "#a78bfa", "#10b981", "#f97316",
  "#f59e0b", "#3b82f6", "#ec4899", "#64748b",
];

const AXIS_COLOR = "rgba(255,255,255,0.45)";
const GRID_COLOR = "rgba(255,255,255,0.08)";

export interface ChartDatum {
  name: string;
  value: number;
  color?: string;
}

const prettify = (v: unknown) => String(v).replace(/_/g, " ");

function DarkTooltip({ active, payload, label }: any) {
  if (!active || !payload || !payload.length) return null;
  return (
    <div
      style={{
        background: "rgba(10,15,25,0.96)",
        border: "1px solid rgba(255,255,255,0.15)",
        borderRadius: 8,
        padding: "0.5rem 0.75rem",
        fontSize: 12,
        boxShadow: "0 8px 24px rgba(0,0,0,0.4)",
      }}
    >
      {label != null && (
        <div style={{ color: "rgba(255,255,255,0.55)", marginBottom: 4, textTransform: "capitalize" }}>
          {prettify(label)}
        </div>
      )}
      {payload.map((p: any, i: number) => (
        <div key={i} style={{ color: p.color || p.fill || "#fff", fontWeight: 600, textTransform: "capitalize" }}>
          {p.name && p.name !== "value" ? `${prettify(p.name)}: ` : ""}
          {p.value}
        </div>
      ))}
    </div>
  );
}

function ChartEmpty({ height, label }: { height: number; label: string }) {
  return (
    <div
      className="flex items-center justify-center text-xs text-muted-foreground italic"
      style={{ height }}
    >
      {label}
    </div>
  );
}

/** Donut chart with a total in the center. Segment colors come from
 *  each datum's `color`, else a severity map, else the categorical palette. */
export function DonutChart({
  data,
  height = 200,
  centerLabel = "Total",
  useSeverityColors = false,
  emptyLabel = "No data",
}: {
  data: ChartDatum[];
  height?: number;
  centerLabel?: string;
  useSeverityColors?: boolean;
  emptyLabel?: string;
}) {
  const filtered = data.filter((d) => d.value > 0);
  const total = filtered.reduce((s, d) => s + d.value, 0);
  if (total === 0) return <ChartEmpty height={height} label={emptyLabel} />;

  return (
    <div className="relative" style={{ width: "100%", height }}>
      <ResponsiveContainer width="100%" height="100%">
        <PieChart>
          <Pie
            data={filtered}
            dataKey="value"
            nameKey="name"
            cx="50%"
            cy="50%"
            innerRadius="62%"
            outerRadius="88%"
            paddingAngle={filtered.length > 1 ? 2 : 0}
            stroke="none"
          >
            {filtered.map((d, i) => (
              <Cell
                key={i}
                fill={
                  d.color ||
                  (useSeverityColors ? SEVERITY_COLORS[d.name] : undefined) ||
                  TYPE_COLORS[i % TYPE_COLORS.length]
                }
              />
            ))}
          </Pie>
          <Tooltip content={<DarkTooltip />} />
        </PieChart>
      </ResponsiveContainer>
      <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none">
        <span className="text-2xl font-extrabold text-foreground leading-none">{total}</span>
        <span className="mt-1 text-[10px] uppercase tracking-wider text-muted-foreground">{centerLabel}</span>
      </div>
    </div>
  );
}

/** Horizontal bar chart for category counts (endpoint types, injection types…). */
export function CategoryBars({
  data,
  height = 220,
  color = "#00d4ff",
  emptyLabel = "No data",
}: {
  data: ChartDatum[];
  height?: number;
  color?: string;
  emptyLabel?: string;
}) {
  if (!data.length) return <ChartEmpty height={height} label={emptyLabel} />;
  return (
    <ResponsiveContainer width="100%" height={height}>
      <BarChart data={data} layout="vertical" margin={{ left: 8, right: 28, top: 4, bottom: 4 }}>
        <CartesianGrid horizontal={false} stroke={GRID_COLOR} />
        <XAxis type="number" allowDecimals={false} stroke={AXIS_COLOR} fontSize={11} tickLine={false} axisLine={false} />
        <YAxis
          type="category"
          dataKey="name"
          width={120}
          stroke={AXIS_COLOR}
          fontSize={11}
          tickLine={false}
          axisLine={false}
          tickFormatter={prettify}
        />
        <Tooltip content={<DarkTooltip />} cursor={{ fill: "rgba(255,255,255,0.04)" }} />
        <Bar dataKey="value" radius={[0, 4, 4, 0]} maxBarSize={22}>
          {data.map((d, i) => (
            <Cell key={i} fill={d.color || color} />
          ))}
          <LabelList dataKey="value" position="right" fill="rgba(255,255,255,0.7)" fontSize={11} />
        </Bar>
      </BarChart>
    </ResponsiveContainer>
  );
}

/** Vertical grouped bar chart (used for the dashboard's scans-by-type overview). */
export function VerticalBars({
  data,
  height = 240,
  emptyLabel = "No data",
}: {
  data: ChartDatum[];
  height?: number;
  emptyLabel?: string;
}) {
  if (!data.length) return <ChartEmpty height={height} label={emptyLabel} />;
  return (
    <ResponsiveContainer width="100%" height={height}>
      <BarChart data={data} margin={{ left: -12, right: 8, top: 8, bottom: 4 }}>
        <CartesianGrid vertical={false} stroke={GRID_COLOR} />
        <XAxis dataKey="name" stroke={AXIS_COLOR} fontSize={11} tickLine={false} axisLine={false} tickFormatter={prettify} />
        <YAxis allowDecimals={false} stroke={AXIS_COLOR} fontSize={11} tickLine={false} axisLine={false} />
        <Tooltip content={<DarkTooltip />} cursor={{ fill: "rgba(255,255,255,0.04)" }} />
        <Bar dataKey="value" radius={[4, 4, 0, 0]} maxBarSize={48}>
          {data.map((d, i) => (
            <Cell key={i} fill={d.color || TYPE_COLORS[i % TYPE_COLORS.length]} />
          ))}
          <LabelList dataKey="value" position="top" fill="rgba(255,255,255,0.7)" fontSize={11} />
        </Bar>
      </BarChart>
    </ResponsiveContainer>
  );
}

/** Radial gauge for a 0–100 risk score, colored by band. */
export function RiskGauge({ score, height = 200 }: { score: number; height?: number }) {
  const clamped = Math.max(0, Math.min(100, Math.round(score)));
  const color =
    clamped >= 75 ? "#ef4444" : clamped >= 50 ? "#f97316" : clamped >= 25 ? "#f59e0b" : "#22c55e";
  const band =
    clamped >= 75 ? "Critical" : clamped >= 50 ? "High" : clamped >= 25 ? "Moderate" : "Low";
  const data = [{ name: "risk", value: clamped, fill: color }];

  return (
    <div className="relative" style={{ width: "100%", height }}>
      <ResponsiveContainer width="100%" height="100%">
        <RadialBarChart innerRadius="68%" outerRadius="100%" data={data} startAngle={220} endAngle={-40}>
          <PolarAngleAxis type="number" domain={[0, 100]} tick={false} />
          <RadialBar background={{ fill: "rgba(255,255,255,0.06)" } as any} dataKey="value" cornerRadius={8} />
        </RadialBarChart>
      </ResponsiveContainer>
      <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none">
        <span className="text-3xl font-extrabold leading-none" style={{ color }}>{clamped}</span>
        <span className="mt-1 text-[11px] font-semibold" style={{ color }}>{band} Risk</span>
      </div>
    </div>
  );
}

/**
 * Compute a 0–100 risk score from a severity→count map.
 * Saturating so a handful of criticals reads as high risk without
 * a single finding pinning it to 100.
 */
export function computeRiskScore(counts: Record<string, number>): number {
  const raw = Object.entries(counts).reduce(
    (sum, [sev, n]) => sum + (SEVERITY_WEIGHT[sev] || 0) * (n || 0),
    0,
  );
  if (raw === 0) return 0;
  // Saturating curve: 100 * (1 - e^(-raw/60)) → ~50 at raw 40, ~80 at raw 100.
  return Math.round(100 * (1 - Math.exp(-raw / 60)));
}
