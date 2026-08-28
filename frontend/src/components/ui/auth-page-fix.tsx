'use client';

import React, { useState } from 'react';
import { motion } from 'framer-motion';
import { AtSignIcon, ChevronLeftIcon, Loader2Icon } from 'lucide-react';
import Link from 'next/link';
import { useRouter } from 'next/navigation';

const API_BASE = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000/api/v1';

/* ──────────────────────────────────────────── icons */
const GoogleIcon = (props: React.ComponentProps<'svg'>) => (
  <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="currentColor" {...props}>
    <path d="M12.479,14.265v-3.279h11.049c0.108,0.571,0.164,1.247,0.164,1.979c0,2.46-0.672,5.502-2.84,7.669C18.744,22.829,16.051,24,12.483,24C5.869,24,0.308,18.613,0.308,12S5.869,0,12.483,0c3.659,0,6.265,1.436,8.223,3.307L18.392,5.62c-1.404-1.317-3.307-2.341-5.913-2.341C7.65,3.279,3.873,7.171,3.873,12s3.777,8.721,8.606,8.721c3.132,0,4.916-1.258,6.059-2.401c0.927-0.927,1.537-2.251,1.777-4.059L12.479,14.265z"/>
  </svg>
);

/* ──────────────────────────────────────────── floating paths - FIXED */
function FloatingPaths({ position }: { position: number }) {
  const paths = Array.from({ length: 36 }, (_, i) => ({
    id: i,
    d: `M-${380 - i * 5 * position} -${189 + i * 6}C-${380 - i * 5 * position} -${189 + i * 6} -${312 - i * 5 * position} ${216 - i * 6} ${152 - i * 5 * position} ${343 - i * 6}C${616 - i * 5 * position} ${470 - i * 6} ${684 - i * 5 * position} ${875 - i * 6} ${684 - i * 5 * position} ${875 - i * 6}`,
    width: 0.5 + i * 0.03,
  }));
  
  return (
    <div className="pointer-events-none absolute inset-0 overflow-hidden">
      <svg 
        className="h-full w-full text-white" 
        viewBox="0 0 696 316" 
        fill="none" 
        preserveAspectRatio="xMidYMid slice"
        style={{ willChange: 'transform' }}
      >
        {paths.map((p) => (
          <motion.path
            key={p.id}
            d={p.d}
            stroke="currentColor"
            strokeWidth={p.width}
            strokeOpacity={0.08 + p.id * 0.015}
            initial={{ pathLength: 0.8, opacity: 0.3 }}
            animate={{ 
              pathLength: [0.8, 1, 0.8], 
              opacity: [0.3, 0.4, 0.3],
            }}
            transition={{ 
              duration: 25 + (p.id % 7) * 5, 
              repeat: Infinity, 
              ease: 'linear',
              delay: p.id * 0.1
            }}
            style={{ willChange: 'opacity' }}
          />
        ))}
      </svg>
    </div>
  );
}
