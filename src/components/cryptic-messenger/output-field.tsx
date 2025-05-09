"use client";

import type React from 'react';
import { Label } from '@/components/ui/label';
import { Skeleton } from '@/components/ui/skeleton';
import { cn } from '@/lib/utils';
import { CopyToClipboardButton } from './copy-to-clipboard-button';

interface OutputFieldProps {
  label: string;
  value: string | null;
  isLoading?: boolean;
  isMonospace?: boolean;
  rows?: number;
  success?: boolean; // For success animation
  placeholder?: string;
}

export function OutputField({
  label,
  value,
  isLoading = false,
  isMonospace = true,
  rows = 3,
  success = false,
  placeholder = "N/A"
}: OutputFieldProps) {
  const displayValue = value || "";
  
  return (
    <div className="space-y-1 w-full">
      <Label htmlFor={label.toLowerCase().replace(/\s+/g, '-')} className="text-sm font-medium text-foreground/80">{label}</Label>
      <div
        className={cn(
          'relative rounded-md border bg-muted/30 p-3 shadow-sm transition-all ease-in-out duration-300 min-h-[60px]',
          success && 'animate-flash-success border-accent',
          isLoading && 'bg-muted/10'
        )}
        style={{ '--tw-border-opacity': success ? 1 : 0.5 } as React.CSSProperties}
      >
        {isLoading ? (
          <div className="space-y-1.5 py-1">
            {Array.from({ length: rows > 1 ? Math.min(rows, 3) : 1 }).map((_, i) => (
               <Skeleton key={i} className={cn("h-4 w-full", i > 0 && "w-[80%]")} />
            ))}
          </div>
        ) : (
          <pre
            id={label.toLowerCase().replace(/\s+/g, '-')}
            className={cn(
              'whitespace-pre-wrap break-all text-sm text-foreground',
              isMonospace && 'font-mono',
              !displayValue && 'text-muted-foreground italic'
            )}
            style={{ minHeight: rows > 1 ? `${rows * 1.5}em` : '1.5em' }}
            aria-label={`${label} value`}
          >
            {displayValue || placeholder}
          </pre>
        )}
        {displayValue && !isLoading && (
          <CopyToClipboardButton
            textToCopy={displayValue}
            className="absolute right-1.5 top-1.5 text-muted-foreground hover:text-foreground"
          />
        )}
      </div>
    </div>
  );
}