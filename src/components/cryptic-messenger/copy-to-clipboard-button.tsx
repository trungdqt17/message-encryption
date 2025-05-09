"use client";

import type React from 'react';
import { useState, useEffect } from 'react';
import { Check, ClipboardCopy } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from '@/components/ui/tooltip';
import { cn } from '@/lib/utils';

interface CopyToClipboardButtonProps {
  textToCopy: string;
  className?: string;
  tooltipText?: string;
}

export function CopyToClipboardButton({
  textToCopy,
  className,
  tooltipText = "Copy to clipboard"
}: CopyToClipboardButtonProps) {
  const [isCopied, setIsCopied] = useState(false);
  const [isClient, setIsClient] = useState(false);

  useEffect(() => {
    setIsClient(true);
  }, []);

  const handleCopy = async () => {
    if (!isClient || !navigator.clipboard) return;
    try {
      await navigator.clipboard.writeText(textToCopy);
      setIsCopied(true);
      setTimeout(() => setIsCopied(false), 2000); // Reset after 2 seconds
    } catch (err) {
      console.error('Failed to copy text: ', err);
      // Optionally, show an error toast to the user
    }
  };

  if (!isClient) {
    return null; // Or a placeholder button
  }

  return (
    <TooltipProvider>
      <Tooltip>
        <TooltipTrigger asChild>
          <Button
            variant="ghost"
            size="icon"
            onClick={handleCopy}
            className={cn('h-8 w-8 p-1.5', className)}
            aria-label={isCopied ? "Copied!" : tooltipText}
          >
            {isCopied ? <Check className="h-4 w-4 text-green-500" /> : <ClipboardCopy className="h-4 w-4" />}
          </Button>
        </TooltipTrigger>
        <TooltipContent>
          <p>{isCopied ? "Copied!" : tooltipText}</p>
        </TooltipContent>
      </Tooltip>
    </TooltipProvider>
  );
}
