import * as React from 'react';
import * as Collapsible from '@radix-ui/react-collapsible';
import { ChevronRight } from 'lucide-react';
import { cn } from '../ui';
import './trace.css';

// Adapted from the official shadcn Radix Trace composition:
// https://ui.shadcn.com/docs/components/radix/trace
// Rows receive interaction semantics from their enclosing trigger or link.
export function Trace({ className, ...props }: React.ComponentProps<'div'>) {
  return <div data-slot="trace" className={cn('ui-trace', className)} {...props} />;
}

export function TraceLine({ className, status, ...props }: React.ComponentProps<'span'> & { status?: 'running' | 'error' | 'pending' }) {
  return <span data-slot="trace-line" data-status={status} className={cn('ui-trace-line', className)} {...props} />;
}

export function TraceIcon({ className, ...props }: React.ComponentProps<'span'>) {
  return <span data-slot="trace-icon" className={cn('ui-trace-icon', className)} {...props} aria-hidden="true" />;
}

export function TraceTitle({ className, ...props }: React.ComponentProps<'span'>) {
  return <span data-slot="trace-title" className={cn('ui-trace-title', className)} {...props} />;
}

export function TraceDescription({ className, ...props }: React.ComponentProps<'span'>) {
  return <span data-slot="trace-description" className={cn('ui-trace-description', className)} {...props} />;
}

type TraceCollapsibleProps = Omit<React.ComponentProps<typeof Collapsible.Root>, 'asChild' | 'open'> & (
  { open?: undefined } | { open: boolean; onOpenChange: NonNullable<React.ComponentProps<typeof Collapsible.Root>['onOpenChange']> }
);

export function TraceCollapsible({ className, ...props }: TraceCollapsibleProps) {
  return <Collapsible.Root data-slot="trace-collapsible" className={cn('ui-trace-collapsible', className)} {...props} />;
}

export function TraceCollapsibleTrigger({ className, children, ...props }: Omit<React.ComponentProps<typeof Collapsible.Trigger>, 'asChild'>) {
  return <Collapsible.Trigger data-slot="trace-collapsible-trigger" className={cn('ui-trace-trigger', className)} {...props}>
    {children}<TraceIcon className="ui-trace-chevron"><ChevronRight size={16} /></TraceIcon>
  </Collapsible.Trigger>;
}

export function TraceCollapsibleContent({ className, children, ...props }: Omit<React.ComponentProps<typeof Collapsible.Content>, 'asChild'>) {
  return <Collapsible.Content data-slot="trace-collapsible-content" className="ui-trace-content" {...props}>
    <div data-slot="trace-collapsible-content-inner" className={cn('ui-trace-content-inner', className)}>{children}</div>
  </Collapsible.Content>;
}
