import * as React from 'react';
import * as AccordionPrimitive from '@radix-ui/react-accordion';
import * as ScrollAreaPrimitive from '@radix-ui/react-scroll-area';
import * as SeparatorPrimitive from '@radix-ui/react-separator';
import * as TooltipPrimitive from '@radix-ui/react-tooltip';
import { ChevronDown } from 'lucide-react';
import { cn } from '../ui';
import './data-display.css';

// Locally owned shadcn-style components: semantic composition with Radix behavior.
export function Card({ className, ...props }: React.ComponentProps<'div'>) { return <div data-slot="card" className={cn('ui-card', className)} {...props} />; }
export function CardHeader({ className, ...props }: React.ComponentProps<'div'>) { return <div data-slot="card-header" className={cn('ui-card-header', className)} {...props} />; }
export function CardTitle({ className, ...props }: React.ComponentProps<'h3'>) { return <h3 data-slot="card-title" className={cn('ui-card-title', className)} {...props} />; }
export function CardDescription({ className, ...props }: React.ComponentProps<'p'>) { return <p data-slot="card-description" className={cn('ui-card-description', className)} {...props} />; }
export function CardContent({ className, ...props }: React.ComponentProps<'div'>) { return <div data-slot="card-content" className={cn('ui-card-content', className)} {...props} />; }
export function CardFooter({ className, ...props }: React.ComponentProps<'div'>) { return <div data-slot="card-footer" className={cn('ui-card-footer', className)} {...props} />; }

export const Accordion = AccordionPrimitive.Root;
export const AccordionItem = React.forwardRef<React.ElementRef<typeof AccordionPrimitive.Item>, React.ComponentPropsWithoutRef<typeof AccordionPrimitive.Item>>(({ className, ...props }, ref) => <AccordionPrimitive.Item ref={ref} className={cn('ui-accordion-item', className)} {...props} />);
export const AccordionTrigger = React.forwardRef<React.ElementRef<typeof AccordionPrimitive.Trigger>, React.ComponentPropsWithoutRef<typeof AccordionPrimitive.Trigger>>(({ className, children, ...props }, ref) => <AccordionPrimitive.Header className="ui-accordion-header"><AccordionPrimitive.Trigger ref={ref} className={cn('ui-accordion-trigger', className)} {...props}>{children}<ChevronDown size={16} className="ui-accordion-chevron" aria-hidden="true" /></AccordionPrimitive.Trigger></AccordionPrimitive.Header>);
export const AccordionContent = React.forwardRef<React.ElementRef<typeof AccordionPrimitive.Content>, React.ComponentPropsWithoutRef<typeof AccordionPrimitive.Content>>(({ className, children, ...props }, ref) => <AccordionPrimitive.Content ref={ref} className="ui-accordion-content" {...props}><div className={cn('ui-accordion-body', className)}>{children}</div></AccordionPrimitive.Content>);
AccordionItem.displayName = 'AccordionItem'; AccordionTrigger.displayName = 'AccordionTrigger'; AccordionContent.displayName = 'AccordionContent';

export const Separator = React.forwardRef<React.ElementRef<typeof SeparatorPrimitive.Root>, React.ComponentPropsWithoutRef<typeof SeparatorPrimitive.Root>>(({ className, orientation = 'horizontal', decorative = true, ...props }, ref) => <SeparatorPrimitive.Root ref={ref} orientation={orientation} decorative={decorative} className={cn('ui-separator', className)} {...props} />);
Separator.displayName = 'Separator';
export const ScrollArea = React.forwardRef<React.ElementRef<typeof ScrollAreaPrimitive.Root>, React.ComponentPropsWithoutRef<typeof ScrollAreaPrimitive.Root>>(({ className, children, ...props }, ref) => <ScrollAreaPrimitive.Root ref={ref} className={cn('ui-scroll-area', className)} {...props}><ScrollAreaPrimitive.Viewport className="ui-scroll-viewport">{children}</ScrollAreaPrimitive.Viewport><ScrollAreaPrimitive.Scrollbar orientation="vertical" className="ui-scrollbar"><ScrollAreaPrimitive.Thumb className="ui-scroll-thumb" /></ScrollAreaPrimitive.Scrollbar><ScrollAreaPrimitive.Scrollbar orientation="horizontal" className="ui-scrollbar"><ScrollAreaPrimitive.Thumb className="ui-scroll-thumb" /></ScrollAreaPrimitive.Scrollbar><ScrollAreaPrimitive.Corner /></ScrollAreaPrimitive.Root>);
ScrollArea.displayName = 'ScrollArea';
export const TooltipProvider = TooltipPrimitive.Provider;
export const Tooltip = TooltipPrimitive.Root;
export const TooltipTrigger = TooltipPrimitive.Trigger;
export const TooltipContent = React.forwardRef<React.ElementRef<typeof TooltipPrimitive.Content>, React.ComponentPropsWithoutRef<typeof TooltipPrimitive.Content>>(({ className, sideOffset = 5, ...props }, ref) => <TooltipPrimitive.Portal><TooltipPrimitive.Content ref={ref} sideOffset={sideOffset} className={cn('ui-tooltip', className)} {...props} /></TooltipPrimitive.Portal>);
TooltipContent.displayName = 'TooltipContent';

export function Alert({ className, ...props }: React.ComponentProps<'div'>) { return <div role="note" className={cn('ui-alert', className)} {...props} />; }
export function AlertTitle({ className, ...props }: React.ComponentProps<'h4'>) { return <h4 className={cn('ui-alert-title', className)} {...props} />; }
export function AlertDescription({ className, ...props }: React.ComponentProps<'div'>) { return <div className={cn('ui-alert-description', className)} {...props} />; }
