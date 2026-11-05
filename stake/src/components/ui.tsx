import * as React from 'react';
import { Slot } from '@radix-ui/react-slot';
import * as TabsPrimitive from '@radix-ui/react-tabs';
import * as DialogPrimitive from '@radix-ui/react-dialog';
import { cva, type VariantProps } from 'class-variance-authority';
import { clsx, type ClassValue } from 'clsx';
import { twMerge } from 'tailwind-merge';
import { X, ArrowUpRight, FolderSearch, LoaderCircle } from 'lucide-react';

export function cn(...values: ClassValue[]) { return twMerge(clsx(values)); }
const buttonVariants = cva('button', { variants: { variant: { default: 'button-primary', outline: 'button-outline', ghost: 'button-ghost' }, size: { default: '', sm: 'button-sm', icon: 'button-icon' } }, defaultVariants: { variant: 'default', size: 'default' } });
export const Button = React.forwardRef<HTMLButtonElement, React.ButtonHTMLAttributes<HTMLButtonElement> & VariantProps<typeof buttonVariants> & { asChild?: boolean }>(
  ({ className, variant, size, asChild, ...props }, ref) => {
    const Component = asChild ? Slot : 'button';
    return <Component ref={ref} type={asChild ? undefined : 'button'} className={cn(buttonVariants({ variant, size }), className)} {...props} />;
  });
Button.displayName = 'Button';
export function Badge({ children, tone = 'neutral', className }: React.PropsWithChildren<{ tone?: string; className?: string }>) {
  return <span className={cn('badge', 'badge-' + tone, className)}>{children}</span>;
}
export const Tabs = TabsPrimitive.Root;
export const TabsList = React.forwardRef<HTMLDivElement, React.ComponentPropsWithoutRef<typeof TabsPrimitive.List>>(({ className, ...props }, ref) => <TabsPrimitive.List ref={ref} className={cn('tabs-list', className)} {...props} />);
export const TabsTrigger = React.forwardRef<HTMLButtonElement, React.ComponentPropsWithoutRef<typeof TabsPrimitive.Trigger>>(({ className, ...props }, ref) => <TabsPrimitive.Trigger ref={ref} className={cn('tabs-trigger', className)} {...props} />);
export const TabsContent = React.forwardRef<HTMLDivElement, React.ComponentPropsWithoutRef<typeof TabsPrimitive.Content>>(({ className, ...props }, ref) => <TabsPrimitive.Content ref={ref} className={cn('tabs-content', className)} {...props} />);
TabsList.displayName = 'TabsList'; TabsTrigger.displayName = 'TabsTrigger'; TabsContent.displayName = 'TabsContent';
export function Drawer({ open, onOpenChange, title, description, children }: React.PropsWithChildren<{ open: boolean; onOpenChange: (value: boolean) => void; title: string; description: string }>) {
  return <DialogPrimitive.Root open={open} onOpenChange={onOpenChange}><DialogPrimitive.Portal>
    <DialogPrimitive.Overlay className="drawer-overlay" />
    <DialogPrimitive.Content className="drawer-content">
      <header className="drawer-heading"><div><p className="eyebrow">EVIDENCE INSPECTOR</p><DialogPrimitive.Title>{title}</DialogPrimitive.Title><DialogPrimitive.Description>{description}</DialogPrimitive.Description></div><DialogPrimitive.Close asChild><Button variant="ghost" size="icon" aria-label="Close evidence"><X size={19} /></Button></DialogPrimitive.Close></header>
      <div className="drawer-body">{children}</div>
    </DialogPrimitive.Content>
  </DialogPrimitive.Portal></DialogPrimitive.Root>;
}
export function Empty({ title, description, action }: { title: string; description?: string; action?: React.ReactNode }) {
  return <div className="empty-state"><FolderSearch size={34} strokeWidth={1.3} /><h3>{title}</h3>{description && <p>{description}</p>}{action}</div>;
}
export function Loading({ label = 'Loading assessment…' }: { label?: string }) { return <div className="loading" role="status"><LoaderCircle className="spinner" size={19} />{label}</div>; }
export function Section({ title, caption, action, children, className }: React.PropsWithChildren<{ title: string; caption?: string; action?: React.ReactNode; className?: string }>) {
  return <section className={cn('section-card', className)}><header className="section-heading"><div><h2>{title}</h2>{caption && <p>{caption}</p>}</div>{action}</header>{children}</section>;
}
export function TextLink({ children, onClick }: React.PropsWithChildren<{ onClick: () => void }>) { return <button className="text-link" onClick={onClick}>{children}<ArrowUpRight size={14} /></button>; }
