import { cn } from '@/lib/utils';

type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

interface SeverityBadgeProps {
  severity: Severity;
  showLabel?: boolean;
  size?: 'sm' | 'md' | 'lg';
  className?: string;
}

const severityConfig: Record<Severity, {
  label: string;
  bgClass: string;
  textClass: string;
  borderClass: string;
  dotClass: string;
}> = {
  critical: {
    label: 'Critical',
    bgClass: 'bg-destructive/20',
    textClass: 'text-destructive',
    borderClass: 'border-destructive/30',
    dotClass: 'bg-destructive',
  },
  high: {
    label: 'High',
    bgClass: 'bg-warning/20',
    textClass: 'text-warning',
    borderClass: 'border-warning/30',
    dotClass: 'bg-warning',
  },
  medium: {
    label: 'Medium',
    bgClass: 'bg-yellow-500/20',
    textClass: 'text-yellow-400',
    borderClass: 'border-yellow-500/30',
    dotClass: 'bg-yellow-400',
  },
  low: {
    label: 'Low',
    bgClass: 'bg-success/20',
    textClass: 'text-success',
    borderClass: 'border-success/30',
    dotClass: 'bg-success',
  },
  info: {
    label: 'Info',
    bgClass: 'bg-blue-500/20',
    textClass: 'text-blue-400',
    borderClass: 'border-blue-500/30',
    dotClass: 'bg-blue-400',
  },
};

const sizeClasses = {
  sm: 'px-2 py-0.5 text-xs',
  md: 'px-2.5 py-1 text-xs',
  lg: 'px-3 py-1.5 text-sm',
};

export function SeverityBadge({ 
  severity, 
  showLabel = true, 
  size = 'md',
  className 
}: SeverityBadgeProps) {
  const config = severityConfig[severity];

  return (
    <span className={cn(
      "inline-flex items-center gap-1.5 rounded-full border font-medium",
      config.bgClass,
      config.textClass,
      config.borderClass,
      sizeClasses[size],
      className
    )}>
      <span className={cn("w-1.5 h-1.5 rounded-full", config.dotClass)} />
      {showLabel && config.label}
    </span>
  );
}
