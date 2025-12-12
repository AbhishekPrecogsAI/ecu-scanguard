import { NavLink, useLocation } from 'react-router-dom';
import {
  LayoutDashboard,
  FileSearch,
  Shield,
  FileText,
  Settings,
  Database,
  AlertTriangle,
  Target,
  BookOpen,
  LogOut,
  Sparkles,
  FileBarChart
} from 'lucide-react';
import { cn } from '@/lib/utils';
import { useAuth } from '@/hooks/useAuth';

const navItems = [
  { to: '/', icon: LayoutDashboard, label: 'Dashboard' },
  { to: '/scan-centre', icon: FileSearch, label: 'Scan Centre' },
  { to: '/vulnerabilities', icon: Shield, label: 'Vulnerabilities' },
  { to: '/imr', icon: AlertTriangle, label: 'IMR Dashboard', badge: 'NEW' },
  { to: '/tara', icon: Target, label: 'TARA' },
  { to: '/compliance', icon: FileText, label: 'Compliance' },
  { to: '/sbom', icon: Database, label: 'SBOM' },
  { to: '/reports', icon: FileBarChart, label: 'Reports' },
  { to: '/documentation', icon: BookOpen, label: 'Documentation' },
];

const bottomNavItems = [
  { to: '/settings', icon: Settings, label: 'Settings' },
];

export function Sidebar() {
  const location = useLocation();
  const { signOut } = useAuth();

  return (
    <aside className="w-64 border-r border-sidebar-border bg-sidebar flex flex-col">
      {/* Logo */}
      <div className="p-4 border-b border-sidebar-border">
        <div className="flex items-center gap-3">
          <img
            src="/logo.png"
            alt="Precogs AI"
            className="w-10 h-10"
          />
          <div>
            <h1 className="font-semibold text-sidebar-foreground text-sm">Precogs AI</h1>
            <p className="text-[10px] text-sidebar-foreground/60">Product Security Platform</p>
          </div>
        </div>
      </div>

      {/* AI Copilot Button */}
      <div className="p-3 border-b border-sidebar-border">
        <NavLink
          to="/copilot"
          className={cn(
            "flex items-center gap-2 px-3 py-2.5 rounded-lg text-sm font-medium transition-all duration-200",
            "bg-gradient-to-r from-primary to-accent text-white hover:opacity-90",
            location.pathname === '/copilot' && "ring-2 ring-white/30"
          )}
        >
          <Sparkles className="w-5 h-5" />
          <span>AI Copilot</span>
          <span className="ml-auto px-1.5 py-0.5 text-[9px] font-bold bg-white/20 rounded">BETA</span>
        </NavLink>
      </div>

      {/* Main Navigation */}
      <nav className="flex-1 p-3 space-y-1 overflow-y-auto">
        {navItems.map((item) => {
          const isActive = location.pathname === item.to ||
            (item.to !== '/' && location.pathname.startsWith(item.to));

          return (
            <NavLink
              key={item.to}
              to={item.to}
              className={cn(
                "flex items-center gap-3 px-3 py-2 rounded-lg text-sm font-medium transition-all duration-200",
                isActive
                  ? "bg-sidebar-primary text-sidebar-primary-foreground"
                  : "text-sidebar-foreground/70 hover:text-sidebar-foreground hover:bg-sidebar-accent"
              )}
            >
              <item.icon className="w-4 h-4" />
              <span>{item.label}</span>
              {item.badge && !isActive && (
                <span className="ml-auto px-1.5 py-0.5 text-[9px] font-semibold bg-orange-500 text-white rounded">{item.badge}</span>
              )}
            </NavLink>
          );
        })}
      </nav>

      {/* Bottom Navigation */}
      <div className="p-3 border-t border-sidebar-border space-y-1">
        {bottomNavItems.map((item) => {
          const isActive = location.pathname === item.to;

          return (
            <NavLink
              key={item.to}
              to={item.to}
              className={cn(
                "flex items-center gap-3 px-3 py-2 rounded-lg text-sm font-medium transition-all duration-200",
                isActive
                  ? "bg-sidebar-primary text-sidebar-primary-foreground"
                  : "text-sidebar-foreground/70 hover:text-sidebar-foreground hover:bg-sidebar-accent"
              )}
            >
              <item.icon className="w-4 h-4" />
              <span>{item.label}</span>
            </NavLink>
          );
        })}
        <button
          onClick={() => signOut()}
          className="w-full flex items-center gap-3 px-3 py-2 rounded-lg text-sm font-medium transition-all duration-200 text-sidebar-foreground/70 hover:text-sidebar-foreground hover:bg-sidebar-accent"
        >
          <LogOut className="w-4 h-4" />
          <span>Sign Out</span>
        </button>
      </div>

      {/* Enterprise Badge */}
      <div className="p-3 border-t border-sidebar-border">
        <div className="bg-gradient-to-r from-primary/10 to-accent/10 rounded-lg p-3 border border-primary/20">
          <div className="flex items-center gap-2 mb-1">
            <div className="w-2 h-2 rounded-full bg-success animate-pulse" />
            <span className="text-[10px] font-semibold text-sidebar-foreground uppercase tracking-wider">Enterprise</span>
          </div>
          <p className="text-[10px] text-sidebar-foreground/60">All systems operational</p>
        </div>
      </div>
    </aside>
  );
}
