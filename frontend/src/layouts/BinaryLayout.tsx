import { Outlet, NavLink, useParams } from 'react-router-dom';
import { cn } from '../lib/utils';
import { FileCode, Braces, AlignLeft, ArrowRightLeft, Database, Box } from 'lucide-react';

export function BinaryLayout() {
  const { binaryName } = useParams();

  const navItems = [
    { to: 'overview', icon: FileCode, label: 'Overview' },
    { to: 'functions', icon: Braces, label: 'Functions' },
    { to: 'strings', icon: AlignLeft, label: 'Strings' },
    { to: 'imports', icon: ArrowRightLeft, label: 'Imports' },
    { to: 'exports', icon: ArrowRightLeft, label: 'Exports' },
    { to: 'symbols', icon: Database, label: 'Symbols' },
    { to: 'segments', icon: Box, label: 'Segments' },
  ];

  return (
    <div className="flex flex-col space-y-8 lg:flex-row lg:space-x-12 lg:space-y-0">
      <aside className="-mx-4 lg:w-1/5">
        <div className="mb-4 px-4">
            <h2 className="text-lg font-semibold tracking-tight truncate" title={binaryName}>
                {binaryName}
            </h2>
            <p className="text-sm text-muted-foreground">Binary Analysis</p>
        </div>
        <nav className="flex space-x-2 lg:flex-col lg:space-x-0 lg:space-y-1 overflow-x-auto lg:overflow-visible px-4 pb-2">
          {navItems.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              className={({ isActive }) =>
                cn(
                  "justify-start flex items-center whitespace-nowrap rounded-md p-2 text-sm font-medium hover:bg-accent hover:text-accent-foreground transition-colors",
                  isActive ? "bg-accent text-accent-foreground" : "text-muted-foreground"
                )
              }
            >
              <item.icon className="mr-2 h-4 w-4" />
              {item.label}
            </NavLink>
          ))}
        </nav>
      </aside>
      <div className="flex-1 lg:max-w-4xl">
        <Outlet />
      </div>
    </div>
  );
}
