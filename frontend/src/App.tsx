import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { MainLayout } from './layouts/MainLayout';
import { Dashboard } from './pages/Dashboard';
import { BinaryLayout } from './layouts/BinaryLayout';
import { BinaryOverview } from './pages/BinaryOverview';
import { FunctionsBrowser } from './pages/FunctionsBrowser';

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      refetchOnWindowFocus: false,
      staleTime: 1000 * 60 * 5, // 5 minutes
    },
  },
});

function Placeholder({ title }: { title: string }) {
  return (
    <div className="flex flex-col items-center justify-center h-[50vh] text-muted-foreground">
      <h3 className="text-xl font-semibold mb-2">{title}</h3>
      <p>This view is under construction.</p>
    </div>
  );
}

function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>
        <Routes>
          <Route path="/" element={<MainLayout />}>
            <Route index element={<Dashboard />} />
            
            <Route path="binary/:binaryName" element={<BinaryLayout />}>
              <Route index element={<Navigate to="overview" replace />} />
              <Route path="overview" element={<BinaryOverview />} />
              <Route path="functions" element={<FunctionsBrowser />} />
              <Route path="strings" element={<Placeholder title="Strings Browser" />} />
              <Route path="imports" element={<Placeholder title="Imports" />} />
              <Route path="exports" element={<Placeholder title="Exports" />} />
              <Route path="symbols" element={<Placeholder title="Symbols" />} />
              <Route path="segments" element={<Placeholder title="Segments" />} />
            </Route>
            
            <Route path="*" element={<Placeholder title="404 Not Found" />} />
          </Route>
        </Routes>
      </BrowserRouter>
    </QueryClientProvider>
  );
}

export default App;
