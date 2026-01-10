import { useState } from 'react';
import { useParams, useSearchParams } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { binaryApi } from '../api/client';
import { Input } from '../components/ui/input';
import { Button } from '../components/ui/button';
import { Search, ChevronLeft, ChevronRight } from 'lucide-react';
import { cn } from '../lib/utils';
import { FunctionDetail } from '../components/FunctionDetail';

export function FunctionsBrowser() {
  const { binaryName } = useParams<{ binaryName: string }>();
  const [searchParams, setSearchParams] = useSearchParams();
  const [selectedAddress, setSelectedAddress] = useState<string | null>(null);
  const [page, setPage] = useState(0);
  const limit = 50;

  const query = searchParams.get('q') || '';

  const { data: functions, isLoading } = useQuery({
    queryKey: ['functions', binaryName, query, page],
    queryFn: () => binaryApi.listFunctions(binaryName!, query, page * limit, limit),
    enabled: !!binaryName,
  });

  const handleSearch = (e: React.ChangeEvent<HTMLInputElement>) => {
    setSearchParams({ q: e.target.value });
    setPage(0);
  };

  return (
    <div className="flex h-full">
      {/* Functions List */}
      <div className="w-1/3 min-w-[300px] border-r flex flex-col bg-background">
        <div className="p-4 border-b space-y-2">
          <div className="relative">
            <Search className="absolute left-2 top-2.5 h-4 w-4 text-muted-foreground" />
            <Input
              placeholder="Search functions..."
              value={query}
              onChange={handleSearch}
              className="pl-8"
            />
          </div>
        </div>
        
        <div className="flex-1 overflow-auto">
          {isLoading ? (
            <div className="p-4 text-center text-muted-foreground">Loading...</div>
          ) : (
            <div className="divide-y">
              {functions?.map((func) => (
                <div
                  key={func.address}
                  className={cn(
                    "p-3 cursor-pointer hover:bg-muted/50 transition-colors text-sm",
                    selectedAddress === func.address ? "bg-muted" : ""
                  )}
                  onClick={() => setSelectedAddress(func.address)}
                >
                  <div className="font-mono font-medium text-primary truncate" title={func.demangled_name || func.name}>
                    {func.demangled_name || func.name}
                  </div>
                  <div className="flex justify-between mt-1 text-xs text-muted-foreground">
                    <span className="font-mono">{func.address}</span>
                    <span>{func.size} bytes</span>
                  </div>
                </div>
              ))}
              {functions?.length === 0 && (
                <div className="p-4 text-center text-muted-foreground">No functions found.</div>
              )}
            </div>
          )}
        </div>

        <div className="p-2 border-t flex justify-between items-center bg-muted/10">
          <Button
            variant="ghost"
            size="sm"
            onClick={() => setPage((p) => Math.max(0, p - 1))}
            disabled={page === 0}
          >
            <ChevronLeft className="h-4 w-4" />
          </Button>
          <span className="text-xs text-muted-foreground">Page {page + 1}</span>
          <Button
            variant="ghost"
            size="sm"
            onClick={() => setPage((p) => p + 1)}
            disabled={!functions || functions.length < limit}
          >
            <ChevronRight className="h-4 w-4" />
          </Button>
        </div>
      </div>

      {/* Function Detail */}
      <div className="flex-1 flex flex-col overflow-hidden bg-slate-50 dark:bg-slate-950">
        {selectedAddress ? (
          <FunctionDetail 
            binaryName={binaryName!} 
            address={selectedAddress} 
            onNavigate={setSelectedAddress}
          />
        ) : (
          <div className="flex-1 flex items-center justify-center text-muted-foreground">
            Select a function to view details
          </div>
        )}
      </div>
    </div>
  );
}
