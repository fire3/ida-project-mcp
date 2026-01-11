import { useState } from 'react';
import { useParams, useSearchParams } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { binaryApi } from '../api/client';
import { Input } from '../components/ui/input';
import { Button } from '../components/ui/button';
import { Search, ChevronLeft, ChevronRight, Quote, ArrowRight, Filter } from 'lucide-react';
import { cn } from '../lib/utils';

interface StringDetailProps {
  binaryName: string;
  address: string;
  stringContent: string;
  onNavigate?: (address: string) => void;
}

function StringDetail({ binaryName, address, stringContent, onNavigate }: StringDetailProps) {
  const { data: xrefs, isLoading } = useQuery({
    queryKey: ['xrefs-to', binaryName, address],
    queryFn: () => binaryApi.getXrefsTo(binaryName, address),
  });

  return (
    <div className="h-full flex flex-col bg-background">
      <div className="p-4 border-b border-border bg-muted/20">
        <h2 className="text-lg font-semibold flex items-center">
          <Quote className="mr-2 h-5 w-5 text-muted-foreground" />
          String Details
        </h2>
        <div className="mt-2 space-y-1">
          <div className="text-sm font-mono text-muted-foreground">Address: {address}</div>
          <div className="p-2 bg-muted rounded border border-border font-mono text-sm whitespace-pre-wrap break-all">
            {stringContent}
          </div>
        </div>
      </div>

      <div className="flex-1 flex flex-col min-h-0">
        <div className="p-3 border-b border-border font-semibold flex items-center bg-muted/30 text-sm">
          <ArrowRight className="mr-2 h-4 w-4 text-green-600 dark:text-green-400" />
          Cross References ({xrefs?.length || 0})
        </div>
        <div className="flex-1 overflow-auto p-0">
          {isLoading ? (
            <div className="p-4 text-muted-foreground text-sm">Loading xrefs...</div>
          ) : (
            <div className="divide-y divide-border">
              {xrefs?.map((ref: any, idx) => (
                <div
                  key={`${ref.from_address}-${idx}`}
                  className="p-3 hover:bg-muted/50 cursor-pointer transition-colors group"
                  onClick={() => onNavigate?.(ref.from_address)}
                >
                  <div className="flex items-center justify-between gap-2">
                    <div className="font-mono text-sm font-medium text-foreground truncate min-w-0 group-hover:text-green-600 dark:group-hover:text-green-400">
                      {ref.from_function || ref.from_address}
                    </div>
                    <div className="text-xs text-muted-foreground font-mono flex-shrink-0">
                      {ref.from_address}
                    </div>
                  </div>
                  <div className="text-xs text-muted-foreground mt-1 font-mono">
                    {ref.xref_type} reference
                  </div>
                </div>
              ))}
              {xrefs?.length === 0 && (
                <div className="p-4 text-center text-muted-foreground text-xs">
                  No cross references found.
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

export function StringsBrowser() {
  const { binaryName } = useParams<{ binaryName: string }>();
  const [searchParams, setSearchParams] = useSearchParams();
  const [selectedString, setSelectedString] = useState<{ address: string; string: string } | null>(null);
  const [page, setPage] = useState(0);
  const [minLength, setMinLength] = useState<number | undefined>(undefined);
  const limit = 50;

  const query = searchParams.get('q') || '';

  const { data: strings, isLoading } = useQuery({
    queryKey: ['strings', binaryName, query, minLength, page],
    queryFn: () => binaryApi.listStrings(binaryName!, query, minLength, page * limit, limit),
    enabled: !!binaryName,
  });

  const handleSearch = (e: React.ChangeEvent<HTMLInputElement>) => {
    setSearchParams({ q: e.target.value });
    setPage(0);
  };

  const handleMinLengthChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const val = parseInt(e.target.value);
    setMinLength(isNaN(val) ? undefined : val);
    setPage(0);
  };

  return (
    <div className="flex h-full">
      {/* Strings List */}
      <div className="w-[350px] border-r flex flex-col bg-background">
        <div className="p-4 border-b space-y-2">
          <div className="relative">
            <Search className="absolute left-2 top-2.5 h-4 w-4 text-muted-foreground" />
            <Input
              placeholder="Search strings..."
              value={query}
              onChange={handleSearch}
              className="pl-8"
            />
          </div>
          <div className="relative flex items-center gap-2">
            <Filter className="h-4 w-4 text-muted-foreground" />
            <Input
              type="number"
              placeholder="Min length"
              value={minLength || ''}
              onChange={handleMinLengthChange}
              className="h-8 text-xs"
            />
          </div>
        </div>
        
        <div className="flex-1 overflow-auto">
          {isLoading ? (
            <div className="p-4 text-center text-muted-foreground">Loading...</div>
          ) : (
            <div className="divide-y">
              {strings?.map((str) => (
                <div
                  key={str.address}
                  className={cn(
                    "p-3 cursor-pointer hover:bg-muted/50 transition-colors text-sm",
                    selectedString?.address === str.address ? "bg-muted" : ""
                  )}
                  onClick={() => setSelectedString({ address: str.address, string: str.string })}
                >
                  <div className="font-mono font-medium text-primary truncate" title={str.string}>
                    {str.string}
                  </div>
                  <div className="flex justify-between mt-1 text-xs text-muted-foreground">
                    <span className="font-mono">{str.address}</span>
                    <span>{str.length} chars</span>
                    {str.section && <span>{str.section}</span>}
                  </div>
                </div>
              ))}
              {strings?.length === 0 && (
                <div className="p-4 text-center text-muted-foreground">No strings found.</div>
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
            disabled={!strings || strings.length < limit}
          >
            <ChevronRight className="h-4 w-4" />
          </Button>
        </div>
      </div>

      {/* String Detail */}
      <div className="flex-1 flex flex-col overflow-hidden bg-slate-50 dark:bg-slate-950">
        {selectedString ? (
          <StringDetail 
            binaryName={binaryName!} 
            address={selectedString.address} 
            stringContent={selectedString.string}
            // onNavigate could navigate to disassembly view if we had global navigation context
          />
        ) : (
          <div className="flex-1 flex items-center justify-center text-muted-foreground">
            Select a string to view details and cross-references
          </div>
        )}
      </div>
    </div>
  );
}
