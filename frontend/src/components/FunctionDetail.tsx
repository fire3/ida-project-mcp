import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { binaryApi } from '../api/client';
import { Button } from './ui/button';
import { Input } from './ui/input';
import { Code, FileText, ArrowRight, ArrowLeft, Search } from 'lucide-react';
import { Prism as SyntaxHighlighter } from 'react-syntax-highlighter';
import { vscDarkPlus } from 'react-syntax-highlighter/dist/esm/styles/prism';

interface FunctionDetailProps {
  binaryName: string;
  address: string;
  onNavigate?: (address: string) => void;
}

export function FunctionDetail({ binaryName, address, onNavigate }: FunctionDetailProps) {
  const [view, setView] = useState<'pseudocode' | 'disassembly'>('pseudocode');
  const [callerSearch, setCallerSearch] = useState('');
  const [calleeSearch, setCalleeSearch] = useState('');

  const { data: pseudocode, isLoading: isPseudoLoading } = useQuery({
    queryKey: ['pseudocode', binaryName, address],
    queryFn: () => binaryApi.getFunctionPseudocode(binaryName, address),
    enabled: view === 'pseudocode',
  });

  const { data: disassembly, isLoading: isDisasmLoading } = useQuery({
    queryKey: ['disassembly', binaryName, address],
    queryFn: () => binaryApi.getFunctionDisassembly(binaryName, address),
    enabled: view === 'disassembly',
  });

  const { data: callers, isLoading: isCallersLoading } = useQuery({
    queryKey: ['callers', binaryName, address],
    queryFn: () => binaryApi.getFunctionCallers(binaryName, address),
  });

  const { data: callees, isLoading: isCalleesLoading } = useQuery({
    queryKey: ['callees', binaryName, address],
    queryFn: () => binaryApi.getFunctionCallees(binaryName, address),
  });

  const filteredCallers = callers?.filter(ref => 
    (ref.caller_name?.toLowerCase().includes(callerSearch.toLowerCase()) || 
     ref.caller_address.toLowerCase().includes(callerSearch.toLowerCase()))
  );

  const filteredCallees = callees?.filter(ref => 
    (ref.callee_name?.toLowerCase().includes(calleeSearch.toLowerCase()) || 
     ref.callee_address.toLowerCase().includes(calleeSearch.toLowerCase()))
  );

  return (
    <div className="flex h-full bg-background overflow-hidden">
      {/* Main Content Area */}
      <div className="flex-1 flex flex-col min-w-0 border-r border-border">
        {/* Toolbar */}
        <div className="border-b border-border p-2 flex space-x-2 bg-muted/20">
          <Button
            variant={view === 'pseudocode' ? 'secondary' : 'ghost'}
            size="sm"
            onClick={() => setView('pseudocode')}
          >
            <Code className="mr-2 h-4 w-4" />
            Pseudocode
          </Button>
          <Button
            variant={view === 'disassembly' ? 'secondary' : 'ghost'}
            size="sm"
            onClick={() => setView('disassembly')}
          >
            <FileText className="mr-2 h-4 w-4" />
            Disassembly
          </Button>
        </div>

        {/* Content */}
        <div className="flex-1 overflow-auto">
          {view === 'pseudocode' && (
            isPseudoLoading ? (
              <div className="flex items-center justify-center h-full text-muted-foreground">Loading pseudocode...</div>
            ) : (
              <div className="h-full text-sm">
                <SyntaxHighlighter
                  language="cpp"
                  style={vscDarkPlus}
                  customStyle={{ margin: 0, height: '100%', borderRadius: 0 }}
                  showLineNumbers
                >
                  {pseudocode?.pseudo_code || "// No pseudocode available."}
                </SyntaxHighlighter>
              </div>
            )
          )}

          {view === 'disassembly' && (
            isDisasmLoading ? (
              <div className="flex items-center justify-center h-full text-muted-foreground">Loading disassembly...</div>
            ) : (
              <div className="h-full text-sm">
                <SyntaxHighlighter
                  language="nasm"
                  style={vscDarkPlus}
                  customStyle={{ margin: 0, height: '100%', borderRadius: 0 }}
                  showLineNumbers
                >
                  {disassembly || "; No disassembly available."}
                </SyntaxHighlighter>
              </div>
            )
          )}
        </div>
      </div>

      {/* Xrefs Sidebar (Fixed Right) */}
      <div className="w-80 flex flex-col bg-background border-l border-border">
        {/* Callers */}
        <div className="flex-1 flex flex-col min-h-0 border-b border-border">
          <div className="p-3 border-b border-border font-semibold flex items-center bg-muted/30 text-sm">
            <ArrowLeft className="mr-2 h-4 w-4 text-blue-600 dark:text-blue-400" />
            Callers ({filteredCallers?.length || 0})
          </div>
          <div className="p-2 border-b border-border bg-background">
            <div className="relative">
              <Search className="absolute left-2 top-2.5 h-3 w-3 text-muted-foreground" />
              <Input
                placeholder="Search callers..."
                value={callerSearch}
                onChange={(e) => setCallerSearch(e.target.value)}
                className="h-8 pl-8 text-xs"
              />
            </div>
          </div>
          <div className="flex-1 overflow-auto p-0">
            {isCallersLoading ? (
              <div className="p-4 text-muted-foreground text-sm">Loading...</div>
            ) : (
              <div className="divide-y divide-border">
                {filteredCallers?.map((ref) => (
                  <div
                    key={`${ref.caller_address}-${ref.call_site_address}`}
                    className="p-2 hover:bg-muted/50 cursor-pointer transition-colors group"
                    onClick={() => onNavigate?.(ref.caller_address)}
                  >
                    <div className="flex items-center justify-between gap-2">
                      <div className="font-mono text-sm font-medium text-foreground truncate min-w-0 group-hover:text-blue-600 dark:group-hover:text-blue-400" title={ref.caller_name || ref.caller_address}>
                        {ref.caller_name || ref.caller_address}
                      </div>
                      <div className="text-xs text-muted-foreground font-mono flex-shrink-0">
                        {ref.caller_address}
                      </div>
                    </div>
                    <div className="text-xs text-muted-foreground mt-0.5 font-mono">
                      callsite {ref.call_site_address}
                    </div>
                  </div>
                ))}
                {filteredCallers?.length === 0 && (
                  <div className="p-4 text-center text-muted-foreground text-xs">
                    {callerSearch ? 'No matching callers found.' : 'No callers found.'}
                  </div>
                )}
              </div>
            )}
          </div>
        </div>

        {/* Callees */}
        <div className="flex-1 flex flex-col min-h-0">
          <div className="p-3 border-b border-border font-semibold flex items-center bg-muted/30 text-sm">
            <ArrowRight className="mr-2 h-4 w-4 text-green-600 dark:text-green-400" />
            Callees ({filteredCallees?.length || 0})
          </div>
          <div className="p-2 border-b border-border bg-background">
            <div className="relative">
              <Search className="absolute left-2 top-2.5 h-3 w-3 text-muted-foreground" />
              <Input
                placeholder="Search callees..."
                value={calleeSearch}
                onChange={(e) => setCalleeSearch(e.target.value)}
                className="h-8 pl-8 text-xs"
              />
            </div>
          </div>
          <div className="flex-1 overflow-auto p-0">
            {isCalleesLoading ? (
              <div className="p-4 text-muted-foreground text-sm">Loading...</div>
            ) : (
              <div className="divide-y divide-border">
                {filteredCallees?.map((ref) => (
                  <div
                    key={`${ref.callee_address}-${ref.call_site_address}`}
                    className="p-2 hover:bg-muted/50 cursor-pointer transition-colors group"
                    onClick={() => onNavigate?.(ref.callee_address)}
                  >
                    <div className="flex items-center justify-between gap-2">
                      <div className="font-mono text-sm font-medium text-foreground truncate min-w-0 group-hover:text-green-600 dark:group-hover:text-green-400" title={ref.callee_name || ref.callee_address}>
                        {ref.callee_name || ref.callee_address}
                      </div>
                      <div className="text-xs text-muted-foreground font-mono flex-shrink-0">
                        {ref.callee_address}
                      </div>
                    </div>
                    <div className="text-xs text-muted-foreground mt-0.5 font-mono flex items-center justify-between">
                      <span>callsite {ref.call_site_address}</span>
                      {ref.call_type && <span className="text-[10px] px-1 rounded bg-muted text-muted-foreground">{ref.call_type}</span>}
                    </div>
                  </div>
                ))}
                {filteredCallees?.length === 0 && (
                  <div className="p-4 text-center text-muted-foreground text-xs">
                    {calleeSearch ? 'No matching callees found.' : 'No callees found.'}
                  </div>
                )}
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
