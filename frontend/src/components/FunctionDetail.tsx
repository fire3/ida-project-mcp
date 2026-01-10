import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { binaryApi } from '../api/client';
import { Button } from './ui/button';
import { Code, FileText, ArrowRightLeft, ArrowRight, ArrowLeft } from 'lucide-react';
import { Prism as SyntaxHighlighter } from 'react-syntax-highlighter';
import { vscDarkPlus } from 'react-syntax-highlighter/dist/esm/styles/prism';
import { cn } from '../lib/utils';

interface FunctionDetailProps {
  binaryName: string;
  address: string;
  onNavigate?: (address: string) => void;
}

export function FunctionDetail({ binaryName, address, onNavigate }: FunctionDetailProps) {
  const [view, setView] = useState<'pseudocode' | 'disassembly' | 'xrefs'>('pseudocode');

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
    enabled: view === 'xrefs',
  });

  const { data: callees, isLoading: isCalleesLoading } = useQuery({
    queryKey: ['callees', binaryName, address],
    queryFn: () => binaryApi.getFunctionCallees(binaryName, address),
    enabled: view === 'xrefs',
  });

  return (
    <div className="flex flex-col h-full bg-background">
      {/* Toolbar */}
      <div className="border-b p-2 flex space-x-2 bg-muted/20">
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
        <Button
          variant={view === 'xrefs' ? 'secondary' : 'ghost'}
          size="sm"
          onClick={() => setView('xrefs')}
        >
          <ArrowRightLeft className="mr-2 h-4 w-4" />
          Xrefs
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

        {view === 'xrefs' && (
          <div className="flex h-full divide-x divide-border">
            {/* Callers */}
            <div className="flex-1 flex flex-col min-w-0">
              <div className="p-3 border-b border-border font-semibold flex items-center bg-muted/30">
                <ArrowLeft className="mr-2 h-4 w-4 text-blue-600 dark:text-blue-400" />
                Callers ({callers?.length || 0})
              </div>
              <div className="flex-1 overflow-auto p-0">
                {isCallersLoading ? (
                  <div className="p-4 text-muted-foreground">Loading...</div>
                ) : (
                  <div className="divide-y divide-border">
                    {callers?.map((func) => (
                      <div
                        key={func.address}
                        className="p-3 hover:bg-muted/50 cursor-pointer transition-colors group"
                        onClick={() => onNavigate?.(func.address)}
                      >
                        <div className="font-mono text-sm font-medium text-foreground truncate group-hover:text-blue-600 dark:group-hover:text-blue-400">
                          {func.demangled_name || func.name}
                        </div>
                        <div className="text-xs text-muted-foreground mt-1 font-mono">
                          {func.address}
                        </div>
                      </div>
                    ))}
                    {callers?.length === 0 && (
                      <div className="p-8 text-center text-muted-foreground text-sm">
                        No callers found.
                      </div>
                    )}
                  </div>
                )}
              </div>
            </div>

            {/* Callees */}
            <div className="flex-1 flex flex-col min-w-0">
              <div className="p-3 border-b border-border font-semibold flex items-center bg-muted/30">
                <ArrowRight className="mr-2 h-4 w-4 text-green-600 dark:text-green-400" />
                Callees ({callees?.length || 0})
              </div>
              <div className="flex-1 overflow-auto p-0">
                {isCalleesLoading ? (
                  <div className="p-4 text-muted-foreground">Loading...</div>
                ) : (
                  <div className="divide-y divide-border">
                    {callees?.map((func) => (
                      <div
                        key={func.address}
                        className="p-3 hover:bg-muted/50 cursor-pointer transition-colors group"
                        onClick={() => onNavigate?.(func.address)}
                      >
                        <div className="font-mono text-sm font-medium text-foreground truncate group-hover:text-green-600 dark:group-hover:text-green-400">
                          {func.demangled_name || func.name}
                        </div>
                        <div className="text-xs text-muted-foreground mt-1 font-mono">
                          {func.address}
                        </div>
                      </div>
                    ))}
                    {callees?.length === 0 && (
                      <div className="p-8 text-center text-muted-foreground text-sm">
                        No callees found.
                      </div>
                    )}
                  </div>
                )}
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
