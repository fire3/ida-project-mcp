import { useParams } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { apiClient } from '../api/client';
import { Card, CardContent, CardHeader, CardTitle } from '../components/ui/card';

export function BinaryOverview() {
  const { binaryName } = useParams();

  const { data: metadata, isLoading } = useQuery({
    queryKey: ['binaryMetadata', binaryName],
    queryFn: () => apiClient.get(`/binary/${binaryName}`).then(res => res.data),
    enabled: !!binaryName,
  });

  if (isLoading) return <div>Loading metadata...</div>;

  return (
    <div className="space-y-6">
      <h3 className="text-lg font-medium">Overview</h3>
      <div className="grid gap-4 md:grid-cols-2">
         <Card>
            <CardHeader>
                <CardTitle className="text-base">File Information</CardTitle>
            </CardHeader>
            <CardContent className="space-y-2 text-sm">
                <div className="flex justify-between">
                    <span className="text-muted-foreground">Name</span>
                    <span className="font-medium">{metadata?.name}</span>
                </div>
                 <div className="flex justify-between">
                    <span className="text-muted-foreground">Architecture</span>
                    <span className="font-medium">{metadata?.arch}</span>
                </div>
                <div className="flex justify-between">
                    <span className="text-muted-foreground">Base Address</span>
                    <span className="font-medium font-mono">{metadata?.base_addr ? `0x${metadata.base_addr.toString(16)}` : 'N/A'}</span>
                </div>
                 <div className="flex justify-between">
                    <span className="text-muted-foreground">Size</span>
                    <span className="font-medium">{metadata?.size} bytes</span>
                </div>
            </CardContent>
         </Card>
          <Card>
            <CardHeader>
                <CardTitle className="text-base">Analysis Stats</CardTitle>
            </CardHeader>
            <CardContent className="space-y-2 text-sm">
                <div className="flex justify-between">
                    <span className="text-muted-foreground">Functions</span>
                    <span className="font-medium">{metadata?.function_count}</span>
                </div>
                 <div className="flex justify-between">
                    <span className="text-muted-foreground">Imported At</span>
                    <span className="font-medium">{new Date(metadata?.created_at).toLocaleString()}</span>
                </div>
                 <div className="flex justify-between">
                    <span className="text-muted-foreground">MD5</span>
                    <span className="font-medium font-mono text-xs truncate max-w-[150px]" title={metadata?.md5}>{metadata?.md5}</span>
                </div>
                 <div className="flex justify-between">
                    <span className="text-muted-foreground">SHA256</span>
                    <span className="font-medium font-mono text-xs truncate max-w-[150px]" title={metadata?.sha256}>{metadata?.sha256}</span>
                </div>
            </CardContent>
         </Card>
      </div>
    </div>
  );
}
