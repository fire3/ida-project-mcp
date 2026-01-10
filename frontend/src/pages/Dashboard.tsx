import { useQuery } from '@tanstack/react-query';
import { projectApi } from '../api/client';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../components/ui/card';
import { FileCode, Activity, Database } from 'lucide-react';
import { Link } from 'react-router-dom';

export function Dashboard() {
  const { data: overview, isLoading: isOverviewLoading } = useQuery({
    queryKey: ['projectOverview'],
    queryFn: projectApi.getOverview,
  });

  const { data: binaries, isLoading: isBinariesLoading } = useQuery({
    queryKey: ['projectBinaries'],
    queryFn: () => projectApi.listBinaries(0, 50),
  });

  if (isOverviewLoading || isBinariesLoading) {
    return <div>Loading...</div>;
  }

  return (
    <div className="container py-6 space-y-6">
      <div className="grid gap-4 md:grid-cols-3">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">
              Total Binaries
            </CardTitle>
            <Database className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{overview?.binaries_count || 0}</div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">
              Analysis Status
            </CardTitle>
            <Activity className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{overview?.analysis_status || "Unknown"}</div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Project ID</CardTitle>
            <FileCode className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-xs text-muted-foreground truncate" title={overview?.project}>
              {overview?.project || "N/A"}
            </div>
          </CardContent>
        </Card>
      </div>

      <div>
        <h2 className="text-2xl font-bold tracking-tight mb-4">Binaries</h2>
        <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
          {binaries?.map((binary) => (
            <Link key={binary.binary_name} to={`/binary/${encodeURIComponent(binary.binary_name)}/overview`}>
              <Card className="hover:bg-muted/50 transition-colors cursor-pointer h-full">
                <CardHeader>
                  <CardTitle className="truncate" title={binary.binary_name}>{binary.binary_name}</CardTitle>
                  <CardDescription>{binary.arch || "Unknown Arch"}</CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="text-sm text-muted-foreground space-y-1">
                    <div className="flex justify-between">
                      <span>Size:</span>
                      <span>{binary.size ? (binary.size / 1024).toFixed(2) + ' KB' : 'N/A'}</span>
                    </div>
                    <div className="flex justify-between">
                      <span>Functions:</span>
                      <span>{binary.function_count !== undefined ? binary.function_count : 'N/A'}</span>
                    </div>
                    <div className="flex justify-between">
                      <span>Imported:</span>
                      <span>{binary.created_at ? new Date(binary.created_at).toLocaleDateString() : 'N/A'}</span>
                    </div>
                  </div>
                </CardContent>
              </Card>
            </Link>
          ))}
          {!binaries?.length && (
             <div className="text-muted-foreground col-span-full text-center py-10">
                No binaries found in this project.
             </div>
          )}
        </div>
      </div>
    </div>
  );
}
