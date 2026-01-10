import axios from 'axios';

// Default to localhost:8765 if not specified
const API_BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:8765/api/v1';

export const apiClient = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    'Content-Type': 'application/json',
  },
});

apiClient.interceptors.response.use(
  (response) => response,
  (error) => {
    // Handle global errors here
    console.error('API Error:', error);
    return Promise.reject(error);
  }
);

export interface ProjectOverview {
  project: string;
  binaries_count: number;
  analysis_status: string;
  backend: string;
  capabilities: Record<string, boolean>;
}

export interface BinarySummary {
  binary_name: string;
  sha256?: string;
  arch?: string;
  file_format?: string;
  size?: number;
  function_count?: number;
  created_at?: string;
  [key: string]: any;
}

export const projectApi = {
  getOverview: () => apiClient.get<ProjectOverview>('/project').then(res => res.data),
  listBinaries: (offset = 0, limit = 50) => 
    apiClient.get<BinarySummary[]>('/project/binaries', { params: { offset, limit } }).then(res => res.data),
};
