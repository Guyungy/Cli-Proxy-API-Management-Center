/**
 * 日志相关 API
 */

import { apiClient } from './client';
import { LOGS_TIMEOUT_MS } from '@/utils/constants';

export interface LogsQuery {
  after?: number;
}

export interface LogsResponse {
  lines: string[];
  'line-count': number;
  'latest-timestamp': number;
}

export interface ErrorLogFile {
  name: string;
  size?: number;
  modified?: number;
}

export interface ErrorLogsResponse {
  files?: ErrorLogFile[];
}

export interface RequestAuditLogFile {
  name: string;
  request_id: string;
  method: string;
  url: string;
  client_ip: string;
  principal: string;
  provider: string;
  status: number;
  modified: number;
  size: number;
}

export interface RequestAuditLogsQuery {
  q?: string;
  principal?: string;
  provider?: string;
  request_id?: string;
  method?: string;
}

export interface RequestAuditLogsResponse {
  files?: RequestAuditLogFile[];
}

export interface RequestAuditLogContentResponse {
  file?: RequestAuditLogFile;
  content?: string;
}

export const logsApi = {
  fetchLogs: (params: LogsQuery = {}): Promise<LogsResponse> =>
    apiClient.get('/logs', { params, timeout: LOGS_TIMEOUT_MS }),

  clearLogs: () => apiClient.delete('/logs'),

  fetchErrorLogs: (): Promise<ErrorLogsResponse> =>
    apiClient.get('/request-error-logs', { timeout: LOGS_TIMEOUT_MS }),

  downloadErrorLog: (filename: string) =>
    apiClient.getRaw(`/request-error-logs/${encodeURIComponent(filename)}`, {
      responseType: 'blob',
      timeout: LOGS_TIMEOUT_MS
    }),

  downloadRequestLogById: (id: string) =>
    apiClient.getRaw(`/request-log-by-id/${encodeURIComponent(id)}`, {
      responseType: 'blob',
      timeout: LOGS_TIMEOUT_MS
    }),

  fetchRequestLogs: (params: RequestAuditLogsQuery = {}): Promise<RequestAuditLogsResponse> =>
    apiClient.get('/request-logs', { params, timeout: LOGS_TIMEOUT_MS }),

  fetchRequestLogContent: (id: string): Promise<RequestAuditLogContentResponse> =>
    apiClient.get(`/request-log-content/${encodeURIComponent(id)}`, { timeout: LOGS_TIMEOUT_MS }),
};
