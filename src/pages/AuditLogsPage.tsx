import { useEffect, useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Card } from '@/components/ui/Card';
import { Button } from '@/components/ui/Button';
import { EmptyState } from '@/components/ui/EmptyState';
import { Input } from '@/components/ui/Input';
import { Modal } from '@/components/ui/Modal';
import { logsApi, type RequestAuditLogFile } from '@/services/api/logs';
import { useAuthStore, useNotificationStore } from '@/stores';
import { formatUnixTimestamp } from '@/utils/format';
import { downloadBlob } from '@/utils/download';
import styles from './AuditLogsPage.module.scss';

const getErrorMessage = (err: unknown): string => {
  if (err instanceof Error) return err.message;
  if (typeof err === 'string') return err;
  return '';
};

export function AuditLogsPage() {
  const { t } = useTranslation();
  const connectionStatus = useAuthStore((state) => state.connectionStatus);
  const { showNotification } = useNotificationStore();
  const [query, setQuery] = useState('');
  const [principal, setPrincipal] = useState('');
  const [provider, setProvider] = useState('');
  const [method, setMethod] = useState('');
  const [requestId, setRequestId] = useState('');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [files, setFiles] = useState<RequestAuditLogFile[]>([]);
  const [selected, setSelected] = useState<RequestAuditLogFile | null>(null);
  const [selectedContent, setSelectedContent] = useState('');
  const [contentLoading, setContentLoading] = useState(false);

  const filters = useMemo(
    () => ({
      q: query.trim() || undefined,
      principal: principal.trim() || undefined,
      provider: provider.trim() || undefined,
      request_id: requestId.trim() || undefined,
      method: method.trim().toUpperCase() || undefined,
    }),
    [method, principal, provider, query, requestId]
  );

  const load = async () => {
    if (connectionStatus !== 'connected') {
      setFiles([]);
      setLoading(false);
      return;
    }
    setLoading(true);
    setError('');
    try {
      const response = await logsApi.fetchRequestLogs(filters);
      setFiles(Array.isArray(response.files) ? response.files : []);
    } catch (err: unknown) {
      setError(getErrorMessage(err) || t('audit_logs.load_error'));
      setFiles([]);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    void load();
  }, [connectionStatus]);

  const handleSearch = async () => {
    await load();
  };

  const handleOpen = async (file: RequestAuditLogFile) => {
    setSelected(file);
    setSelectedContent('');
    setContentLoading(true);
    try {
      const response = await logsApi.fetchRequestLogContent(file.request_id);
      setSelectedContent(response.content || '');
    } catch (err: unknown) {
      showNotification(getErrorMessage(err) || t('audit_logs.content_load_error'), 'error');
    } finally {
      setContentLoading(false);
    }
  };

  const handleDownload = async (file: RequestAuditLogFile) => {
    try {
      const response = await logsApi.downloadRequestLogById(file.request_id);
      downloadBlob({ filename: file.name, blob: new Blob([response.data], { type: 'text/plain' }) });
      showNotification(t('audit_logs.download_success'), 'success');
    } catch (err: unknown) {
      showNotification(getErrorMessage(err) || t('audit_logs.download_error'), 'error');
    }
  };

  return (
    <div className={styles.container}>
      <h1 className={styles.pageTitle}>{t('audit_logs.title')}</h1>
      <Card className={styles.card}>
        <div className={styles.filters}>
          <Input value={query} onChange={(event) => setQuery(event.target.value)} label={t('audit_logs.search')} />
          <Input value={principal} onChange={(event) => setPrincipal(event.target.value)} label={t('audit_logs.principal')} />
          <Input value={provider} onChange={(event) => setProvider(event.target.value)} label={t('audit_logs.provider')} />
          <Input value={method} onChange={(event) => setMethod(event.target.value)} label={t('audit_logs.method')} />
          <Input value={requestId} onChange={(event) => setRequestId(event.target.value)} label={t('audit_logs.request_id')} />
          <div className={styles.actions}>
            <Button onClick={() => void handleSearch()} loading={loading}>
              {t('common.refresh')}
            </Button>
          </div>
        </div>

        {error ? <div className="error-box">{error}</div> : null}

        {!loading && files.length === 0 ? (
          <EmptyState title={t('audit_logs.empty_title')} description={t('audit_logs.empty_desc')} />
        ) : null}

        <div className={styles.list}>
          {files.map((file) => (
            <button key={file.name} type="button" className={styles.item} onClick={() => void handleOpen(file)}>
              <div className={styles.itemMain}>
                <div className={styles.itemTop}>
                  <span className={styles.method}>{file.method || '-'}</span>
                  <span className={styles.status}>{file.status || 0}</span>
                  <span className={styles.requestId}>{file.request_id}</span>
                </div>
                <div className={styles.url}>{file.url || '-'}</div>
                <div className={styles.meta}>
                  <span>{t('audit_logs.principal')}: {file.principal || '-'}</span>
                  <span>{t('audit_logs.provider')}: {file.provider || '-'}</span>
                  <span>{t('audit_logs.client_ip')}: {file.client_ip || '-'}</span>
                  <span>{formatUnixTimestamp(file.modified)}</span>
                </div>
              </div>
              <div className={styles.itemActions}>
                <Button variant="secondary" size="sm" onClick={(event) => { event.stopPropagation(); void handleDownload(file); }}>
                  {t('common.download', { defaultValue: '下载' })}
                </Button>
              </div>
            </button>
          ))}
        </div>
      </Card>

      <Modal
        open={Boolean(selected)}
        onClose={() => setSelected(null)}
        title={selected?.request_id || t('audit_logs.detail_title')}
        width={960}
      >
        <div className={styles.modalContent}>
          {contentLoading ? <div className="hint">{t('common.loading')}</div> : null}
          {!contentLoading ? <pre className={styles.pre}>{selectedContent}</pre> : null}
        </div>
      </Modal>
    </div>
  );
}
