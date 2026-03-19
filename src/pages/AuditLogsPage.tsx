import { useEffect, useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Card } from '@/components/ui/Card';
import { Button } from '@/components/ui/Button';
import { EmptyState } from '@/components/ui/EmptyState';
import { Input } from '@/components/ui/Input';
import { Select } from '@/components/ui/Select';
import { IconDownload, IconRefreshCw, IconSearch } from '@/components/ui/icons';
import { logsApi, type RequestAuditLogFile } from '@/services/api/logs';
import { useAuthStore, useConfigStore, useNotificationStore } from '@/stores';
import { formatUnixTimestamp } from '@/utils/format';
import { downloadBlob } from '@/utils/download';
import styles from './AuditLogsPage.module.scss';

type TimeRange = 'today' | '24h' | '7d' | 'custom';

interface ParsedAuditTranscript {
  mergedText: string;
  metaLines: string[];
  messages: Array<{ role: 'system' | 'user' | 'assistant'; text: string }>;
  assistantText: string;
}

const DEFAULT_RISK_PATTERNS: Array<{ key: string; label: string; words: string[] }> = [
  { key: 'sensitive', label: '敏感词', words: ['身份证', '银行卡', '手机号', '住址', '验证码', 'password', 'token', 'secret', 'api-key'] },
  { key: 'privilege', label: '越权词', words: ['绕过', '提权', '越权', '管理员权限', 'admin access', 'bypass', 'override policy', 'disable guard'] },
  { key: 'violation', label: '违规词', words: ['洗钱', '诈骗', '木马', '钓鱼', '违法', '违规', 'exploit', 'malware', 'phishing', 'fraud'] },
];

const getErrorMessage = (err: unknown): string => {
  if (err instanceof Error) return err.message;
  if (typeof err === 'string') return err;
  return '';
};

const startOfToday = () => {
  const date = new Date();
  date.setHours(0, 0, 0, 0);
  return date.getTime();
};

const escapeRegExp = (value: string) => value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

const formatDatetimeLocal = (timestamp: number) => {
  const date = new Date(timestamp);
  const pad = (value: number) => String(value).padStart(2, '0');
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}T${pad(date.getHours())}:${pad(date.getMinutes())}`;
};

const parseDatetimeLocal = (value: string) => {
  if (!value) return null;
  const timestamp = new Date(value).getTime();
  return Number.isFinite(timestamp) ? timestamp : null;
};

const buildHighlightSegments = (content: string, keyword: string) => {
  const query = keyword.trim();
  if (!query) {
    return [{ text: content, highlighted: false }];
  }

  const pattern = new RegExp(`(${escapeRegExp(query)})`, 'gi');
  const parts = content.split(pattern);
  return parts.filter(Boolean).map((part) => ({ text: part, highlighted: pattern.test(part) }));
};

const buildRiskRules = (auditRiskRules: { sensitive?: string[]; privilege?: string[]; violation?: string[] } | undefined) => {
  const source = auditRiskRules || {};
  return DEFAULT_RISK_PATTERNS.map((rule) => {
    const configured = source[rule.key as keyof typeof source];
    const words = Array.isArray(configured) && configured.length > 0 ? configured : rule.words;
    return {
      key: rule.key,
      label: rule.label,
      words,
      patterns: words.map((word) => new RegExp(escapeRegExp(word), 'i')),
    };
  });
};

const detectRiskTags = (
  content: string,
  riskRules: Array<{ key: string; label: string; patterns: RegExp[] }>
) => riskRules.filter((rule) => rule.patterns.some((pattern) => pattern.test(content)));

const extractChunkText = (value: unknown): string[] => {
  if (typeof value === 'string') {
    return value.trim() ? [value] : [];
  }
  if (!Array.isArray(value)) {
    return [];
  }

  const parts: string[] = [];
  value.forEach((item) => {
    if (!item || typeof item !== 'object') return;
    const record = item as Record<string, unknown>;
    if (typeof record.text === 'string' && record.text.trim()) {
      parts.push(record.text);
      return;
    }
    if (record.type === 'output_text' && typeof record.text === 'string' && record.text.trim()) {
      parts.push(record.text);
    }
  });
  return parts;
};

const extractMessageText = (value: unknown): string => {
  if (typeof value === 'string') return value.trim();
  if (!Array.isArray(value)) return '';

  const parts: string[] = [];
  value.forEach((item) => {
    if (!item || typeof item !== 'object') return;
    const record = item as Record<string, unknown>;
    if (typeof record.text === 'string' && record.text.trim()) {
      parts.push(record.text);
      return;
    }
    if (typeof record.input_text === 'string' && record.input_text.trim()) {
      parts.push(record.input_text);
      return;
    }
    if (typeof record.output_text === 'string' && record.output_text.trim()) {
      parts.push(record.output_text);
    }
  });
  return parts.join('\n').trim();
};

const extractRequestMessages = (content: string): Array<{ role: 'system' | 'user' | 'assistant'; text: string }> => {
  const match = content.match(/=== REQUEST BODY ===\s*([\s\S]*?)(?:\n=== .* ===|$)/);
  if (!match?.[1]) return [];
  const raw = match[1].trim();
  if (!raw) return [];

  try {
    const parsed = JSON.parse(raw) as Record<string, unknown>;
    const messages = Array.isArray(parsed.messages) ? parsed.messages : [];
    const parsedMessages: Array<{ role: 'system' | 'user' | 'assistant'; text: string }> = [];
    messages.forEach((message) => {
      if (!message || typeof message !== 'object') return;
      const record = message as Record<string, unknown>;
      const role = record.role;
      if (role !== 'system' && role !== 'user' && role !== 'assistant') return;

      let text = '';
      if (typeof record.content === 'string') {
        text = record.content.trim();
      } else {
        text = extractMessageText(record.content);
      }
      if (!text) return;
      parsedMessages.push({ role, text });
    });
    if (parsedMessages.length > 0) {
      return parsedMessages;
    }

    const input = parsed.input;
    const extractedInput = typeof input === 'string' ? input.trim() : extractMessageText(input);
    if (extractedInput) {
      return [{ role: 'user', text: extractedInput }];
    }
    return [];
  } catch {
    return raw ? [{ role: 'user', text: raw }] : [];
  }
};

const extractSSEBody = (content: string): string => {
  const match = content.match(/=== API RESPONSE(?: [0-9]+)? ===[\s\S]*?Body:\s*([\s\S]*?)(?:\n=== API RESPONSE|$)/);
  return match?.[1]?.trim() || '';
};

const dedupeChunkSequence = (parts: string[]): string[] => {
  const deduped: string[] = [];
  parts.forEach((part) => {
    if (!part) return;
    const previous = deduped[deduped.length - 1];
    if (previous === part) return;
    if (previous && previous.endsWith(part) && part.length <= 12) return;
    deduped.push(part);
  });
  return deduped;
};

const parseAuditTranscript = (content: string): ParsedAuditTranscript | null => {
  const sseBody = extractSSEBody(content);
  const lines = sseBody ? sseBody.split(/\r?\n/) : [];
  const textParts: string[] = [];
  const meta = new Set<string>();
  const messages = extractRequestMessages(content);

  lines.forEach((line) => {
    const trimmed = line.trim();
    if (!trimmed.startsWith('data:')) return;
    const payload = trimmed.slice(5).trim();
    if (!payload || payload === '[DONE]') return;

    try {
      const parsed = JSON.parse(payload) as Record<string, unknown>;
      if (typeof parsed.model === 'string' && parsed.model.trim()) {
        meta.add(`model: ${parsed.model}`);
      }

      const usage = parsed.usage;
      if (usage && typeof usage === 'object') {
        const usageRecord = usage as Record<string, unknown>;
        const total = usageRecord.total_tokens;
        if (typeof total === 'number') {
          meta.add(`tokens: ${total}`);
        }
      }

      const choices = Array.isArray(parsed.choices) ? parsed.choices : [];
      choices.forEach((choice) => {
        if (!choice || typeof choice !== 'object') return;
        const record = choice as Record<string, unknown>;
        const delta = record.delta;
        if (delta && typeof delta === 'object') {
          const deltaRecord = delta as Record<string, unknown>;
          if (typeof deltaRecord.content === 'string' && deltaRecord.content) {
            textParts.push(deltaRecord.content);
          } else {
            extractChunkText(deltaRecord.content).forEach((part) => textParts.push(part));
          }
        }

        const message = record.message;
        if (message && typeof message === 'object') {
          const messageRecord = message as Record<string, unknown>;
          if (typeof messageRecord.content === 'string' && messageRecord.content) {
            textParts.push(messageRecord.content);
          } else {
            extractChunkText(messageRecord.content).forEach((part) => textParts.push(part));
          }
        }
      });
    } catch {
      // Ignore non-JSON stream lines and preserve raw log below.
    }
  });

  const mergedText = dedupeChunkSequence(textParts).join('').trim();
  if (!mergedText && meta.size === 0) {
    return null;
  }

  return {
    mergedText,
    metaLines: Array.from(meta),
    messages,
    assistantText: mergedText,
  };
};

const exportAuditResults = (files: RequestAuditLogFile[], selectedMap: Record<string, string>) => {
  const payload = files.map((file) => ({
    ...file,
    content: selectedMap[file.request_id] || '',
  }));
  const blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' });
  downloadBlob({
    filename: `audit-export-${new Date().toISOString().replace(/[:.]/g, '-')}.json`,
    blob,
  });
};

export function AuditLogsPage() {
  const { t } = useTranslation();
  const connectionStatus = useAuthStore((state) => state.connectionStatus);
  const config = useConfigStore((state) => state.config);
  const { showNotification } = useNotificationStore();
  const [query, setQuery] = useState('');
  const [principal, setPrincipal] = useState('');
  const [provider, setProvider] = useState('');
  const [method, setMethod] = useState('');
  const [requestId, setRequestId] = useState('');
  const [timeRange, setTimeRange] = useState<TimeRange>('24h');
  const [customStart, setCustomStart] = useState(formatDatetimeLocal(Date.now() - 24 * 60 * 60 * 1000));
  const [customEnd, setCustomEnd] = useState(formatDatetimeLocal(Date.now()));
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [files, setFiles] = useState<RequestAuditLogFile[]>([]);
  const [selected, setSelected] = useState<RequestAuditLogFile | null>(null);
  const [selectedContent, setSelectedContent] = useState('');
  const [contentLoading, setContentLoading] = useState(false);
  const [contentMap, setContentMap] = useState<Record<string, string>>({});
  const riskRules = useMemo(() => buildRiskRules(config?.auditRiskRules), [config?.auditRiskRules]);

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

  const filteredByTime = useMemo(() => {
    const now = Date.now();
    let start: number | null = null;
    let end: number | null = now;

    if (timeRange === 'today') start = startOfToday();
    if (timeRange === '24h') start = now - 24 * 60 * 60 * 1000;
    if (timeRange === '7d') start = now - 7 * 24 * 60 * 60 * 1000;
    if (timeRange === 'custom') {
      start = parseDatetimeLocal(customStart);
      end = parseDatetimeLocal(customEnd);
    }

    return files.filter((file) => {
      const timestamp = (file.modified || 0) * 1000;
      if (start !== null && timestamp < start) return false;
      if (end !== null && timestamp > end) return false;
      return true;
    });
  }, [customEnd, customStart, files, timeRange]);

  const activeCount = [query, principal, provider, method, requestId].filter((item) => item.trim()).length + 1;
  const principalCount = useMemo(
    () => new Set(filteredByTime.map((file) => file.principal).filter(Boolean)).size,
    [filteredByTime]
  );
  const todayCount = useMemo(
    () => filteredByTime.filter((file) => (file.modified || 0) * 1000 >= startOfToday()).length,
    [filteredByTime]
  );
  const abnormalCount = useMemo(
    () => filteredByTime.filter((file) => file.status >= 400).length,
    [filteredByTime]
  );
  const keywordHitCount = useMemo(() => {
    const keyword = query.trim().toLowerCase();
    if (!keyword) return 0;
    return filteredByTime.filter((file) => {
      const content = `${file.url} ${file.principal} ${file.provider} ${contentMap[file.request_id] || ''}`.toLowerCase();
      return content.includes(keyword);
    }).length;
  }, [contentMap, filteredByTime, query]);
  const topPrincipal = useMemo(() => {
    const counter = new Map<string, number>();
    filteredByTime.forEach((file) => {
      const key = file.principal || '-';
      counter.set(key, (counter.get(key) || 0) + 1);
    });
    let current = '-';
    let max = 0;
    counter.forEach((count, key) => {
      if (count > max) {
        max = count;
        current = key;
      }
    });
    return current;
  }, [filteredByTime]);

  const riskTags = useMemo(() => detectRiskTags(selectedContent, riskRules), [riskRules, selectedContent]);
  const parsedTranscript = useMemo(() => parseAuditTranscript(selectedContent), [selectedContent]);
  const contextMessages = useMemo(() => {
    if (!parsedTranscript?.messages?.length) return [];
    if (parsedTranscript.messages.length <= 1) return [];
    return parsedTranscript.messages.slice(0, -1);
  }, [parsedTranscript]);
  const latestUserMessage = useMemo(() => {
    if (!parsedTranscript?.messages?.length) return '';
    for (let i = parsedTranscript.messages.length - 1; i >= 0; i -= 1) {
      if (parsedTranscript.messages[i].role === 'user') {
        return parsedTranscript.messages[i].text;
      }
    }
    return '';
  }, [parsedTranscript]);
  const highlightedSegments = useMemo(
    () => buildHighlightSegments(parsedTranscript?.mergedText || selectedContent, query),
    [parsedTranscript?.mergedText, query, selectedContent]
  );

  const load = async () => {
    if (connectionStatus !== 'connected') {
      setFiles([]);
      setSelected(null);
      setSelectedContent('');
      setLoading(false);
      return;
    }
    setLoading(true);
    setError('');
    try {
      const response = await logsApi.fetchRequestLogs(filters);
      const nextFiles = Array.isArray(response.files) ? response.files : [];
      setFiles(nextFiles);
      setSelected((prev) => {
        if (!prev) return nextFiles[0] || null;
        return nextFiles.find((item) => item.request_id === prev.request_id) || nextFiles[0] || null;
      });
    } catch (err: unknown) {
      setError(getErrorMessage(err) || t('audit_logs.load_error'));
      setFiles([]);
      setSelected(null);
      setSelectedContent('');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    void load();
  }, [connectionStatus]);

  useEffect(() => {
    const nextSelected = selected ? filteredByTime.find((item) => item.request_id === selected.request_id) || filteredByTime[0] || null : filteredByTime[0] || null;
    setSelected(nextSelected);
  }, [filteredByTime.length, timeRange, customStart, customEnd]);

  useEffect(() => {
    if (!selected?.request_id) {
      setSelectedContent('');
      return;
    }

    const cached = contentMap[selected.request_id];
    if (cached) {
      setSelectedContent(cached);
      return;
    }

    let cancelled = false;
    const loadContent = async () => {
      setContentLoading(true);
      try {
        const response = await logsApi.fetchRequestLogContent(selected.request_id);
        if (!cancelled) {
          const content = response.content || '';
          setSelectedContent(content);
          setContentMap((prev) => ({ ...prev, [selected.request_id]: content }));
        }
      } catch (err: unknown) {
        if (!cancelled) {
          setSelectedContent('');
          showNotification(getErrorMessage(err) || t('audit_logs.content_load_error'), 'error');
        }
      } finally {
        if (!cancelled) setContentLoading(false);
      }
    };

    void loadContent();
    return () => {
      cancelled = true;
    };
  }, [selected?.request_id, contentMap]);

  const handleSearch = async () => {
    await load();
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

  const handleExport = () => {
    exportAuditResults(filteredByTime, contentMap);
    showNotification(t('audit_logs.export_success'), 'success');
  };

  return (
    <div className={styles.container}>
      <div className={styles.hero}>
        <div className={styles.heroCopy}>
          <span className={styles.eyebrow}>Review Center</span>
          <h1 className={styles.pageTitle}>{t('audit_logs.title')}</h1>
          <p className={styles.description}>{t('audit_logs.review_desc')}</p>
        </div>
        <div className={styles.summaryGrid}>
          <div className={styles.summaryCard}><span className={styles.summaryLabel}>{t('audit_logs.summary_today')}</span><span className={styles.summaryValue}>{todayCount}</span></div>
          <div className={styles.summaryCard}><span className={styles.summaryLabel}>{t('audit_logs.summary_abnormal')}</span><span className={styles.summaryValue}>{abnormalCount}</span></div>
          <div className={styles.summaryCard}><span className={styles.summaryLabel}>{t('audit_logs.summary_keyword_hits')}</span><span className={styles.summaryValue}>{keywordHitCount}</span></div>
          <div className={styles.summaryCard}><span className={styles.summaryLabel}>{t('audit_logs.summary_records')}</span><span className={styles.summaryValue}>{filteredByTime.length}</span></div>
          <div className={styles.summaryCard}><span className={styles.summaryLabel}>{t('audit_logs.summary_principals')}</span><span className={styles.summaryValue}>{principalCount}</span></div>
          <div className={styles.summaryCard}><span className={styles.summaryLabel}>{t('audit_logs.summary_top_principal')}</span><span className={styles.summaryValue}>{topPrincipal}</span></div>
        </div>
      </div>

      <Card className={styles.filterCard}>
        <div className={styles.filterHeader}>
          <div>
            <div className={styles.sectionTitle}>{t('audit_logs.filter_title')}</div>
            <div className={styles.sectionHint}>{t('audit_logs.filter_desc')}</div>
          </div>
          <div className={styles.filterBadge}>{t('audit_logs.active_filters', { count: activeCount })}</div>
        </div>

        <div className={styles.filters}>
          <Input value={query} onChange={(event) => setQuery(event.target.value)} label={t('audit_logs.search')} />
          <Input value={principal} onChange={(event) => setPrincipal(event.target.value)} label={t('audit_logs.principal')} />
          <Input value={provider} onChange={(event) => setProvider(event.target.value)} label={t('audit_logs.provider')} />
          <Input value={method} onChange={(event) => setMethod(event.target.value)} label={t('audit_logs.method')} />
          <Input value={requestId} onChange={(event) => setRequestId(event.target.value)} label={t('audit_logs.request_id')} />
          <div className={styles.selectField}>
            <div className={styles.selectLabel}>{t('audit_logs.time_range')}</div>
            <Select
              value={timeRange}
              onChange={(value) => setTimeRange((value as TimeRange) || '24h')}
              options={[
                { label: t('audit_logs.range_today'), value: 'today' },
                { label: t('audit_logs.range_24h'), value: '24h' },
                { label: t('audit_logs.range_7d'), value: '7d' },
                { label: t('audit_logs.range_custom'), value: 'custom' },
              ]}
              ariaLabel={t('audit_logs.time_range')}
            />
          </div>
          {timeRange === 'custom' ? (
            <>
              <Input type="datetime-local" value={customStart} onChange={(event) => setCustomStart(event.target.value)} label={t('audit_logs.custom_start')} />
              <Input type="datetime-local" value={customEnd} onChange={(event) => setCustomEnd(event.target.value)} label={t('audit_logs.custom_end')} />
            </>
          ) : null}
        </div>

        <div className={styles.actions}>
          <Button variant="secondary" onClick={() => void handleSearch()} loading={loading}><IconSearch size={16} />{t('audit_logs.search_button')}</Button>
          <Button variant="secondary" onClick={() => void load()} disabled={loading}><IconRefreshCw size={16} />{t('common.refresh')}</Button>
          <Button variant="secondary" onClick={handleExport} disabled={filteredByTime.length === 0}><IconDownload size={16} />{t('audit_logs.export_button')}</Button>
        </div>
      </Card>

      {error ? <div className="error-box">{error}</div> : null}
      {!loading && filteredByTime.length === 0 ? <EmptyState title={t('audit_logs.empty_title')} description={t('audit_logs.empty_desc')} /> : null}

      {filteredByTime.length > 0 ? (
        <div className={styles.workspace}>
          <Card className={styles.listCard}>
            <div className={styles.sectionHeader}>
              <div>
                <div className={styles.sectionTitle}>{t('audit_logs.session_list')}</div>
                <div className={styles.sectionHint}>{t('audit_logs.session_list_desc')}</div>
              </div>
              <div className={styles.listCount}>{t('audit_logs.summary_records')}: {filteredByTime.length}</div>
            </div>
            <div className={styles.list}>
              {filteredByTime.map((file) => {
                const active = selected?.request_id === file.request_id;
                const itemRiskTags = detectRiskTags(contentMap[file.request_id] || file.url || '', riskRules);
                return (
                  <button key={file.name} type="button" className={`${styles.item} ${active ? styles.itemActive : ''}`} onClick={() => setSelected(file)}>
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
                        <span>{formatUnixTimestamp(file.modified)}</span>
                      </div>
                      {itemRiskTags.length > 0 ? (
                        <div className={styles.riskTags}>
                          {itemRiskTags.map((tag) => <span key={`${file.request_id}-${tag.key}`} className={styles.riskTag}>{tag.label}</span>)}
                        </div>
                      ) : null}
                    </div>
                  </button>
                );
              })}
            </div>
          </Card>

          <Card className={styles.detailCard}>
            {selected ? (
              <>
                <div className={styles.sectionHeader}>
                  <div>
                    <div className={styles.sectionTitle}>{t('audit_logs.detail_title')}</div>
                    <div className={styles.sectionHint}>{t('audit_logs.detail_desc')}</div>
                  </div>
                  <Button variant="secondary" size="sm" onClick={() => void handleDownload(selected)}><IconDownload size={16} />{t('common.download', { defaultValue: '下载' })}</Button>
                </div>

                {riskTags.length > 0 ? (
                  <div className={styles.riskTags}>
                    {riskTags.map((tag) => <span key={tag.key} className={styles.riskTag}>{tag.label}</span>)}
                  </div>
                ) : null}

                <div className={styles.detailMetaGrid}>
                  <div className={styles.detailMetaItem}><span className={styles.detailMetaLabel}>{t('audit_logs.request_id')}</span><span className={styles.detailMetaValue}>{selected.request_id}</span></div>
                  <div className={styles.detailMetaItem}><span className={styles.detailMetaLabel}>{t('audit_logs.principal')}</span><span className={styles.detailMetaValue}>{selected.principal || '-'}</span></div>
                  <div className={styles.detailMetaItem}><span className={styles.detailMetaLabel}>{t('audit_logs.provider')}</span><span className={styles.detailMetaValue}>{selected.provider || '-'}</span></div>
                  <div className={styles.detailMetaItem}><span className={styles.detailMetaLabel}>{t('audit_logs.client_ip')}</span><span className={styles.detailMetaValue}>{selected.client_ip || '-'}</span></div>
                  <div className={styles.detailMetaItem}><span className={styles.detailMetaLabel}>{t('audit_logs.method')}</span><span className={styles.detailMetaValue}>{selected.method || '-'}</span></div>
                  <div className={styles.detailMetaItem}><span className={styles.detailMetaLabel}>{t('common.status')}</span><span className={styles.detailMetaValue}>{selected.status || 0}</span></div>
                  <div className={`${styles.detailMetaItem} ${styles.detailMetaWide}`}><span className={styles.detailMetaLabel}>URL</span><span className={styles.detailMetaValue}>{selected.url || '-'}</span></div>
                </div>

                <div className={styles.transcriptCard}>
                  <div className={styles.transcriptHeader}>{t('audit_logs.transcript')}</div>
                  {parsedTranscript?.metaLines.length ? (
                    <div className={styles.transcriptMeta}>
                      {parsedTranscript.metaLines.map((line) => (
                        <span key={line} className={styles.transcriptMetaPill}>{line}</span>
                      ))}
                    </div>
                  ) : null}
                  {contentLoading ? <div className="hint">{t('common.loading')}</div> : null}
                  {!contentLoading ? (
                    <div className={styles.conversationView}>
                      {contextMessages.length > 0 ? (
                        <details className={styles.contextPanel}>
                          <summary className={styles.contextSummary}>
                            {t('audit_logs.history_context_count', {
                              defaultValue: '历史上下文（{{count}}条）',
                              count: contextMessages.length,
                            })}
                          </summary>
                          <div className={styles.contextList}>
                            {contextMessages.map((message, index) => (
                              <div
                                key={`${message.role}-${index}`}
                                className={`${styles.messageBubble} ${message.role === 'system' ? styles.systemBubble : message.role === 'assistant' ? styles.assistantBubble : styles.userBubble}`}
                              >
                                <div className={styles.messageRole}>
                                  {message.role === 'system'
                                    ? t('audit_logs.system_role', { defaultValue: '系统提示' })
                                    : message.role === 'assistant'
                                      ? t('audit_logs.history_assistant', { defaultValue: '历史模型消息' })
                                      : t('audit_logs.history_user', { defaultValue: '历史用户消息' })}
                                </div>
                                <div className={styles.messageText}>{message.text}</div>
                              </div>
                            ))}
                          </div>
                        </details>
                      ) : null}

                      {latestUserMessage ? (
                        <div className={`${styles.messageBubble} ${styles.userBubble}`}>
                          <div className={styles.messageRole}>{t('audit_logs.current_user', { defaultValue: '当前用户输入' })}</div>
                          <div className={styles.messageText}>{latestUserMessage}</div>
                        </div>
                      ) : null}

                      <div className={`${styles.messageBubble} ${styles.assistantBubble}`}>
                        <div className={styles.messageRole}>{t('audit_logs.current_assistant', { defaultValue: '本次模型输出' })}</div>
                        <div className={styles.messageText}>
                          {highlightedSegments.map((segment, index) => segment.highlighted ? <mark key={`${segment.text}-${index}`} className={styles.highlight}>{segment.text}</mark> : <span key={`${segment.text}-${index}`}>{segment.text}</span>)}
                        </div>
                      </div>
                    </div>
                  ) : null}
                </div>

                {parsedTranscript?.mergedText ? (
                  <div className={styles.rawCard}>
                    <div className={styles.rawHeader}>{t('audit_logs.raw_transcript', { defaultValue: '原始记录' })}</div>
                    <pre className={styles.rawPre}>{selectedContent}</pre>
                  </div>
                ) : null}
              </>
            ) : (
              <EmptyState title={t('audit_logs.select_title')} description={t('audit_logs.select_desc')} />
            )}
          </Card>
        </div>
      ) : null}
    </div>
  );
}
