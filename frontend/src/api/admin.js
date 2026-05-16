import client from './client'

export const getAuditLogs = async (limit = 100) => (await client.get('/api/v1/audit', { params: { limit } })).data
export const getCacheStats = async () => (await client.get('/api/v1/cache/stats')).data
export const clearCaches = async () => (await client.post('/api/v1/cache/clear')).data
export const getMetrics = async () => (await client.get('/api/v1/metrics', { responseType: 'text' })).data
