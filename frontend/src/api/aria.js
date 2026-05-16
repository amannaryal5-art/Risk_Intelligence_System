import client from './client'

export const ariaChat = async (payload) => (await client.post('/api/aria/chat', payload)).data
export const getAriaAssets = async () => (await client.get('/api/aria/assets')).data
export const addAriaAsset = async (payload) => (await client.post('/api/aria/assets', payload)).data
export const deleteAriaAsset = async (id) => (await client.delete(`/api/aria/assets/${id}`)).data
export const scanAriaAsset = async (id) => (await client.post(`/api/aria/assets/${id}/scan`)).data
export const getAriaAssetHistory = async (id) => (await client.get(`/api/aria/assets/${id}/history`)).data
export const getAriaAssetSummary = async (id) => (await client.get(`/api/aria/assets/${id}/summary`)).data
export const getAriaAlerts = async () => (await client.get('/api/aria/alerts')).data
export const markAriaAlertSeen = async (id) => (await client.post(`/api/aria/alerts/${id}/seen`)).data
export const markAllAriaAlertsSeen = async () => (await client.post('/api/aria/alerts/seen-all')).data
export const getAriaReports = async () => (await client.get('/api/aria/reports')).data
export const getAriaReport = async (id) => (await client.get(`/api/aria/reports/${id}`)).data
export const generateAriaReport = async () => (await client.post('/api/aria/reports/generate')).data
export const getAriaStats = async () => (await client.get('/api/aria/stats')).data
