import client from './client'

export const analyzeText = async (payload) => (await client.post('/api/v1/analyze', payload)).data
export const analyzeBatch = async (payload) => (await client.post('/api/v1/analyze/batch', payload)).data
export const scamCheck = async (payload) => (await client.post('/api/v1/scamcheck', payload)).data
export const fusionScan = async (payload) => (
  await client.post('/api/v1/fusion-scan', payload, { timeout: 180000 })
).data
