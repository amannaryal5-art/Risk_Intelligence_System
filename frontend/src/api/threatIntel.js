import client from './client'

export const getThreatIntel = async (payload) => (await client.post('/api/v1/threat-intel', payload)).data
export const getWebsiteIntel = async (payload) => (await client.post('/api/v1/website-intel', payload)).data
export const traceWebsite = async (payload) => (
  await client.post('/api/v1/trace-website', payload, { timeout: 180000 })
).data
export const getIOC = async (type, value) => (
  await client.get(`/api/v1/ioc/${type}/${encodeURIComponent(value)}`)
).data
export const getQuickIoc = async (iocType, value, live = false) => (
  await client.get(`/api/v1/ioc/${iocType}/${encodeURIComponent(value)}`, { params: { live } })
).data
