import client from './client'

export const getFeedsStatus = async () => (await client.get('/api/v1/feeds/status/live')).data
export const probeFeeds = async () => (await client.get('/api/v1/feeds/probe')).data
export const configureFeeds = async (payload) => (await client.post('/api/v1/feeds/configure', payload)).data
