import client from './client'

export const getWhoAmI = async () => (await client.get('/api/v1/auth/whoami')).data
export const getHealth = async () => (await client.get('/api/v1/health')).data
