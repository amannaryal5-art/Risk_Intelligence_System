import client from './client'

export const listCases = async (params) => (await client.get('/api/v1/cases', { params })).data
export const getCase = async (id) => (await client.get(`/api/v1/cases/${id}`)).data
export const createCase = async (payload) => (await client.post('/api/v1/cases', payload)).data
export const createCaseFromAnalysis = async (payload) => (await client.post('/api/v1/cases/from-analysis', payload)).data
export const updateCase = async (id, payload) => (await client.patch(`/api/v1/cases/${id}`, payload)).data
export const deleteCase = async (id) => (await client.delete(`/api/v1/cases/${id}`)).data
export const addCaseComment = async (id, payload) => (await client.post(`/api/v1/cases/${id}/comments`, payload)).data
