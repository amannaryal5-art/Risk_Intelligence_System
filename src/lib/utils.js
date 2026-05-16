import clsx from 'clsx'
import { twMerge } from 'tailwind-merge'

export const API_BASE = import.meta.env.VITE_API_BASE || 'http://127.0.0.1:8000'

export const RISK_COLORS = {
  critical: { bg: 'bg-red-900/30', text: 'text-red-400', border: 'border-red-700', dot: '#dc2626' },
  high: { bg: 'bg-orange-900/30', text: 'text-orange-400', border: 'border-orange-700', dot: '#ea580c' },
  medium: { bg: 'bg-yellow-900/30', text: 'text-yellow-400', border: 'border-yellow-700', dot: '#d97706' },
  low: { bg: 'bg-green-900/30', text: 'text-green-400', border: 'border-green-600', dot: '#16a34a' },
  clean: { bg: 'bg-emerald-900/30', text: 'text-emerald-400', border: 'border-emerald-600', dot: '#059669' },
  unknown: { bg: 'bg-slate-800/30', text: 'text-slate-400', border: 'border-slate-600', dot: '#475569' },
}

export const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low']
export const STATUS_ORDER = ['new', 'triaged', 'escalated', 'closed']

export function cn(...inputs) {
  return twMerge(clsx(inputs))
}

export function normalizeRiskLevel(value) {
  const v = String(value || 'unknown').toLowerCase()
  if (v.includes('critical')) return 'critical'
  if (v.includes('high') || v.includes('danger')) return 'high'
  if (v.includes('medium') || v.includes('caution')) return 'medium'
  if (v.includes('low')) return 'low'
  if (v.includes('clean') || v.includes('safe')) return 'clean'
  return 'unknown'
}

export function riskFromScore(score) {
  const s = Number(score || 0)
  if (s >= 81) return 'critical'
  if (s >= 61) return 'high'
  if (s >= 31) return 'medium'
  if (s > 0) return 'low'
  return 'clean'
}

export function formatDate(value) {
  if (!value) return '—'
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return String(value)
  return date.toLocaleString()
}

export function truncate(value, size = 70) {
  if (!value) return '—'
  return value.length > size ? `${value.slice(0, size)}…` : value
}

export function downloadJson(filename, data) {
  const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = filename
  a.click()
  URL.revokeObjectURL(url)
}

export function downloadCsv(filename, rows) {
  const csv = rows.map((row) => row.map((cell) => `"${String(cell ?? '').replaceAll('"', '""')}"`).join(',')).join('\n')
  const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = filename
  a.click()
  URL.revokeObjectURL(url)
}

export async function copyText(value) {
  await navigator.clipboard.writeText(String(value ?? ''))
}

export function safeArray(value) {
  return Array.isArray(value) ? value : []
}

export function getWsUrl(path) {
  const url = new URL(API_BASE)
  url.protocol = url.protocol === 'https:' ? 'wss:' : 'ws:'
  url.pathname = path
  url.search = ''
  return url.toString()
}

export function pushHistory(key, entry, limit = 10) {
  const current = JSON.parse(localStorage.getItem(key) || '[]')
  const next = [entry, ...current].slice(0, limit)
  localStorage.setItem(key, JSON.stringify(next))
}

export function readHistory(key) {
  return JSON.parse(localStorage.getItem(key) || '[]')
}

export function extractIOCs(text) {
  const content = text || ''
  const urls = [...new Set(content.match(/\bhttps?:\/\/[^\s<>"']+/gi) || [])]
  const ips = [...new Set(content.match(/\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b/g) || [])]
  const domains = [...new Set(content.match(/\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b/gi) || [])]
    .filter((domain) => !urls.some((url) => url.includes(domain)))
  const hashes = [...new Set(content.match(/\b(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})\b/g) || [])]
  return { urls, ips, domains, hashes }
}

export function scoreColor(score) {
  if (score > 80) return '#dc2626'
  if (score > 60) return '#ea580c'
  if (score > 30) return '#d97706'
  return '#16a34a'
}
