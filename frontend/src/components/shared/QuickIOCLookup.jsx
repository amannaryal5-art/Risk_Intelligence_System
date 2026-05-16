import { useState } from 'react'
import { useMutation } from '@tanstack/react-query'
import toast from 'react-hot-toast'
import { Search } from 'lucide-react'
import { getQuickIoc } from '../../api/threatIntel'
import Spinner from '../ui/Spinner'
import IOCResultTable from './IOCResultTable'

const types = ['domain', 'ip', 'url', 'hash_md5', 'hash_sha256', 'hash_sha1']

export default function QuickIOCLookup() {
  const [iocType, setIocType] = useState('domain')
  const [value, setValue] = useState('')
  const [live, setLive] = useState(false)

  const lookup = useMutation({
    mutationFn: () => getQuickIoc(iocType, value, live),
    onError: (error) => toast.error(error.response?.data?.detail || 'IOC lookup failed'),
  })

  return (
    <div className="panel p-5">
      <p className="section-title">Quick IOC Lookup</p>
      <div className="mt-4 grid gap-3">
        <select className="field" value={iocType} onChange={(event) => setIocType(event.target.value)}>
          {types.map((type) => <option key={type}>{type}</option>)}
        </select>
        <input className="field" value={value} onChange={(event) => setValue(event.target.value)} placeholder="Enter IOC value" />
        <label className="flex items-center gap-2 text-sm text-slate-300">
          <input type="checkbox" checked={live} onChange={(event) => setLive(event.target.checked)} />
          Use live feed lookup
        </label>
        <button type="button" className="btn-primary" disabled={!value || lookup.isPending} onClick={() => lookup.mutate()}>
          {lookup.isPending ? <Spinner /> : <Search className="h-4 w-4" />}
          Lookup
        </button>
      </div>

      {lookup.data ? (
        <div className="mt-5">
          <IOCResultTable data={lookup.data} />
        </div>
      ) : null}
    </div>
  )
}
