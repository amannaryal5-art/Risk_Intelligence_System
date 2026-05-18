import { Navigate, Route, Routes, useLocation } from 'react-router-dom'
import { motion } from 'framer-motion'
import { useAuthStore } from './store/authStore'
import Shell from './components/layout/Shell'
import Login from './pages/Login'
import Dashboard from './pages/Dashboard'
import Intelligence from './pages/Intelligence'
import DeviceScan from './pages/DeviceScan'
import Cases from './pages/Cases'
import CaseDetail from './pages/CaseDetail'
import ARIA from './pages/ARIA'
import Assets from './pages/Assets'
import Alerts from './pages/Alerts'
import AutoPilot from './pages/AutoPilot'
import Reports from './pages/Reports'
import FeedStatus from './pages/FeedStatus'
import Admin from './pages/Admin'

function ProtectedLayout() {
  const location = useLocation()
  const user = useAuthStore((state) => state.user)

  return (
    <Shell userRole={user?.role}>
      <motion.div key={location.pathname} initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} className="mx-auto w-full max-w-[1600px]">
        <Routes>
          <Route path="/" element={<Dashboard />} />
          <Route path="/intelligence" element={<Intelligence />} />
          <Route path="/device" element={<DeviceScan />} />
          <Route path="/analyze" element={<Navigate to="/intelligence" replace />} />
          <Route path="/threat-intel" element={<Navigate to="/intelligence" replace />} />
          <Route path="/website-intel" element={<Navigate to="/intelligence" replace />} />
          <Route path="/malware" element={<Navigate to="/intelligence" replace />} />
          <Route path="/fusion-scan" element={<Navigate to="/intelligence" replace />} />
          <Route path="/cases" element={<Cases />} />
          <Route path="/cases/:id" element={<CaseDetail />} />
          <Route path="/aria" element={<ARIA />} />
          <Route path="/assets" element={<Assets />} />
          <Route path="/alerts" element={<Alerts />} />
          <Route path="/autopilot" element={<AutoPilot />} />
          <Route path="/reports" element={<Reports />} />
          <Route path="/feeds" element={<FeedStatus />} />
          <Route path="/admin" element={user?.role === 'admin' ? <Admin /> : <Navigate to="/" replace />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </motion.div>
    </Shell>
  )
}

export default function App() {
  const user = useAuthStore((state) => state.user)

  return (
    <Routes>
      <Route path="/login" element={user?.authenticated ? <Navigate to="/" replace /> : <Login />} />
      <Route path="/*" element={user?.authenticated ? <ProtectedLayout /> : <Navigate to="/login" replace />} />
    </Routes>
  )
}
