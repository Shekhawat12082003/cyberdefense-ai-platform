import axios from 'axios'

const BASE = 'http://localhost:5000/api'

const getHeaders = () => ({
  Authorization: `Bearer ${localStorage.getItem('token')}`
})

export const login    = (u, p) => axios.post(`${BASE}/login`, { username: u, password: p })
export const getStats   = ()  => axios.get(`${BASE}/stats`,   { headers: getHeaders() })
export const getThreats = ()  => axios.get(`${BASE}/threats`, { headers: getHeaders() })
export const getSHAP    = ()  => axios.get(`${BASE}/shap`,    { headers: getHeaders() })
export const predict    = (f) => axios.post(`${BASE}/predict`, { features: f }, { headers: getHeaders() })
export const getAuditLogs = () => axios.get(`${BASE}/audit-log`, { headers: getHeaders() })

export const uploadScan = (file) => {
  const form = new FormData()
  form.append('file', file)
  return axios.post(`${BASE}/upload-scan`, form, {
    headers: { ...getHeaders(), 'Content-Type': 'multipart/form-data' }
  })
}

export const exportThreatsCSV = () => {
  const a = document.createElement('a')
  a.href = `${BASE}/threats/export/csv`
  const token = localStorage.getItem('token')
  fetch(`${BASE}/threats/export/csv`, { headers: { Authorization: `Bearer ${token}` } })
    .then(r => r.blob())
    .then(blob => {
      const url = URL.createObjectURL(blob)
      a.href = url
      a.download = `threats_${Date.now()}.csv`
      a.click()
      URL.revokeObjectURL(url)
    })
}