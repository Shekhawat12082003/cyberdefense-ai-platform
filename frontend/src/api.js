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