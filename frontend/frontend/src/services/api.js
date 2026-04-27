import axios from 'axios';

const api = axios.create({
  baseURL: 'http://localhost:8000',
});

api.interceptors.request.use((config) => {
  const token = localStorage.getItem('token');
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

export const loginUser = async (username, password) => {
  const formData = new URLSearchParams();
  formData.append('username', username);
  formData.append('password', password);
  const response = await api.post('/login', formData, {
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
  });
  return response.data;
};

export const registerUser = async (username, password) => {
  const response = await api.post('/register', { username, password });
  return response.data;
};

export const startScan = async (target) => {
  const response = await api.post('/scan', { target });
  return response.data;
};

export const getScans = async () => {
  const response = await api.get('/scans');
  return response.data;
};

export const getReport = async (scanId) => {
  const response = await api.get(`/report/${scanId}`, { responseType: 'blob' });
  return response.data;
};

export default api;