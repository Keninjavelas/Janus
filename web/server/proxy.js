const express = require('express');
const { createProxyMiddleware } = require('http-proxy-middleware');
const cors = require('cors');

const app = express();
const PORT = 3001;

// Enable CORS
app.use(cors());

// Proxy all requests to the Go HTTP API
app.use('/api', createProxyMiddleware({
  target: 'http://localhost:8080',
  changeOrigin: true,
  pathRewrite: {
    '^/api': '/api',
  },
}));

// Health check
app.get('/health', (req, res) => {
  res.json({ status: 'healthy', proxy: 'running' });
});

app.listen(PORT, () => {
  console.log(`Proxy server running on port ${PORT}`);
  console.log(`Proxying requests to http://localhost:8080`);
});
