module.exports = {
  apps: [{
    script: 'dist/app.js',
    env: {
      PORT: 9876,
      NODE_ENV: 'development',
    }
  }],
};
