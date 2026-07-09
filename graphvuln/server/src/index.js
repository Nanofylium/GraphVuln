'use strict';

const { createApp } = require('./app');

const PORT = process.env.PORT || 4123;
const app = createApp();

app.listen(PORT, () => {
  // eslint-disable-next-line no-console
  console.log(`GraphVuln API listening on http://localhost:${PORT}`);
});
