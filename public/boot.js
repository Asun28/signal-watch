// Serve the pinned React UMD builds from this origin instead of unpkg (same files, same SRI hashes).
window.__resources = {
  'https://unpkg.com/react@18.3.1/umd/react.production.min.js': '/vendor/react.production.min.js',
  'https://unpkg.com/react-dom@18.3.1/umd/react-dom.production.min.js': '/vendor/react-dom.production.min.js',
};
