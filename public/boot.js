// Serve the pinned React UMD builds from this origin instead of unpkg (same files, same SRI hashes).
window.__resources = {
  'https://unpkg.com/react@18.3.1/umd/react.production.min.js': '/vendor/react.production.min.js',
  'https://unpkg.com/react-dom@18.3.1/umd/react-dom.production.min.js': '/vendor/react-dom.production.min.js',
};
// Apply the saved theme before first paint, so light and Auto users do not see a dark flash. /rules is always dark.
if (!location.pathname.startsWith('/rules')) {
  let t = 'dark';
  try { t = localStorage.getItem('signalwatch.theme') || 'dark'; } catch (e) {}
  document.documentElement.style.colorScheme = t === 'system' ? 'light dark' : t;
  document.documentElement.style.background = 'light-dark(#eef1f5,#111418)';
}
