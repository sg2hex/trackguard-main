(() => {
  const root = document.documentElement;
  const themeKey = 'trackguard-theme';
  const savedTheme = root.dataset.theme || 'light';
  const button = document.createElement('button');

  button.type = 'button';
  button.className = 'theme-toggle';
  button.setAttribute('aria-pressed', String(savedTheme === 'dark'));
  button.innerHTML = `
    <svg class="theme-moon" viewBox="0 0 24 24" aria-hidden="true">
      <path d="M20.5 15.2A8.5 8.5 0 0 1 8.8 3.5 8.5 8.5 0 1 0 20.5 15.2Z"/>
    </svg>
    <svg class="theme-sun" viewBox="0 0 24 24" aria-hidden="true">
      <circle cx="12" cy="12" r="4"/>
      <path d="M12 2v2m0 16v2M4.93 4.93l1.42 1.42m11.3 11.3 1.42 1.42M2 12h2m16 0h2M4.93 19.07l1.42-1.42m11.3-11.3 1.42-1.42"/>
    </svg>
  `;

  const updateButton = (theme) => {
    const isDark = theme === 'dark';
    button.setAttribute('aria-label', `Switch to ${isDark ? 'light' : 'dark'} mode`);
    button.title = `Switch to ${isDark ? 'light' : 'dark'} mode`;
    button.setAttribute('aria-pressed', String(isDark));
  };

  updateButton(savedTheme);
  button.addEventListener('click', () => {
    const nextTheme = root.dataset.theme === 'dark' ? 'light' : 'dark';
    root.dataset.theme = nextTheme;
    updateButton(nextTheme);
    try {
      localStorage.setItem(themeKey, nextTheme);
    } catch (error) {
      console.error('Unable to save theme preference:', error);
    }
  });

  document.body.appendChild(button);
})();
