// theme.js

const themeToggle = document.getElementById('theme-toggle');
const iconSun = document.getElementById('icon-sun');
const iconMoon = document.getElementById('icon-moon');

export const THEMES = {
  dark: 'mbo',
  light: 'duotone-light'
};

/**
 * @param {string} theme - 'dark' or 'light'
 * @param {CodeMirror} editorContent - odeMirror instance for HTML editor
 * @param {CodeMirror} editorCSS - CodeMirror instance for CSS editor
 */
export function setTheme(theme, editorContent, editorCSS) {
  document.documentElement.setAttribute('data-theme', theme);

  if (theme === 'dark') {
    iconMoon.style.display = 'none';
    iconSun.style.display = 'inline';

    if (editorContent && editorCSS) {
      editorContent.setOption('theme', THEMES.dark);
      editorCSS.setOption('theme', THEMES.dark);
    }
  } else {
    iconMoon.style.display = 'inline';
    iconSun.style.display = 'none';

    if (editorContent && editorCSS) {
      editorContent.setOption('theme', THEMES.light);
      editorCSS.setOption('theme', THEMES.light);
    }
  }

  localStorage.setItem('theme', theme);
}

/**
 * toggle dark and light theme
 * @param {CodeMirror} editorContent
 * @param {CodeMirror} editorCSS
 */
export function toggleTheme(editorContent, editorCSS) {
  const currentTheme = document.documentElement.getAttribute('data-theme') || 'light';
  const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
  setTheme(newTheme, editorContent, editorCSS);
}

/**
 * initialize theme toggle and apply saved or default theme
 * @param {CodeMirror} editorContent
 * @param {CodeMirror} editorCSS
 */
export function initializeThemeToggle(editorContent, editorCSS) {
  if (themeToggle) {
    themeToggle.addEventListener('click', () => {
      toggleTheme(editorContent, editorCSS);
    });
  }

  const savedTheme = localStorage.getItem('theme') || 'light';
  setTheme(savedTheme, editorContent, editorCSS);
}
