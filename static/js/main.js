import { THEMES, initializeThemeToggle } from './theme.js';

let editorContent;
let editorCSS;

document.addEventListener('DOMContentLoaded', () => {
  const preview = document.querySelector('#edit-preview');
  const fullPreviewIframe = document.querySelector('#full-preview-iframe');
  if (!preview || !fullPreviewIframe) return;

  const savedTheme = localStorage.getItem('theme') || 'light';
  const initialTheme = THEMES[savedTheme] || THEMES.light;

  // CodeMirror editors
  editorContent = CodeMirror.fromTextArea(document.getElementById("edit-textarea"), {
    lineNumbers: true,
    mode: "htmlmixed",
    theme: initialTheme,
    indentUnit: 2,
    tabSize: 2,
    lineWrapping: true,
    scrollbarStyle: "null"
  });

  editorCSS = CodeMirror.fromTextArea(document.getElementById("edit-cssarea"), {
    lineNumbers: true,
    mode: "css",
    theme: initialTheme,
    indentUnit: 2,
    tabSize: 2,
    lineWrapping: true,
    scrollbarStyle: "null"
  });
});

document.addEventListener('DOMContentLoaded', () => {
  // tab switching
  const tabButtons = document.querySelectorAll('.tab-button');
  const tabContents = document.querySelectorAll('.tab-content');

  tabButtons.forEach(button => {
    button.addEventListener('click', () => {
      const targetTab = button.dataset.tab;

      tabButtons.forEach(btn => btn.classList.remove('active'));
      button.classList.add('active');

      tabContents.forEach(content => {
        content.style.display = (content.id === `${targetTab}-tab`) ? 'block' : 'none';
      });

      if (targetTab === 'full-preview') {
        updateFullPreviewIframe();
      }
    });
  });

  // initial tab setup
  document.querySelector('.tab-button.active').click();

  // live preview update function
  function updateLivePreview() {
    if (!editorContent || !editorCSS) return;

    const html = editorContent.getValue();
    const css = `<style>${editorCSS.getValue()}</style>`;
    const preview = document.querySelector('#edit-preview');
    if (preview) {
      preview.innerHTML = css + html;
    }
  }

  // full preview iframe update
  function updateFullPreviewIframe() {
    if (!editorContent || !editorCSS) return;

    const iframe = document.querySelector('#full-preview-iframe');
    if (!iframe) return;

    const doc = iframe.contentDocument || iframe.contentWindow.document;
    const html = editorContent.getValue();
    const css = `<style>${editorCSS.getValue()}</style>`;

    doc.open();
    doc.write(css + html);
    doc.close();
  }

  // attach change listeners to CodeMirror editors
  if (editorContent && editorCSS) {
    editorContent.on('change', updateLivePreview);
    editorCSS.on('change', updateLivePreview);
    updateLivePreview(); // initial render
  }
});

// editor resizing
document.addEventListener('DOMContentLoaded', () => {
  const resizable = document.querySelector('.editors-wrapper');
  const containerWidth = resizable.parentElement.getBoundingClientRect().width;
  resizable.style.width = (containerWidth / 1.9) + 'px';
  const handle = resizable.querySelector('.resize-handle');

  handle.addEventListener('mousedown', function(e) {
    e.preventDefault();

    const startX = e.clientX;
    const startWidth = parseInt(window.getComputedStyle(resizable).width, 10);

    function doDrag(e) {
      const newWidth = startWidth + (e.clientX - startX);
      if (newWidth >= 200) {
        resizable.style.width = newWidth + 'px';
      }
    }

    function stopDrag() {
      window.removeEventListener('mousemove', doDrag);
      window.removeEventListener('mouseup', stopDrag);
    }

    window.addEventListener('mousemove', doDrag);
    window.addEventListener('mouseup', stopDrag);
  });
});

// dashboard search and sort
document.addEventListener('DOMContentLoaded', () => {
    const searchInput = document.getElementById('search');
    const pastesContainer = document.querySelector('.pastes-container tbody');
    const dropdown = document.querySelector('.dropdown');
    const selected = dropdown.querySelector('.selected');
    const optionsContainer = dropdown.querySelector('.options');
    const optionsList = optionsContainer.querySelectorAll('div');

    const urlParams = new URLSearchParams(window.location.search);
    let currentSortValue = urlParams.get('sort') || '';
    let currentPage = parseInt(urlParams.get('page')) || 1;
    let debounceTimeout = null;

    const sortText = {
        'a-z': 'A-Z',
        'created': 'Created (Latest to Oldest)',
        'edited': 'Edited (Latest to Oldest)',
        '': 'Sort by'
    };
    selected.textContent = sortText[currentSortValue] || 'Sort by';
    selected.dataset.value = currentSortValue;

    searchInput.value = urlParams.get('search') || '';

    selected.addEventListener('click', () => {
        const isVisible = optionsContainer.style.display === 'block';
        optionsContainer.style.display = isVisible ? 'none' : 'block';
    });

    optionsList.forEach(option => {
        option.addEventListener('click', () => {
            currentSortValue = option.dataset.value || '';
            selected.textContent = option.textContent;
            selected.dataset.value = currentSortValue;
            optionsContainer.style.display = 'none';
            currentPage = 1;
            fetchPastes();
        });
    });

    document.addEventListener('click', (event) => {
        if (!dropdown.contains(event.target)) {
            optionsContainer.style.display = 'none';
        }
    });

    searchInput.addEventListener('input', () => {
        clearTimeout(debounceTimeout);
        debounceTimeout = setTimeout(() => {
            currentPage = 1;
            fetchPastes();
        }, 300);
    });

    document.querySelectorAll('.pagination-controls a.button').forEach(button => {
        button.addEventListener('click', (event) => {
            event.preventDefault();
            const href = button.getAttribute('href');
            const params = new URLSearchParams(href.split('?')[1] || '');
            currentPage = parseInt(params.get('page')) || 1;
            fetchPastes();
        });
    });

    function fetchPastes() {
        const searchTerm = searchInput.value.trim();
        const params = new URLSearchParams();
        if (searchTerm.length > 0) params.append('search', searchTerm);
        if (currentSortValue) params.append('sort', currentSortValue);
        params.append('page', currentPage);

        fetch(`/api/pastes?${params.toString()}`, {
            method: 'GET',
            headers: { 'Accept': 'application/json' },
            credentials: 'same-origin',
        })
        .then(response => {
            if (!response.ok) throw new Error('Network response was not ok');
            return response.json();
        })
        .then(data => {
            pastesContainer.innerHTML = '';
            if (data.pastes.length === 0) {
                pastesContainer.innerHTML = '<tr><td>No pastes found.</td></tr>';
                return;
            }
            for (const paste of data.pastes) {
                const tr = document.createElement('tr');
                const td = document.createElement('td');
                const a = document.createElement('a');
                a.href = `/${paste.token}`;
                a.textContent = paste.token;
                td.appendChild(a);
                tr.appendChild(td);
                pastesContainer.appendChild(tr);
            }

            const paginationControls = document.querySelector('.pagination-controls');
            const backButton = paginationControls.querySelector('a.button:nth-child(1)');
            const nextButton = paginationControls.querySelector('a.button:nth-child(2)');
            
            if (data.has_prev) {
                backButton.classList.remove('disabled');
                backButton.href = `?page=${data.page - 1}${searchTerm ? `&search=${searchTerm}` : ''}${currentSortValue ? `&sort=${currentSortValue}` : ''}`;
            } else {
                backButton.classList.add('disabled');
                backButton.removeAttribute('href');
            }
            
            if (data.has_next) {
                nextButton.classList.remove('disabled');
                nextButton.href = `?page=${data.page + 1}${searchTerm ? `&search=${searchTerm}` : ''}${currentSortValue ? `&sort=${currentSortValue}` : ''}`;
            } else {
                nextButton.classList.add('disabled');
                nextButton.removeAttribute('href');
            }
        })
        .catch(error => {
            console.error('Fetch error:', error);
            pastesContainer.innerHTML = '<tr><td>Error loading pastes.</td></tr>';
        });

        const newUrl = `${window.location.pathname}?${params.toString()}`;
        window.history.pushState({}, '', newUrl);
    }

    fetchPastes();
});