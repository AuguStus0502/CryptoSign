/* CryptoSign — main.js v5 */

// ── Theme (run immediately before DOM paints) ──
(function () {
  const saved = localStorage.getItem('cs-theme') || 'light';
  document.documentElement.setAttribute('data-theme', saved);
})();

function toggleTheme() {
  const current = document.documentElement.getAttribute('data-theme') || 'light';
  const next = current === 'dark' ? 'light' : 'dark';
  document.documentElement.setAttribute('data-theme', next);
  localStorage.setItem('cs-theme', next);
  updateThemeIcon(next);
}

function updateThemeIcon(theme) {
  const moon = document.getElementById('theme-icon-moon');
  const sun  = document.getElementById('theme-icon-sun');
  if (!moon || !sun) return;
  if (theme === 'dark') {
    moon.style.display = 'none';
    sun.style.display  = 'block';
  } else {
    moon.style.display = 'block';
    sun.style.display  = 'none';
  }
}

document.addEventListener('DOMContentLoaded', () => {
  const theme = document.documentElement.getAttribute('data-theme') || 'light';
  updateThemeIcon(theme);

  // ── File drop zones ──────────────────────────
  document.querySelectorAll('.drop-zone').forEach(zone => {
    const input = zone.querySelector('input[type="file"]');
    const label = zone.querySelector('.drop-zone-text');

    zone.addEventListener('click', () => input && input.click());

    zone.addEventListener('dragover', e => {
      e.preventDefault();
      zone.classList.add('drag-over');
    });

    zone.addEventListener('dragleave', () => zone.classList.remove('drag-over'));

    zone.addEventListener('drop', e => {
      e.preventDefault();
      zone.classList.remove('drag-over');
      if (input && e.dataTransfer.files.length) {
        input.files = e.dataTransfer.files;
        if (label) label.textContent = e.dataTransfer.files[0].name;
        input.dispatchEvent(new Event('change'));
      }
    });

    if (input) {
      input.addEventListener('change', () => {
        if (input.files.length && label) {
          label.textContent = input.files[0].name;
        }
      });
    }
  });

  // ── Copy buttons ──────────────────────────────
  document.querySelectorAll('.copy-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      const target = document.querySelector(btn.dataset.copy);
      if (!target) return;
      navigator.clipboard.writeText(target.textContent.trim()).then(() => {
        const orig = btn.textContent;
        btn.textContent = 'Copied!';
        setTimeout(() => btn.textContent = orig, 1800);
      });
    });
  });

  // ── Auto-dismiss alerts ───────────────────────
  document.querySelectorAll('.alert[data-auto-dismiss]').forEach(el => {
    setTimeout(() => {
      el.style.transition = 'opacity .4s, transform .4s';
      el.style.opacity = '0';
      el.style.transform = 'translateX(20px)';
      setTimeout(() => el.remove(), 400);
    }, 4500);
  });

  // ── Password strength ─────────────────────────
  const pwInput = document.querySelector('#password');
  const pwBar   = document.querySelector('.pw-strength-bar');
  if (pwInput && pwBar) {
    pwInput.addEventListener('input', () => {
      const v = pwInput.value;
      let score = 0;
      if (v.length >= 8)           score++;
      if (v.length >= 12)          score++;
      if (/[A-Z]/.test(v))         score++;
      if (/[0-9]/.test(v))         score++;
      if (/[^A-Za-z0-9]/.test(v))  score++;
      const pct   = (score / 5) * 100;
      const color = score <= 1 ? '#EF4444' : score <= 3 ? '#F59E0B' : '#10B981';
      pwBar.style.width      = pct + '%';
      pwBar.style.background = color;
    });
  }

  // ── Confirm dangerous actions ─────────────────
  document.querySelectorAll('[data-confirm]').forEach(el => {
    el.addEventListener('click', e => {
      if (!confirm(el.dataset.confirm)) e.preventDefault();
    });
  });
});

// ── Security question custom dropdowns ───────────
function toggleDropdown(dropId) {
  const drop  = document.getElementById(dropId);
  const trigger = drop && drop.previousElementSibling;
  const arrow = trigger && trigger.querySelector('.sq-select-arrow');

  // Close all others first
  document.querySelectorAll('.sq-dropdown.open').forEach(d => {
    if (d.id !== dropId) {
      d.classList.remove('open');
      const t = d.previousElementSibling;
      if (t) {
        t.classList.remove('open');
        const a = t.querySelector('.sq-select-arrow');
        if (a) a.classList.remove('rotated');
      }
    }
  });

  if (!drop) return;
  const isOpen = drop.classList.contains('open');
  drop.classList.toggle('open');
  if (trigger) trigger.classList.toggle('open');
  if (arrow) arrow.classList.toggle('rotated', !isOpen);
}

function selectOption(selectId, dropId, labelId, arrowId, value) {
  // Update hidden native select
  const sel = document.getElementById(selectId);
  if (sel) sel.value = value;

  // Update displayed label
  const label = document.getElementById(labelId);
  if (label) label.textContent = value;

  // Mark selected
  const drop = document.getElementById(dropId);
  if (drop) {
    drop.querySelectorAll('.sq-option').forEach(opt => {
      opt.classList.toggle('selected', opt.dataset.value === value);
    });
  }

  // Close dropdown
  if (drop) drop.classList.remove('open');
  const trigger = drop && drop.previousElementSibling;
  if (trigger) trigger.classList.remove('open');
  const arrow = document.getElementById(arrowId);
  if (arrow) arrow.classList.remove('rotated');
}

// Close all dropdowns when clicking outside
document.addEventListener('click', e => {
  if (!e.target.closest('.sq-select-wrap')) {
    document.querySelectorAll('.sq-dropdown.open').forEach(d => {
      d.classList.remove('open');
      const t = d.previousElementSibling;
      if (t) {
        t.classList.remove('open');
        const a = t.querySelector('.sq-select-arrow');
        if (a) a.classList.remove('rotated');
      }
    });
  }
});
