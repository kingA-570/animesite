// ============ AnimeKai Theme Manager (miruro-style) ============
// Themes: dark / light / anilist / catppuccin
// Accents: orange / red / pink / purple / blue / green / yellow
// Settings persist under localStorage["animekai:settings"].
(function () {
    var KEY = 'animekai:settings';
    var THEMES = [
        { name: 'dark', label: 'Dark', color: '#0c1116' },
        { name: 'light', label: 'Light', color: '#eef1f6' },
        { name: 'anilist', label: 'Anilist', color: '#0b1622' },
        { name: 'catppuccin', label: 'Catppuccin', color: '#1e1e2e' }
    ];
    var ACCENTS = [
        { name: 'orange', color: '#e45f3a' },
        { name: 'red', color: '#ef4444' },
        { name: 'pink', color: '#ec4899' },
        { name: 'purple', color: '#a855f7' },
        { name: 'blue', color: '#3b82f6' },
        { name: 'green', color: '#22c55e' },
        { name: 'yellow', color: '#eab308' }
    ];

    function getSettings() {
        try {
            var raw = localStorage.getItem(KEY);
            var s = raw ? JSON.parse(raw) : {};
            if (!s.theme) s.theme = 'dark';
            if (!s.accent) s.accent = 'orange';
            return s;
        } catch (e) {
            return { theme: 'dark', accent: 'orange' };
        }
    }

    function save(settings) {
        try { localStorage.setItem(KEY, JSON.stringify(settings)); } catch (e) { /* ignore */ }
    }

    function apply(settings) {
        var root = document.documentElement;
        root.setAttribute('data-theme', settings.theme);
        root.setAttribute('data-accent', settings.accent);
    }

    // Apply immediately so the page never flashes the wrong theme.
    var settings = getSettings();
    apply(settings);

    function buildUI() {
        var themesEl = document.getElementById('theme-options');
        var accentsEl = document.getElementById('accent-options');
        var toggleBtn = document.querySelector('.theme-toggle-btn');
        var panel = document.getElementById('theme-panel');
        if (!themesEl || !accentsEl || !toggleBtn || !panel) return;

        THEMES.forEach(function (t) {
            var btn = document.createElement('button');
            btn.type = 'button';
            btn.className = 'tp-theme' + (settings.theme === t.name ? ' active' : '');
            btn.innerHTML = '<span class="tp-swatch" style="background:' + t.color + '"></span><span>' + t.label + '</span>';
            btn.addEventListener('click', function () {
                settings.theme = t.name;
                save(settings);
                apply(settings);
                document.querySelectorAll('.tp-theme').forEach(function (x) { x.classList.remove('active'); });
                btn.classList.add('active');
            });
            themesEl.appendChild(btn);
        });

        ACCENTS.forEach(function (a) {
            var dot = document.createElement('button');
            dot.type = 'button';
            dot.className = 'tp-accent' + (settings.accent === a.name ? ' active' : '');
            dot.style.background = a.color;
            dot.title = a.name;
            dot.setAttribute('aria-label', 'Accent ' + a.name);
            dot.addEventListener('click', function () {
                settings.accent = a.name;
                save(settings);
                apply(settings);
                document.querySelectorAll('.tp-accent').forEach(function (x) { x.classList.remove('active'); });
                dot.classList.add('active');
            });
            accentsEl.appendChild(dot);
        });

        toggleBtn.addEventListener('click', function (e) {
            e.stopPropagation();
            panel.classList.toggle('open');
        });
        document.addEventListener('click', function (e) {
            if (!panel.contains(e.target) && !toggleBtn.contains(e.target)) panel.classList.remove('open');
        });
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', buildUI);
    } else {
        buildUI();
    }
})();
