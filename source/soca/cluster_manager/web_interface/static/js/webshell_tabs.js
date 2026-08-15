// -----------------------------------------------------------------------
// webshell_tabs.js - shared tab manager for inline + pop-out browser
// terminals. Each tab owns an independent tmux session
// (edh_<user>_<label>) backed by its own WebSocket.
//
//
//
// Session discovery: at construction time we call /web_terminal/sessions
// and render a tab for every existing tmux session owned by this
// user. Existing sessions are shown as 'detached' until clicked;
// clicking them opens a WebSocket and attaches.
// -----------------------------------------------------------------------

(function(global) {
    'use strict';

    const DEFAULT_I18N = {
        connecting:     'Connecting...',
        connected:      'Connected',
        disconnected:   'Disconnected',
        detached:       'Detached',
        auth_failed:    'Authentication failed.',
        ws_error:       'WebSocket error',
        // Detach (pause icon): closes the WS but the remote tmux session
        // keeps running so you can reattach later. Non-destructive.
        detach_tab:     'Detach (session keeps running)',
        // Kill (X icon): terminates tmux. Destructive, prompts for confirm.
        kill_tab:       'End session (kill tmux)',
        confirm_kill:   'End this terminal session? The remote tmux will be terminated and any work inside is lost.',
        last_tab_close: 'This is the last tab. Close the window?',
    };

    class WebshellTabManager {
        /**
         * @param {Object} opts
         * @param {HTMLElement} opts.tabBar      Tab header container (must have a "+" button with id=edh-new-tab)
         * @param {HTMLElement} opts.termContainer Terminal panes container
         * @param {string}      opts.labelPrefix  Prefix for auto-generated session labels
         * @param {string}      opts.storageKey   sessionStorage key for tab persistence
         * @param {string}      opts.csrfToken    CSRF token (from {{ csrf_token() }})
         * @param {Object}      [opts.i18n]       Override default translated strings
         * @param {boolean}     [opts.autoOpen=false]    If true, opens a fresh tab on init when no sessions exist
         * @param {boolean}     [opts.closeWindowOnLastTab=false] Pop-out mode
         * @param {HTMLElement} [opts.emptyState] Optional element shown when zero tabs
         * @param {string}      [opts.initialLabel] Optional label to open on init
         */
        constructor(opts) {
            this.opts = opts;
            this.i18n = Object.assign({}, DEFAULT_I18N, opts.i18n || {});
            this.tabs = new Map();       // Map<label, Tab>
            this.activeLabel = null;
            this.tabCounter = 0;

            this._bindElements();
            this._bindEvents();
        }

        _bindElements() {
            this.tabBar = this.opts.tabBar;
            this.termContainer = this.opts.termContainer;
            this.emptyState = this.opts.emptyState || null;
            this.newTabBtn = this.tabBar.querySelector('.edh-new-tab, #edh-new-tab');
            if (!this.newTabBtn) {
                // Inject one if caller didn't provide.
                this.newTabBtn = document.createElement('div');
                this.newTabBtn.className = 'edh-new-tab';
                this.newTabBtn.id = 'edh-new-tab';
                this.newTabBtn.textContent = '+';
                this.newTabBtn.title = '+';
                this.tabBar.appendChild(this.newTabBtn);
            }
        }

        _bindEvents() {
            this.newTabBtn.addEventListener('click', () => {
                this.createTab(this._nextLabel());
            });

            // Re-fit active terminal on window resize (debounced).
            let resizeTimer = null;
            window.addEventListener('resize', () => {
                if (resizeTimer) clearTimeout(resizeTimer);
                resizeTimer = setTimeout(() => {
                    const tab = this.tabs.get(this.activeLabel);
                    if (!tab) return;
                    try { tab.fitAddon.fit(); } catch (e) {}
                }, 80);
            });

            // Ctrl+Shift+T -> new tab.
            window.addEventListener('keydown', (e) => {
                if (e.ctrlKey && e.shiftKey && (e.key === 'T' || e.key === 't')) {
                    e.preventDefault();
                    this.createTab(this._nextLabel());
                }
            });

            // Close all WS on window unload so the service promptly sees detach.
            window.addEventListener('beforeunload', () => {
                for (const tab of this.tabs.values()) {
                    if (tab.ws && tab.ws.readyState === WebSocket.OPEN) {
                        try { tab.ws.close(1000, 'window closed'); } catch (e) {}
                    }
                }
            });
        }

        // ---------------------------------------------------------------
        // Init: discover existing sessions via API, render detached tabs,
        // restore persisted state from sessionStorage, and finally open
        // an initial tab if autoOpen.
        // ---------------------------------------------------------------
        async init() {
            let discovered = [];
            try {
                const resp = await fetch('/web_terminal/sessions', {
                    method: 'GET',
                    credentials: 'same-origin',
                    headers: { 'Accept': 'application/json' },
                });
                if (resp.ok) {
                    const body = await resp.json();
                    if (body && body.success && body.message && Array.isArray(body.message.sessions)) {
                        discovered = body.message.sessions;
                    }
                }
            } catch (e) {
                // Non-fatal - continue without discovery.
                console.warn('webshell session discovery failed:', e);
            }

            // Render discovered sessions as detached tabs. Do NOT connect
            // automatically - user clicks the tab to attach.
            for (const s of discovered) {
                this._renderDiscoveredTab(s.label);
                // Sync counter so auto-generated labels don't collide.
                const m = s.label.match(/-(\d+)$/);
                if (m) {
                    const n = parseInt(m[1], 10);
                    if (!isNaN(n) && n > this.tabCounter) this.tabCounter = n;
                }
            }

            // Persisted state (open tabs prior to accidental reload).
            const persisted = this._loadPersisted();
            for (const label of (persisted.labels || [])) {
                if (!this.tabs.has(label)) {
                    this._renderDiscoveredTab(label);
                }
            }
            if (persisted.counter && persisted.counter > this.tabCounter) {
                this.tabCounter = persisted.counter;
            }

            // If caller supplied an initial label (pop-out window from a
            // specific ?session=... arg), surface it and make it active.
            if (this.opts.initialLabel) {
                if (!this.tabs.has(this.opts.initialLabel)) {
                    this._renderDiscoveredTab(this.opts.initialLabel);
                }
                this._connectTab(this.tabs.get(this.opts.initialLabel));
                this._activate(this.opts.initialLabel);
            } else if (persisted.active && this.tabs.has(persisted.active)) {
                this._connectTab(this.tabs.get(persisted.active));
                this._activate(persisted.active);
            } else if (this.opts.autoOpen && this.tabs.size === 0) {
                this.createTab(this._nextLabel());
            } else if (this.tabs.size > 0) {
                // Activate first tab (visual only - stays detached until clicked).
                this._activate(Array.from(this.tabs.keys())[0]);
            }
            this._renderEmptyState();
        }

        // ---------------------------------------------------------------
        // Tab lifecycle
        // ---------------------------------------------------------------
        createTab(label) {
            if (!label) label = this._nextLabel();
            if (this.tabs.has(label)) {
                this._activate(label);
                const existing = this.tabs.get(label);
                if (existing.state === 'detached') this._connectTab(existing);
                return;
            }
            const tab = this._renderDiscoveredTab(label);
            this._persist();
            this._connectTab(tab);
            this._activate(label);
        }

        /**
         * Detach: close the WS; tmux session keeps running.
         * (Browser tab close button.)
         */
        closeTab(label) {
            const tab = this.tabs.get(label);
            if (!tab) return;
            if (this.tabs.size === 1 && this.opts.closeWindowOnLastTab) {
                if (confirm(this.i18n.last_tab_close)) {
                    window.close();
                }
                return;
            }
            this._teardownTab(tab, /* removeDom */ true);
            this._persist();
            this._activateAfterRemoval(label);
        }

        /**
         * Kill: sends API call to terminate tmux, THEN tears down locally.
         */
        async killTab(label) {
            const tab = this.tabs.get(label);
            if (!tab) return;
            if (!confirm(this.i18n.confirm_kill)) return;

            // Mark UI as killing to give feedback during the API call.
            this._setTabState(tab, 'connecting', 'killing...');

            try {
                const resp = await fetch('/web_terminal/sessions/kill', {
                    method: 'POST',
                    credentials: 'same-origin',
                    headers: {
                        'Accept': 'application/json',
                        'Content-Type': 'application/json',
                        'X-CSRFToken': this.opts.csrfToken,
                    },
                    body: JSON.stringify({ label }),
                });
                // Even on non-2xx we still proceed with local teardown -
                // the user explicitly asked to end it.
                if (!resp.ok) {
                    console.warn('kill returned non-OK', resp.status);
                }
            } catch (e) {
                console.warn('kill request failed', e);
            }
            this._teardownTab(tab, true);
            this._persist();
            this._activateAfterRemoval(label);
        }

        // ---------------------------------------------------------------
        // Internals
        // ---------------------------------------------------------------
        _nextLabel() {
            // Find smallest integer N >= 1 such that `<prefix><N>` is not
            // already a current tab label. Reusing released numbers (rather
            // than monotonic increment) keeps the label set tight after
            // kills: kill main-2, then create -> get main-2 back, not main-4.
            // We also bump tabCounter to the chosen N so old persisted-state
            // logic that compares against tabCounter still behaves sanely.
            const prefix = this.opts.labelPrefix;
            const used = new Set();
            for (const label of this.tabs.keys()) {
                if (label.startsWith(prefix)) {
                    const n = parseInt(label.slice(prefix.length), 10);
                    if (!isNaN(n) && n > 0) used.add(n);
                }
            }
            let n = 1;
            while (used.has(n)) n++;
            this.tabCounter = n;
            return `${prefix}${n}`;
        }

        _renderDiscoveredTab(label) {
            // Build DOM for tab header.
            const tabEl = document.createElement('div');
            tabEl.className = 'edh-tab detached';
            tabEl.dataset.label = label;
            tabEl.innerHTML = `
                <span class="edh-tab-state"></span>
                <span class="edh-tab-label"></span>
                <span class="edh-tab-detach" title="${this._attr(this.i18n.detach_tab)}">&#9208;</span>
                <span class="edh-tab-kill" title="${this._attr(this.i18n.kill_tab)}">&times;</span>
            `;
            tabEl.querySelector('.edh-tab-label').textContent = label;
            this.tabBar.insertBefore(tabEl, this.newTabBtn);

            tabEl.addEventListener('click', (e) => {
                if (e.target.classList.contains('edh-tab-detach')) return;
                if (e.target.classList.contains('edh-tab-kill')) return;
                // Clicking a detached tab connects it.
                const tab = this.tabs.get(label);
                if (tab && tab.state === 'detached') this._connectTab(tab);
                this._activate(label);
            });
            tabEl.querySelector('.edh-tab-detach').addEventListener('click', (e) => {
                e.stopPropagation();
                this.closeTab(label);
            });
            tabEl.querySelector('.edh-tab-kill').addEventListener('click', (e) => {
                e.stopPropagation();
                this.killTab(label);
            });

            // Terminal pane.
            const paneEl = document.createElement('div');
            paneEl.className = 'edh-terminal-pane';
            paneEl.dataset.label = label;
            this.termContainer.appendChild(paneEl);

            const term = new Terminal({
                cursorBlink: true,
                fontFamily: '"Fira Code", "Cascadia Code", "Menlo", "Consolas", monospace',
                fontSize: 14,
                scrollback: 10000,
                theme: { background: '#000000', foreground: '#e0e0e0' },
            });
            const fitAddon = new FitAddon.FitAddon();
            term.loadAddon(fitAddon);
            term.open(paneEl);

            const tab = {
                label, tabEl, paneEl, term, fitAddon,
                ws: null, keepaliveTimer: null, state: 'detached',
            };
            this.tabs.set(label, tab);

            term.onData(data => {
                if (tab.ws && tab.ws.readyState === WebSocket.OPEN) {
                    tab.ws.send(new TextEncoder().encode(data));
                }
            });
            term.onResize(() => {
                if (!tab.ws || tab.ws.readyState !== WebSocket.OPEN) return;
                tab.ws.send(JSON.stringify({
                    type: 'resize', rows: term.rows, cols: term.cols,
                }));
            });

            // Wheel -> tmux scrollback via user-keys (mouse stays off so browser keeps native select/copy); Shift = browser scroll
            term.attachCustomWheelEventHandler((ev) => {
                if (ev.shiftKey) return true;
                if (!tab.ws || tab.ws.readyState !== WebSocket.OPEN) return true;
                ev.preventDefault();
                const seq = ev.deltaY < 0 ? '\x1b[5000~' : '\x1b[5001~';
                tab.ws.send(new TextEncoder().encode(seq));
                return false;
            });

            this._setTabState(tab, 'detached', this.i18n.detached);
            this._renderEmptyState();
            return tab;
        }

        _teardownTab(tab, removeDom) {
            if (tab.ws) { try { tab.ws.close(1000, 'teardown'); } catch (e) {} }
            if (tab.keepaliveTimer) clearInterval(tab.keepaliveTimer);
            tab.ws = null;
            tab.keepaliveTimer = null;
            try { tab.term.dispose(); } catch (e) {}
            if (removeDom) {
                tab.tabEl.remove();
                tab.paneEl.remove();
                this.tabs.delete(tab.label);
            }
        }

        _activateAfterRemoval(removedLabel) {
            if (this.activeLabel !== removedLabel) return;
            const remaining = Array.from(this.tabs.keys());
            if (remaining.length > 0) {
                this._activate(remaining[0]);
                const newlyActive = this.tabs.get(remaining[0]);
                if (newlyActive.state === 'detached') this._connectTab(newlyActive);
            } else {
                this.activeLabel = null;
                this._renderEmptyState();
            }
        }

        _activate(label) {
            if (!this.tabs.has(label)) return;
            for (const [lbl, t] of this.tabs.entries()) {
                const on = (lbl === label);
                t.tabEl.classList.toggle('active', on);
                t.paneEl.classList.toggle('active', on);
                if (on) {
                    this.activeLabel = lbl;
                    requestAnimationFrame(() => {
                        try { t.fitAddon.fit(); } catch (e) {}
                        t.term.focus();
                    });
                }
            }
            this._persist();
            this._renderEmptyState();
        }

        _setTabState(tab, state, title) {
            tab.state = state;
            tab.tabEl.classList.remove('connecting', 'connected', 'disconnected', 'detached');
            tab.tabEl.classList.add(state);
            if (title) tab.tabEl.querySelector('.edh-tab-state').title = title;
        }

        async _connectTab(tab) {
            if (tab.ws && (tab.ws.readyState === WebSocket.CONNECTING || tab.ws.readyState === WebSocket.OPEN)) {
                return;  // already connected / connecting
            }
            this._setTabState(tab, 'connecting', this.i18n.connecting);

            let authResp;
            try {
                authResp = await fetch('/web_terminal/terminal_auth', {
                    method: 'POST',
                    credentials: 'same-origin',
                    headers: {
                        'Accept': 'application/json',
                        'X-CSRFToken': this.opts.csrfToken,
                    },
                });
            } catch (err) {
                this._setTabState(tab, 'disconnected', this.i18n.auth_failed);
                tab.term.write('\r\n\x1b[31m*** ' + this.i18n.auth_failed + ' ***\x1b[0m\r\n');
                return;
            }
            if (!authResp.ok) {
                this._setTabState(tab, 'disconnected', this.i18n.auth_failed);
                tab.term.write('\r\n\x1b[31m*** ' + this.i18n.auth_failed
                    + ' (HTTP ' + authResp.status + ') ***\x1b[0m\r\n');
                return;
            }

            const proto = location.protocol === 'https:' ? 'wss' : 'ws';
            const wsUrl = `${proto}://${location.host}/web_terminal/endpoint?session=${encodeURIComponent(tab.label)}`;
            const ws = new WebSocket(wsUrl);
            ws.binaryType = 'arraybuffer';
            tab.ws = ws;

            ws.onmessage = (event) => {
                if (event.data instanceof ArrayBuffer) {
                    tab.term.write(new Uint8Array(event.data));
                } else {
                    tab.term.write(event.data);
                }
            };
            ws.onopen = () => {
                this._setTabState(tab, 'connected', this.i18n.connected);
                requestAnimationFrame(() => {
                    try { tab.fitAddon.fit(); } catch (e) {}
                    if (ws.readyState === WebSocket.OPEN) {
                        ws.send(JSON.stringify({
                            type: 'resize', rows: tab.term.rows, cols: tab.term.cols,
                        }));
                    }
                });
                tab.keepaliveTimer = setInterval(() => {
                    if (ws.readyState === WebSocket.OPEN) {
                        ws.send(JSON.stringify({ type: 'ping' }));
                    }
                }, 30000);
            };
            ws.onclose = (event) => {
                this._setTabState(tab, 'disconnected', this.i18n.disconnected);
                const reason = event.reason || (this.i18n.disconnected + ' (code ' + event.code + ')');
                tab.term.write('\r\n\r\n\x1b[31m*** ' + reason + ' ***\x1b[0m\r\n');
                if (tab.keepaliveTimer) { clearInterval(tab.keepaliveTimer); tab.keepaliveTimer = null; }
            };
            ws.onerror = () => {
                this._setTabState(tab, 'disconnected', this.i18n.ws_error);
            };
        }

        _renderEmptyState() {
            if (!this.emptyState) return;
            this.emptyState.style.display = this.tabs.size === 0 ? 'block' : 'none';
        }

        _persist() {
            try {
                sessionStorage.setItem(this.opts.storageKey, JSON.stringify({
                    counter: this.tabCounter,
                    labels: Array.from(this.tabs.keys()),
                    active: this.activeLabel,
                }));
            } catch (e) {}
        }

        _loadPersisted() {
            try {
                const raw = sessionStorage.getItem(this.opts.storageKey);
                return raw ? JSON.parse(raw) : {};
            } catch (e) {
                return {};
            }
        }

        _attr(s) {
            // HTML-attribute-safe version of a translated string.
            return (s || '').replace(/"/g, '&quot;');
        }
    }

    global.WebshellTabManager = WebshellTabManager;
})(window);
