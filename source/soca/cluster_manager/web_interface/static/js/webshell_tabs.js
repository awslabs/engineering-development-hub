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
        paused:         'Paused (idle)',
        ended:          'Session ended',
        auth_failed:    'Authentication failed.',
        ws_error:       'WebSocket error',
        // Written INTO the terminal pane of a tab that is not connected, so a
        // detached pane is never just a blank black rectangle the user cannot
        // tell apart from a hung shell.
        detached_hint:  'This session is still running. Click this tab to reattach.',
        paused_hint:    'Disconnected after a period of inactivity. The session is still running - click this tab to resume.',
        ended_hint:     'This session no longer exists on any login node. Click this tab to start a new one here.',
        locating:       'Locating the login node that holds this session...',
        reconnecting:   'Connection lost - reconnecting...',
        reconnect_gave_up: 'Could not reconnect. Click this tab to try again.',
        on_node:        'Login node',
        // Detach (pause icon): closes the WS but the remote tmux session
        // keeps running so you can reattach later. Non-destructive.
        detach_tab:     'Detach (session keeps running)',
        // Kill (X icon): terminates tmux. Destructive, prompts for confirm.
        kill_tab:       'End session (kill tmux)',
        confirm_kill:   'End this terminal session? The remote tmux will be terminated and any work inside is lost.',
        last_tab_close: 'This is the last tab. Close the window?',
    };

    // WebSocket close codes originated by the login-node webshell service.
    // Kept in sync with webshell_service.py.
    const CLOSE_AUTH_FAILED   = 4401;
    const CLOSE_IDLE_TIMEOUT  = 4408;
    const CLOSE_WRONG_NODE    = 4409;
    const CLOSE_SESSION_GONE  = 4410;

    // A resume is not guaranteed to reach the login node holding the tmux
    // session: the ALB spreads /web_terminal/endpoint across the whole login
    // node ASG with no stickiness. The service answers CLOSE_WRONG_NODE and
    // we immediately reconnect so the ALB picks again. Bounded so a genuinely
    // unreachable session cannot spin forever.
    const WRONG_NODE_MAX_ATTEMPTS = 8;
    const WRONG_NODE_RETRY_MS = 250;

    // Backoff for genuinely abnormal drops (proxy timeout, network blip).
    const RECONNECT_BACKOFF_MS = [1000, 2000, 4000, 8000, 15000];

    // Abnormal close codes worth retrying. A normal 1000 is NOT here on
    // purpose: the service closes 1000 when the user's shell exited, and
    // reconnecting then would spawn a brand new session behind their back.
    const TRANSIENT_CLOSE_CODES = new Set([1001, 1005, 1006, 1011, 1012, 1013, 1014]);

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
         * @param {HTMLElement} [opts.loadingState] Optional element shown while init() discovers sessions
         * @param {string}      [opts.initialLabel] Optional label to open on init
         */
        constructor(opts) {
            this.opts = opts;
            this.i18n = Object.assign({}, DEFAULT_I18N, opts.i18n || {});
            this.tabs = new Map();       // Map<label, Tab>
            this.activeLabel = null;
            this.tabCounter = 0;
            // Set in beforeunload. Suppresses the reconnect logic while the
            // page is going away, so navigating off does not fire a burst of
            // pointless WebSocket attempts.
            this.unloading = false;

            this._bindElements();
            this._bindEvents();
        }

        _bindElements() {
            this.tabBar = this.opts.tabBar;
            this.termContainer = this.opts.termContainer;
            this.emptyState = this.opts.emptyState || null;
            // Optional "Fetching terminals" spinner, visible until session discovery ends
            this.loadingState = this.opts.loadingState || null;
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
                this.unloading = true;
                for (const tab of this.tabs.values()) {
                    if (tab.reconnectTimer) clearTimeout(tab.reconnectTimer);
                    if (tab.ws && tab.ws.readyState === WebSocket.OPEN) {
                        try { tab.ws.close(1000, 'window closed'); } catch (e) {}
                    }
                }
            });
        }

        // ---------------------------------------------------------------
        // Init: discover existing sessions via API, render them, reconcile
        // persisted state against what actually exists, and connect the tab
        // that ends up on screen.
        //
        // The invariant this establishes is "the tab the user is looking at
        // is connected". Previously the only auto-connect path was a
        // matching `active` label in sessionStorage, which is scoped per
        // BROWSER TAB - so arriving from a new browser tab or after a
        // browser restart rendered the session's tab from fleet discovery
        // and then never opened a WebSocket for it. _activate() now owns
        // that decision so on-screen and connected cannot diverge.
        // ---------------------------------------------------------------
        async init() {
            let discovered = [];
            let discoveryOk = false;
            // Discovery fans out to the login nodes and can take a few seconds: keep the
            // "Fetching terminals" spinner up (and the empty state hidden) until it ends.
            if (this.loadingState) this.loadingState.style.display = 'flex';
            if (this.emptyState) this.emptyState.style.display = 'none';
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
                        discoveryOk = true;
                    }
                }
            } catch (e) {
                // Non-fatal - continue without discovery.
                console.warn('webshell session discovery failed:', e);
            } finally {
                if (this.loadingState) this.loadingState.style.display = 'none';
            }

            // Render discovered sessions. Each one records the instance that
            // reported it so a later attach can be pinned to that node.
            const discoveredLabels = new Set();
            for (const s of discovered) {
                discoveredLabels.add(s.label);
                this._renderDiscoveredTab(s.label, {
                    instanceId: s.instance_id || '',
                    origin: 'discovered',
                });
                // Sync counter so auto-generated labels don't collide.
                const m = s.label.match(/-(\d+)$/);
                if (m) {
                    const n = parseInt(m[1], 10);
                    if (!isNaN(n) && n > this.tabCounter) this.tabCounter = n;
                }
            }

            // Persisted state (tabs open before a reload or a navigation
            // away). RECONCILED against discovery rather than merged with
            // it: a persisted label that discovery did not report no longer
            // exists on any login node, and rendering it would let a click
            // silently create a fresh empty session under the old name.
            // Only reconcile when discovery actually succeeded - if the API
            // call failed we know nothing, and dropping every tab on a
            // transient error would be worse than showing a stale one.
            const persisted = this._loadPersisted();
            for (const entry of (persisted.tabs || [])) {
                if (this.tabs.has(entry.label)) continue;
                if (discoveryOk && !discoveredLabels.has(entry.label)) {
                    continue;  // gone from the fleet; do not resurrect it
                }
                this._renderDiscoveredTab(entry.label, {
                    instanceId: entry.instanceId || '',
                    origin: 'persisted',
                });
            }
            if (persisted.counter && persisted.counter > this.tabCounter) {
                this.tabCounter = persisted.counter;
            }

            // Choose which tab ends up on screen. _activate() connects it.
            if (this.opts.initialLabel) {
                // Pop-out window opened for one specific ?session=... label.
                if (!this.tabs.has(this.opts.initialLabel)) {
                    this._renderDiscoveredTab(this.opts.initialLabel, {
                        origin: discoveredLabels.has(this.opts.initialLabel)
                            ? 'discovered' : 'new',
                    });
                }
                this._activate(this.opts.initialLabel);
            } else if (persisted.active && this.tabs.has(persisted.active)) {
                this._activate(persisted.active);
            } else if (this.tabs.size > 0) {
                this._activate(Array.from(this.tabs.keys())[0]);
            } else if (this.opts.autoOpen) {
                this.createTab(this._nextLabel());
            }
            this._persist();
            this._renderEmptyState();
        }

        // ---------------------------------------------------------------
        // Tab lifecycle
        // ---------------------------------------------------------------
        createTab(label) {
            if (!label) label = this._nextLabel();
            if (this.tabs.has(label)) {
                // _activate connects it if it is not already connected.
                this._activate(label);
                return;
            }
            this._renderDiscoveredTab(label, { origin: 'new' });
            this._persist();
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

        _renderDiscoveredTab(label, meta) {
            meta = meta || {};
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
                const tab = this.tabs.get(label);
                // An 'ended' tab is one whose remote session is gone. Only an
                // explicit click may turn it back into a new session -
                // _activate deliberately will not, so nothing creates a
                // session on the user's behalf.
                if (tab && tab.state === 'ended') {
                    tab.origin = 'new';
                    tab.instanceId = '';
                    this._resetRetries(tab);
                    this._connectTab(tab);
                }
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
                // Which login node reported this session, when known. Sent as
                // ?instance= on attach so the service can bounce us off the
                // wrong node instead of creating a duplicate there.
                instanceId: meta.instanceId || '',
                // 'discovered' | 'persisted' -> resume an existing session
                // (attach, never create). 'new' -> create one.
                origin: meta.origin || 'new',
                reconnectTimer: null,
                reconnectAttempts: 0,
                wrongNodeAttempts: 0,
                // True once this attempt has received a byte from the PTY,
                // which is what clears the retry budget. See _connectTab.
                sawData: false,
                // Set before we close a socket ourselves so onclose can tell
                // a deliberate teardown from a connection that dropped.
                intentional: false,
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
            // Never leave an unconnected pane blank. A tab we already know
            // is backed by a live session says so, and says which node it
            // was found on, so a detached pane cannot be mistaken for a
            // connected shell that has hung.
            if (tab.origin !== 'new') {
                const where = tab.instanceId
                    ? ` (${this.i18n.on_node}: ${tab.instanceId})`
                    : '';
                this._writeNotice(tab, this.i18n.detached_hint + where);
            }
            this._renderEmptyState();
            return tab;
        }

        /**
         * Write an out-of-band status line into a terminal pane. Used for
         * states the remote shell cannot report itself (detached, paused,
         * ended, reconnecting) so every pane always explains itself.
         */
        _writeNotice(tab, text, colour) {
            const code = colour || '36';  // cyan: informational, not an error
            try {
                tab.term.write(`\r\n\x1b[${code}m*** ${text} ***\x1b[0m\r\n`);
            } catch (e) {}
        }

        _resetRetries(tab) {
            if (tab.reconnectTimer) { clearTimeout(tab.reconnectTimer); tab.reconnectTimer = null; }
            tab.reconnectAttempts = 0;
            tab.wrongNodeAttempts = 0;
        }

        _teardownTab(tab, removeDom) {
            // Flag first: closing the socket fires onclose, which must not
            // treat a deliberate teardown as a dropped connection and try
            // to reconnect.
            tab.intentional = true;
            this._resetRetries(tab);
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
                // _activate connects it if it is not already connected.
                this._activate(remaining[0]);
            } else {
                this.activeLabel = null;
                // Persist the cleared active label, otherwise sessionStorage
                // keeps pointing at a tab that no longer exists.
                this._persist();
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

            // A tab that is on screen must be connected. This is the single
            // place that decision is made, so "visible" and "connected"
            // cannot drift apart the way they did when init() only connected
            // a sessionStorage-matched label.
            //
            // 'ended' is deliberately excluded: its remote session is gone,
            // so connecting would CREATE one, and that has to be an explicit
            // user action (the tab click handler), not a side effect of a tab
            // becoming visible.
            const tab = this.tabs.get(label);
            if (['detached', 'disconnected', 'paused'].includes(tab.state)) {
                // A user action earns a fresh attempt budget. Without this a
                // tab that exhausted its wrong-node or backoff allowance stays
                // in 'disconnected' with the counters still maxed, so clicking
                // it reconnects once and then gives up on the first close.
                //
                // Reset HERE and not in _connectTab: the automatic paths call
                // _connectTab themselves from setTimeout, so resetting there
                // would zero the counters on every scheduled retry and turn the
                // bounded backoff into an unbounded loop.
                this._resetRetries(tab);
                this._connectTab(tab);
            }
        }

        _setTabState(tab, state, title) {
            tab.state = state;
            tab.tabEl.classList.remove(
                'connecting', 'connected', 'disconnected', 'detached',
                'paused', 'ended',
            );
            tab.tabEl.classList.add(state);
            if (title) tab.tabEl.querySelector('.edh-tab-state').title = title;
        }

        async _connectTab(tab) {
            if (tab.ws && (tab.ws.readyState === WebSocket.CONNECTING || tab.ws.readyState === WebSocket.OPEN)) {
                return;  // already connected / connecting
            }
            if (this.unloading) return;
            if (tab.reconnectTimer) { clearTimeout(tab.reconnectTimer); tab.reconnectTimer = null; }
            tab.intentional = false;
            // Cleared per attempt: the budget is reset by the first PTY byte
            // of THIS attempt, not by any earlier one that happened to succeed.
            tab.sawData = false;
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
                // The tab may already be torn down: see the note below.
                if (this.unloading || tab.intentional) return;
                this._setTabState(tab, 'disconnected', this.i18n.auth_failed);
                tab.term.write('\r\n\x1b[31m*** ' + this.i18n.auth_failed + ' ***\x1b[0m\r\n');
                return;
            }
            // The auth call is a network round trip, and the tab can be detached
            // or killed while it is in flight. _teardownTab sets tab.intentional,
            // disposes tab.term, nulls tab.ws and may remove the tab from the
            // map, so none of the guards at the top of this function can catch
            // it after the fact. Without this re-check the attempt would carry on
            // to open a socket for a session the user just walked away from,
            // attached to no visible tab, and write to a disposed terminal.
            if (this.unloading || tab.intentional) return;
            if (!authResp.ok) {
                this._setTabState(tab, 'disconnected', this.i18n.auth_failed);
                tab.term.write('\r\n\x1b[31m*** ' + this.i18n.auth_failed
                    + ' (HTTP ' + authResp.status + ') ***\x1b[0m\r\n');
                return;
            }

            // Tell the login node what we intend. 'attach' means this session
            // already exists and must NOT be created here - without it, a
            // resume landing on the wrong node (the ALB has no stickiness
            // across the login node ASG) silently creates a second empty
            // session under the same name and the user loses their work.
            // ?instance= names the node that reported the session so the
            // wrong one can bounce us straight away instead of us waiting for
            // the attach to fail.
            const proto = location.protocol === 'https:' ? 'wss' : 'ws';
            const params = ['session=' + encodeURIComponent(tab.label)];
            if (tab.origin !== 'new') {
                params.push('mode=attach');
                if (tab.instanceId) {
                    params.push('instance=' + encodeURIComponent(tab.instanceId));
                }
            }
            const wsUrl = `${proto}://${location.host}/web_terminal/endpoint?${params.join('&')}`;
            const ws = new WebSocket(wsUrl);
            ws.binaryType = 'arraybuffer';
            tab.ws = ws;

            ws.onmessage = (event) => {
                // The FIRST byte from the PTY is the only proof the attach
                // really succeeded, so it is what clears the retry budget.
                //
                // Not onopen: a wrong-node bounce is sent AFTER the WebSocket
                // handshake completes (the service accepts the upgrade, then
                // closes with CLOSE_WRONG_NODE), so onopen fires on a
                // connection that is about to be rejected. Resetting there
                // meant wrongNodeAttempts could never exceed 1, the bound was
                // never reached, and an unreachable session reconnected
                // forever at WRONG_NODE_RETRY_MS.
                if (!tab.sawData) {
                    tab.sawData = true;
                    this._resetRetries(tab);
                }
                if (event.data instanceof ArrayBuffer) {
                    tab.term.write(new Uint8Array(event.data));
                } else {
                    tab.term.write(event.data);
                }
            };
            ws.onopen = () => {
                // Once attached, this session is real regardless of how the
                // tab started life, so any later reconnect must attach
                // rather than create.
                tab.origin = 'discovered';
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
                if (tab.keepaliveTimer) { clearInterval(tab.keepaliveTimer); tab.keepaliveTimer = null; }
                if (tab.ws === ws) tab.ws = null;
                // Deliberate teardown (detach, kill, page unload): say nothing.
                if (tab.intentional || this.unloading) return;
                this._handleClose(tab, event);
            };
            ws.onerror = () => {
                // onerror is always followed by onclose, which owns the state
                // transition and the retry decision. Only set a title here.
                if (tab.tabEl) {
                    const dot = tab.tabEl.querySelector('.edh-tab-state');
                    if (dot) dot.title = this.i18n.ws_error;
                }
            };
        }

        /**
         * Decide what a closed socket means and what to do about it.
         *
         * The close code is the only signal that distinguishes "your session
         * is still there, we just are not talking to it" from "your session
         * is gone". Treating them alike is what left a tab looking alive with
         * nothing behind it.
         */
        _handleClose(tab, event) {
            const code = event.code;

            // The ALB sent us to a login node that does not hold this
            // session. Reconnect straight away so it picks another target.
            if (code === CLOSE_WRONG_NODE) {
                tab.wrongNodeAttempts += 1;
                if (tab.wrongNodeAttempts <= WRONG_NODE_MAX_ATTEMPTS) {
                    if (tab.wrongNodeAttempts === 1) {
                        this._setTabState(tab, 'connecting', this.i18n.locating);
                        this._writeNotice(tab, this.i18n.locating);
                    }
                    tab.reconnectTimer = setTimeout(
                        () => this._connectTab(tab), WRONG_NODE_RETRY_MS);
                    return;
                }
                // Exhausted: the node that reported it may have gone away.
                // Drop the pin and let the next attempt land anywhere.
                tab.instanceId = '';
                this._setTabState(tab, 'disconnected', this.i18n.reconnect_gave_up);
                this._writeNotice(tab, this.i18n.reconnect_gave_up, '31');
                return;
            }

            // The session no longer exists. Do NOT silently create a
            // replacement - say so and let the user decide.
            if (code === CLOSE_SESSION_GONE) {
                this._setTabState(tab, 'ended', this.i18n.ended);
                this._writeNotice(tab, this.i18n.ended_hint, '33');
                return;
            }

            // Closed for inactivity. tmux is untouched, so this is a pause,
            // not a failure. Deliberately NOT auto-reconnected: doing so
            // would defeat the idle timeout and pin login node resources for
            // every abandoned browser tab.
            if (code === CLOSE_IDLE_TIMEOUT) {
                this._setTabState(tab, 'paused', this.i18n.paused);
                this._writeNotice(tab, this.i18n.paused_hint, '33');
                return;
            }

            if (code === CLOSE_AUTH_FAILED) {
                this._setTabState(tab, 'disconnected', this.i18n.auth_failed);
                this._writeNotice(tab, this.i18n.auth_failed, '31');
                return;
            }

            // Abnormal drop: proxy timeout, network blip, service restart.
            // Retry with backoff, but only for an existing session (attach is
            // idempotent) - never for one we would have to create.
            if (TRANSIENT_CLOSE_CODES.has(code) && tab.origin !== 'new') {
                const delay = RECONNECT_BACKOFF_MS[tab.reconnectAttempts];
                if (delay !== undefined) {
                    tab.reconnectAttempts += 1;
                    this._setTabState(tab, 'connecting', this.i18n.reconnecting);
                    this._writeNotice(tab, this.i18n.reconnecting);
                    tab.reconnectTimer = setTimeout(() => this._connectTab(tab), delay);
                    return;
                }
                this._setTabState(tab, 'disconnected', this.i18n.reconnect_gave_up);
                this._writeNotice(tab, this.i18n.reconnect_gave_up, '31');
                return;
            }

            // Everything else, including a normal 1000 (the user's shell
            // exited). Report it and stop.
            this._setTabState(tab, 'disconnected', this.i18n.disconnected);
            const reason = event.reason
                || (this.i18n.disconnected + ' (code ' + code + ')');
            this._writeNotice(tab, reason, '31');
        }

        _renderEmptyState() {
            if (!this.emptyState) return;
            this.emptyState.style.display = this.tabs.size === 0 ? 'block' : 'none';
        }

        _persist() {
            try {
                sessionStorage.setItem(this.opts.storageKey, JSON.stringify({
                    counter: this.tabCounter,
                    // Objects rather than bare labels so a same-browser-tab
                    // reload keeps the node each session was found on.
                    tabs: Array.from(this.tabs.values()).map(t => ({
                        label: t.label,
                        instanceId: t.instanceId || '',
                    })),
                    active: this.activeLabel,
                }));
            } catch (e) {}
        }

        _loadPersisted() {
            let raw;
            try {
                raw = sessionStorage.getItem(this.opts.storageKey);
            } catch (e) {
                return {};
            }
            if (!raw) return {};
            let parsed;
            try {
                parsed = JSON.parse(raw);
            } catch (e) {
                return {};
            }
            if (!parsed || typeof parsed !== 'object') return {};
            // Normalise to `tabs: [{label, instanceId}]`. Entries written by
            // an earlier build are a bare `labels: ['main-1', ...]` array;
            // read them so an in-flight upgrade does not drop a user's tabs.
            if (!Array.isArray(parsed.tabs)) {
                parsed.tabs = (parsed.labels || [])
                    .filter(l => typeof l === 'string')
                    .map(l => ({ label: l, instanceId: '' }));
            } else {
                parsed.tabs = parsed.tabs
                    .filter(t => t && typeof t.label === 'string')
                    .map(t => ({ label: t.label, instanceId: t.instanceId || '' }));
            }
            return parsed;
        }

        _attr(s) {
            // HTML-attribute-safe version of a translated string.
            return (s || '').replace(/"/g, '&quot;');
        }
    }

    global.WebshellTabManager = WebshellTabManager;
})(window);
