/*
 * EDH resumable download manager (Slice 2).
 * Client-driven, ranged, resumable download straight to disk via the
 * File System Access API (Chromium). Degrades to the native browser
 * download when the API is unavailable. No external dependencies.
 *
 * Wiring: intercepts clicks on <a href="/file_explorer/download?uid=...">.
 *   - single uid  -> showSaveFilePicker(), ranged fetch -> file on disk
 *   - comma uids  -> showDirectoryPicker(), each file fetched into the dir
 * File names/sizes come from window.EDH_FILES (emitted by the template);
 * download_all (path-based) is left to the native server path.
 */
(function () {
    "use strict";

    var CHUNK = 16 * 1024 * 1024;   // 16 MB range slices
    var MAX_RETRY = 5;              // per-chunk network retries
    var PARALLEL = 4;               // concurrent range fetches per single-file download
    var _seq = 0;
    var _zipModPromise = null;      // memoized client-zip module

    function _fsaSingleSupported() {
        return typeof window.showSaveFilePicker === "function";
    }
    function _fsaDirSupported() {
        return typeof window.showDirectoryPicker === "function";
    }

    // --- progress panel (self-contained, BS4-safe inline positioning) ---
    function _panel() {
        var _p = document.getElementById("edh-dl-panel");
        if (_p) return _p;
        _p = document.createElement("div");
        _p.id = "edh-dl-panel";
        _p.setAttribute(
            "style",
            "position:fixed; bottom:1rem; right:1rem; z-index:1300; width:360px; " +
            "max-height:60vh; overflow-y:auto; font-size:0.85rem;"
        );
        document.body.appendChild(_p);
        return _p;
    }

    function _row(_title) {
        var _id = "edh-dl-row-" + (++_seq);
        var _el = document.createElement("div");
        _el.id = _id;
        _el.setAttribute(
            "style",
            "background:#fff; color:#212529; border:1px solid #dee2e6; border-radius:6px; " +
            "box-shadow:0 2px 6px rgba(0,0,0,0.15); padding:8px 10px; margin-top:8px;"
        );
        _el.innerHTML =
            '<div style="display:flex; justify-content:space-between; align-items:center;">' +
            '  <strong style="overflow:hidden; text-overflow:ellipsis; white-space:nowrap; max-width:250px;"></strong>' +
            '  <a href="#" class="edh-dl-x" style="color:#6c757d; text-decoration:none; margin-left:8px;">&times;</a>' +
            '</div>' +
            '<div style="background:#e9ecef; border-radius:4px; height:8px; margin-top:6px; overflow:hidden;">' +
            '  <div class="edh-dl-bar" style="background:#0087F7; height:8px; width:0%;"></div>' +
            '</div>' +
            '<div class="edh-dl-stat" style="color:#6c757d; margin-top:4px;"></div>';
        _el.querySelector("strong").textContent = _title;
        _panel().appendChild(_el);
        return {
            id: _id,
            el: _el,
            bar: _el.querySelector(".edh-dl-bar"),
            stat: _el.querySelector(".edh-dl-stat"),
            close: _el.querySelector(".edh-dl-x"),
        };
    }

    function _human(_n) {
        if (!_n) return "0 B";
        var _u = ["B", "KB", "MB", "GB", "TB"], _i = Math.floor(Math.log(_n) / Math.log(1024));
        return (_n / Math.pow(1024, _i)).toFixed(1) + " " + _u[_i];
    }

    // Fade out + remove a completed row after a short delay. Failures are left
    // in place (caller skips this) so the user can see what went wrong.
    function _autoDismiss(_ui, _ms) {
        setTimeout(function () {
            _ui.el.style.transition = "opacity 0.5s";
            _ui.el.style.opacity = "0";
            setTimeout(function () { _ui.el.remove(); }, 500);
        }, _ms || 6000);
    }

    // --- ranged fetch with retry/resume ---
    async function _fetchRange(_url, _start, _end, _signal) {
        var _attempt = 0;
        while (true) {
            try {
                var _resp = await fetch(_url, {
                    headers: { "Range": "bytes=" + _start + "-" + _end },
                    signal: _signal,
                    credentials: "same-origin",
                });
                if (_resp.status !== 206 && _resp.status !== 200) {
                    throw new Error("HTTP " + _resp.status);
                }
                // Server/proxy ignored Range: a 200 full-body at a non-zero offset would corrupt the parallel write
                if (_resp.status === 200 && _start !== 0) {
                    throw new Error("Server does not support range requests");
                }
                return _resp;
            } catch (_err) {
                if (_signal && _signal.aborted) throw _err;
                if (++_attempt > MAX_RETRY) throw _err;
                await new Promise(function (r) { setTimeout(r, 500 * _attempt); });
            }
        }
    }

    // Parallel ranged fetch: N workers pull CHUNK-sized ranges from a shared
    // cursor and write each at its byte offset (File System Access positional
    // write), so one file downloads over N concurrent connections.
    async function _streamParallel(_url, _size, _writable, _ui, _ctrl, _parallel) {
        var _next = 0;   // next unassigned byte offset (single-threaded => no race)
        var _done = 0;   // bytes completed, for progress
        async function _worker() {
            try {
                while (true) {
                    if (_ctrl.signal.aborted) throw new DOMException("aborted", "AbortError");
                    var _start = _next;
                    if (_start >= _size) return;
                    var _end = Math.min(_start + CHUNK, _size) - 1;
                    _next = _end + 1;
                    var _resp = await _fetchRange(_url, _start, _end, _ctrl.signal);
                    var _buf = await _resp.arrayBuffer();
                    if (_buf.byteLength === 0) return;
                    await _writable.write({ type: "write", position: _start, data: _buf });
                    _done += _buf.byteLength;
                    var _pct = Math.floor((_done / _size) * 100);
                    _ui.bar.style.width = _pct + "%";
                    _ui.stat.textContent = _human(_done) + " / " + _human(_size) + "  (" + _pct + "%)";
                }
            } catch (_err) {
                _ctrl.abort(); // stop sibling workers before the caller closes the writable
                throw _err;
            }
        }
        var _n = Math.max(1, Math.min(_parallel, Math.ceil(_size / CHUNK)));
        var _pool = [];
        for (var _w = 0; _w < _n; _w++) _pool.push(_worker());
        await Promise.all(_pool);
    }

    async function _downloadSingle(_url, _name, _size) {
        var _handle;
        try {
            _handle = await window.showSaveFilePicker({ suggestedName: _name, startIn: "downloads" });
        } catch (_err) {
            if (_err && _err.name === "AbortError") return; // user cancelled
            var _u = _row(_name);
            _u.bar.style.background = "#dc3545";
            _u.stat.textContent = "Couldn't use that location — choose a regular folder like Downloads.";
            return;
        }
        var _writable = await _handle.createWritable();
        var _ui = _row(_name);
        var _ctrl = new AbortController();
        _ui.close.addEventListener("click", function (e) { e.preventDefault(); _ctrl.abort(); });
        try {
            await _streamParallel(_url, _size, _writable, _ui, _ctrl, PARALLEL);
            await _writable.close();
            _ui.bar.style.background = "#28a745";
            _ui.stat.textContent = "Done — " + _human(_size);
            _autoDismiss(_ui);
        } catch (_err) {
            try { await _writable.abort(); } catch (e) {}
            _ui.bar.style.background = "#dc3545";
            _ui.stat.textContent = _ctrl.signal.aborted ? "Cancelled" : ("Failed: " + _err.message);
        }
    }

    // Load the vendored client-zip ESM via a blob URL so the module MIME type
    // is guaranteed correct regardless of how uwsgi serves static .js.
    function _loadZip() {
        if (_zipModPromise) return _zipModPromise;
        _zipModPromise = (async function () {
            var _src = await (await fetch("/static/js/vendor/client-zip.js", { credentials: "same-origin" })).text();
            var _url = URL.createObjectURL(new Blob([_src], { type: "text/javascript" }));
            try { return await import(_url); }
            finally { URL.revokeObjectURL(_url); }
        })();
        return _zipModPromise;
    }

    // Multi-select: stream all selected files into ONE .zip saved via
    // showSaveFilePicker. showDirectoryPicker is avoided because Chrome
    // blocklists directory access to Downloads/Desktop/Documents/home.
    async function _downloadMany(_entries) {
        var _handle;
        try {
            _handle = await window.showSaveFilePicker({ suggestedName: "edh-download.zip", startIn: "downloads" });
        } catch (_err) {
            if (_err && _err.name === "AbortError") return; // user cancelled
            var _u = _row("Download");
            _u.bar.style.background = "#dc3545";
            _u.stat.textContent = "Couldn't use that location — choose a regular folder like Downloads.";
            return;
        }
        var _writable = await _handle.createWritable();
        var _ui = _row(_entries.length + " files \u2192 zip");
        var _ctrl = new AbortController();
        _ui.close.addEventListener("click", function (e) { e.preventDefault(); _ctrl.abort(); });
        var _total = _entries.reduce(function (a, e) { return a + (e.size || 0); }, 0);
        var _seen = 0;
        try {
            var _mod = await _loadZip();
            async function* _gen() {
                for (var _k = 0; _k < _entries.length; _k++) {
                    var _e = _entries[_k];
                    _ui.stat.textContent = "Adding " + (_k + 1) + "/" + _entries.length + ": " + _e.name;
                    var _resp = await fetch(_e.url, { signal: _ctrl.signal, credentials: "same-origin" });
                    yield { name: _e.name, input: _resp, size: _e.size };
                }
            }
            var _counter = new TransformStream({
                transform: function (_chunk, _c) {
                    _seen += _chunk.byteLength;
                    var _p = _total ? Math.min(99, Math.floor((_seen / _total) * 100)) : 0;
                    _ui.bar.style.width = _p + "%";
                    _c.enqueue(_chunk);
                },
            });
            await _mod.downloadZip(_gen()).body.pipeThrough(_counter).pipeTo(_writable);
            _ui.bar.style.width = "100%";
            _ui.bar.style.background = "#28a745";
            _ui.stat.textContent = "Done \u2014 " + _entries.length + " files (" + _human(_seen) + ")";
            _autoDismiss(_ui);
        } catch (_err) {
            try { await _writable.abort(); } catch (e) {}
            _ui.bar.style.background = "#dc3545";
            _ui.stat.textContent = _ctrl.signal.aborted ? "Cancelled" : ("Failed: " + _err.message);
        }
    }

    function _uidsFromHref(_href) {
        var _m = /[?&]uid=([^&]+)/.exec(_href);
        if (!_m) return [];
        return decodeURIComponent(_m[1]).split(",").filter(Boolean);
    }

    function _lookup(_uid) {
        return (window.EDH_FILES && window.EDH_FILES[_uid]) || null;
    }

    function _onClick(_evt) {
        var _a = _evt.target.closest && _evt.target.closest('a[href*="/file_explorer/download?uid="]');
        if (!_a) return;

        var _uids = _uidsFromHref(_a.getAttribute("href"));
        if (_uids.length === 0) return;

        // Single file: needs showSaveFilePicker; else let the native anchor run.
        if (_uids.length === 1) {
            if (!_fsaSingleSupported()) return; // graceful fallback (native download)
            var _info = _lookup(_uids[0]);
            if (!_info) return;
            _evt.preventDefault();
            _downloadSingle(_a.href, _info.name, _info.size);
            return;
        }

        // Multiple files: streamed into one zip via showSaveFilePicker; else
        // let the native server-zip path run.
        if (!_fsaSingleSupported()) return;
        var _entries = [];
        for (var _i = 0; _i < _uids.length; _i++) {
            var _fi = _lookup(_uids[_i]);
            if (!_fi) return; // incomplete map -> fall back to native
            _entries.push({
                url: "/file_explorer/download?uid=" + encodeURIComponent(_uids[_i]),
                name: _fi.name,
                size: _fi.size,
            });
        }
        _evt.preventDefault();
        _downloadMany(_entries);
    }

    document.addEventListener("click", _onClick, true);
})();
