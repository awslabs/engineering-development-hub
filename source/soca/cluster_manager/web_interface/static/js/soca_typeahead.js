/* SOCA/EDH shared typeahead widget.
 * Drives bounded user/group pickers off /api/ldap/users?q= and
 * /api/ldap/groups?q= so pages never render the full directory.
 *
 * Markup contract (any element with class "soca-typeahead"):
 *   data-endpoint     (required)  e.g. "/api/ldap/users"
 *   data-results      (required)  id of an adjacent results container
 *   data-sink         (optional)  id of element to receive the chosen value;
 *                                 if omitted, the input itself holds the value
 *                                 (used by the project "Add" buttons that read
 *                                  the input .value directly)
 *   data-value-field  (default "username")  field used as the submitted value
 *   data-label-field  (default "display_name")  field shown in the dropdown
 *   data-require       (optional "true")  block form submit until a pick is made
 *                                         (only meaningful with a separate sink)
 */
(function () {
    if (window.__socaTypeaheadLoaded) { return; }
    window.__socaTypeaheadLoaded = true;
    var css =
        ".soca-th-results,.soca-user-results{position:absolute;z-index:1050;width:100%;max-height:260px;overflow-y:auto;display:none;}" +
        ".soca-th-results .list-group-item,.soca-user-results .list-group-item{cursor:pointer;text-align:left;}" +
        // UseBootstrapTag copies the input's .form-control onto its chip box,
        // whose fixed height clips wrapped chip rows. Let it grow, keep an
        // input-height baseline, and allow vertical padding for multiple rows.
        ".use-bootstrap-tag{height:auto !important;min-height:calc(1.5em + 0.75rem + 2px);padding-top:0.25rem;padding-bottom:0.25rem;}";
    var st = document.createElement("style");
    st.textContent = css;
    document.head.appendChild(st);

    function debounce(fn, ms) {
        var t;
        return function () {
            var ctx = this, args = arguments;
            clearTimeout(t);
            t = setTimeout(function () { fn.apply(ctx, args); }, ms);
        };
    }

    // The theme's .card has overflow:hidden (for rounded corners), which clips
    // a dropdown that extends past a short card. Let the enclosing card overflow
    // so the suggestion list isn't trimmed to the card border.
    function unclipCard(el) {
        var card = el && el.closest ? el.closest(".card") : null;
        if (card) { card.style.overflow = "visible"; }
    }

    function init(input) {
        var endpoint = input.getAttribute("data-endpoint");
        var resultsId = input.getAttribute("data-results");
        var results = resultsId ? document.getElementById(resultsId) : null;
        if (!endpoint || !results) { return; }
        unclipCard(input);
        var sinkId = input.getAttribute("data-sink") || input.getAttribute("data-hidden");
        var sink = sinkId ? document.getElementById(sinkId) : input;
        var valueField = input.getAttribute("data-value-field") || "username";
        var labelField = input.getAttribute("data-label-field") || "display_name";
        var separate = sink && sink !== input;

        function clearBox() { results.innerHTML = ""; results.style.display = "none"; }

        function showSpinner() {
            results.innerHTML = '<span class="list-group-item text-muted"><span class="spinner-border spinner-border-sm me-2" role="status"></span>Searching...</span>';
            results.style.display = "block";
        }

        function render(items) {
            results.innerHTML = "";
            if (!items || !items.length) {
                var empty = document.createElement("span");
                empty.className = "list-group-item text-muted";
                empty.textContent = "No results found";
                results.appendChild(empty);
                results.style.display = "block";
                return;
            }
            items.forEach(function (it) {
                var val = it[valueField];
                if (val === undefined || val === null || val === "") { return; }
                var label = it[labelField] || val;
                if (label !== val) { label = label + " (" + val + ")"; }
                var b = document.createElement("button");
                b.type = "button";
                b.className = "list-group-item list-group-item-action";
                b.textContent = label; // textContent: no HTML injection from directory values
                b.addEventListener("click", function () {
                    if (separate) { sink.value = val; input.value = label; }
                    else { input.value = val; }
                    input.classList.remove("is-invalid");
                    clearBox();
                });
                results.appendChild(b);
            });
            results.style.display = "block";
        }

        var run = debounce(function () {
            if (separate) { sink.value = ""; }
            var q = input.value.trim();
            if (q.length < 2) { clearBox(); return; }
            showSpinner();
            var url = endpoint + (endpoint.indexOf("?") > -1 ? "&" : "?") +
                "q=" + encodeURIComponent(q) + "&max_results=50";
            fetch(url, { headers: { "Accept": "application/json" } })
                .then(function (r) { return r.json(); })
                .then(function (d) {
                    if (d && d.success && Array.isArray(d.message)) { render(d.message); }
                    else { clearBox(); }
                })
                .catch(function () { clearBox(); });
        }, 250);

        input.addEventListener("input", run);
        document.addEventListener("click", function (e) {
            if (e.target !== input && !results.contains(e.target)) { clearBox(); }
        });
    }

    // Tag-search mode: turn a comma-string <input> into a chip box (via
    // UseBootstrapTag) with an inline typeahead dropdown anchored to the chip
    // box's own text input. Typing searches the directory; picking a result
    // drops a chip in place. One widget for allow/deny user/group lists.
    //   data-endpoint     (required)  e.g. "/api/ldap/users"
    //   data-value-field  (default "username")
    //   data-label-field  (default "display_name")
    //   data-allow-star   ("true")  enforce '*' as an exclusive token
    // Backend contract (comma-separated value on the target input) is unchanged.
    function initTagSearch(target) {
        if (typeof UseBootstrapTag !== "function") { return; }
        var endpoint = target.getAttribute("data-endpoint");
        if (!endpoint) { return; }
        var valueField = target.getAttribute("data-value-field") || "username";
        var labelField = target.getAttribute("data-label-field") || "display_name";
        var allowStar = target.getAttribute("data-allow-star") === "true";

        var inst = UseBootstrapTag(target);
        target._ubTagInstance = inst;
        var root = target.nextElementSibling; // the .use-bootstrap-tag chip box
        if (!root || !root.classList.contains("use-bootstrap-tag")) { return; }
        var typeInput = root.querySelector("input");
        if (!typeInput) { return; }

        // Anchor a results dropdown directly under the chip box.
        var holder = document.createElement("div");
        holder.style.position = "relative";
        root.parentNode.insertBefore(holder, root);
        holder.appendChild(root);
        var results = document.createElement("div");
        results.className = "list-group soca-th-results";
        holder.appendChild(results);
        unclipCard(target);

        var current = [];      // rendered suggestions: [{ val, btn }]
        var activeIndex = -1;  // keyboard-highlighted row, -1 = none

        function clearBox() {
            results.innerHTML = "";
            results.style.display = "none";
            current = [];
            activeIndex = -1;
        }

        function showSpinner() {
            results.innerHTML = '<span class="list-group-item text-muted"><span class="spinner-border spinner-border-sm me-2" role="status"></span> Searching...</span>';
            results.style.display = "block";
            current = [];
            activeIndex = -1;
        }

        function addVal(v) {
            if (allowStar) {
                if (v === "*") {
                    var others = inst.getValues().filter(function (x) { return x !== "*"; });
                    if (others.length) { inst.removeValue(others); }
                } else if (inst.getValues().indexOf("*") > -1) {
                    inst.removeValue("*");
                }
            }
            inst.addValue(v);
        }

        // Commit suggestion at index i, then clear + refocus for the next entry.
        function choose(i) {
            if (i < 0 || i >= current.length) { return; }
            addVal(current[i].val);
            typeInput.value = "";
            typeInput.dispatchEvent(new Event("input")); // reset lib's internal text state
            clearBox();
            typeInput.focus();
        }

        // Move the keyboard highlight (clamped) and scroll it into view.
        function setActive(i) {
            if (!current.length) { return; }
            if (i < 0) { i = 0; }
            if (i > current.length - 1) { i = current.length - 1; }
            current.forEach(function (it, idx) { it.btn.classList.toggle("active", idx === i); });
            activeIndex = i;
            current[i].btn.scrollIntoView({ block: "nearest" });
        }

        function render(items) {
            results.innerHTML = "";
            current = [];
            activeIndex = -1;
            var existing = inst.getValues();
            (items || []).forEach(function (it) {
                var val = it[valueField];
                if (val === undefined || val === null || val === "") { return; }
                if (existing.indexOf(val) > -1) { return; } // already a chip
                var label = it[labelField] || val;
                if (label !== val) { label = label + " (" + val + ")"; }
                var b = document.createElement("button");
                b.type = "button";
                b.className = "list-group-item list-group-item-action";
                b.textContent = label; // textContent: no HTML injection from directory values
                var myIdx = current.length;
                // Keep the chip-box input focused on click: otherwise the input
                // blurs first and UseBootstrapTag commits the typed text as a
                // stray chip alongside the picked value.
                b.addEventListener("mousedown", function (e) { e.preventDefault(); });
                b.addEventListener("mouseenter", function () { setActive(myIdx); });
                b.addEventListener("click", function () { choose(myIdx); });
                results.appendChild(b);
                current.push({ val: val, btn: b });
            });
            if (!current.length) {
                var empty = document.createElement("span");
                empty.className = "list-group-item text-muted";
                empty.textContent = "No results found";
                results.appendChild(empty);
                results.style.display = "block";
            } else {
                results.style.display = "block";
            }
        }

        var run = debounce(function () {
            var q = typeInput.value.trim();
            if (q.length < 2) { clearBox(); return; }
            showSpinner();
            var url = endpoint + (endpoint.indexOf("?") > -1 ? "&" : "?") +
                "q=" + encodeURIComponent(q) + "&max_results=50";
            fetch(url, { headers: { "Accept": "application/json" } })
                .then(function (r) { return r.json(); })
                .then(function (d) {
                    if (d && d.success && Array.isArray(d.message)) { render(d.message); }
                    else { clearBox(); }
                })
                .catch(function () { clearBox(); });
        }, 250);

        typeInput.addEventListener("input", run);
        document.addEventListener("click", function (e) {
            if (e.target !== typeInput && !results.contains(e.target)) { clearBox(); }
        });

        // Keyboard navigation. UseBootstrapTag owns typeInput.onkeydown (its
        // Enter commits the typed text); wrap it so that when the dropdown is
        // open with a highlighted row, Arrow/Enter/Tab/Escape drive the list,
        // and everything else falls through to the library (Backspace removes
        // last chip; Enter on typed text with no highlight still commits it).
        var libKeydown = typeInput.onkeydown;
        typeInput.onkeydown = function (e) {
            var open = results.style.display !== "none" && current.length > 0;
            if (open) {
                if (e.key === "ArrowDown") { setActive(activeIndex + 1); e.preventDefault(); return; }
                if (e.key === "ArrowUp") { setActive(activeIndex === -1 ? current.length - 1 : activeIndex - 1); e.preventDefault(); return; }
                if (e.key === "Escape") { clearBox(); e.preventDefault(); return; }
                if ((e.key === "Enter" || e.key === "Tab") && activeIndex >= 0) { choose(activeIndex); e.preventDefault(); return; }
            }
            if (libKeydown) { return libKeydown.call(typeInput, e); }
        };

        // Enforce '*' exclusivity for values added by typing (Enter/comma/blur),
        // matching the legacy Add-button behavior. Dropdown picks go via addVal.
        if (allowStar) {
            var prev = inst.getValues().slice();
            var guard = false;
            target.addEventListener("change", function () {
                if (guard) { return; }
                var cur = inst.getValues();
                var added = cur.filter(function (v) { return prev.indexOf(v) === -1; });
                guard = true;
                if (added.indexOf("*") > -1) {
                    var others = cur.filter(function (v) { return v !== "*"; });
                    if (others.length) { inst.removeValue(others); }
                } else if (added.length && cur.indexOf("*") > -1) {
                    inst.removeValue("*");
                }
                guard = false;
                prev = inst.getValues().slice();
            });
        }
    }

    function boot() {
        document.querySelectorAll(".soca-typeahead").forEach(init);
        document.querySelectorAll(".soca-tagsearch").forEach(initTagSearch);
        document.querySelectorAll("form").forEach(function (f) {
            var requireds = f.querySelectorAll('.soca-typeahead[data-require="true"]');
            if (!requireds.length) { return; }
            f.addEventListener("submit", function (e) {
                for (var i = 0; i < requireds.length; i++) {
                    var ta = requireds[i];
                    var sinkId = ta.getAttribute("data-sink") || ta.getAttribute("data-hidden");
                    var sink = sinkId ? document.getElementById(sinkId) : null;
                    if (sink && !sink.value) {
                        e.preventDefault();
                        ta.classList.add("is-invalid");
                        ta.focus();
                        return;
                    }
                }
            });
        });
    }

    if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", boot);
    } else {
        boot();
    }
})();
