// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/*
 * EDH file picker: a custom jQuery formBuilder / formRender field ("edhFilePicker").
 *
 * Renders a text input + "Browse" button. The button opens a modal that browses the EDH
 * filesystem through /file_explorer/browse (server-side ACLs apply) and writes the selected
 * path(s) into the input, comma-separated when multiple selection is enabled. The input keeps
 * the field `name`, so the value reaches the job script like any other form parameter.
 *
 * Usage:
 *   formBuilder: { fields: EDHFilePicker.fields, templates: EDHFilePicker.templates,
 *                  typeUserAttrs: EDHFilePicker.typeUserAttrs }
 *   formRender:  { templates: EDHFilePicker.templates }
 *
 * Requires jQuery, Bootstrap 5 and window.i18n: load this script AFTER common/js_i18n.html so the
 * builder labels are translated (they are resolved when this file runs).
 */
(function (window, $) {
    "use strict";

    const TYPE = "edhFilePicker";
    const DELIMITER = ","; // must match MULTI_SELECT_DELIMITER in views/submit_job.py
    const PAGE_SIZE = 100; // entries per page in the browse modal (server caps at 500)
    const t = (key, fallback) => (window.i18n && window.i18n[key]) || fallback;

    function isTrue(value) {
        // formRender passes boolean attributes as true, "true" or the attribute name
        // (required -> "required"), depending on where the value comes from.
        return value === true || value === "true" || value === "required";
    }

    // -- Modal (one shared instance, created on first use) --
    let modalEl = null;
    let state = null; // {input, multiple, selectType, selected:Set, current}

    function buildModal() {
        modalEl = document.createElement("div");
        modalEl.className = "modal fade";
        modalEl.id = "edhFilePickerModal";
        modalEl.tabIndex = -1;
        modalEl.setAttribute("aria-hidden", "true");
        modalEl.innerHTML =
            '<div class="modal-dialog modal-lg modal-dialog-scrollable"><div class="modal-content">' +
            '<div class="modal-header"><h5 class="modal-title"></h5>' +
            '<button type="button" class="close" data-bs-dismiss="modal" aria-label="Close">&times;</button></div>' +
            '<div class="modal-body">' +
            '<div class="alert alert-primary py-2 mb-2 small" role="note"><span data-fp="hint"></span></div>' +
            '<div class="d-flex align-items-center mb-2">' +
            '<button type="button" class="btn btn-sm btn-outline-secondary mr-2 me-2" data-fp="home"><i class="fas fa-home"></i></button>' +
            '<button type="button" class="btn btn-sm btn-outline-secondary mr-2 me-2" data-fp="up"><i class="fas fa-level-up-alt"></i></button>' +
            '<code class="text-break" data-fp="path"></code></div>' +
            '<div class="list-group" data-fp="list"></div>' +
            '<div class="d-flex justify-content-between align-items-center mt-2" data-fp="pager">' +
            '<button type="button" class="btn btn-sm btn-outline-secondary" data-fp="prev"><i class="fas fa-chevron-left"></i></button>' +
            '<small class="text-muted" data-fp="page"></small>' +
            '<button type="button" class="btn btn-sm btn-outline-secondary" data-fp="next"><i class="fas fa-chevron-right"></i></button>' +
            "</div></div>" +
            '<div class="modal-footer"><small class="text-muted me-auto mr-auto" data-fp="count"></small>' +
            '<button type="button" class="btn btn-outline-primary" data-fp="use-folder"></button>' +
            '<button type="button" class="btn btn-secondary" data-bs-dismiss="modal" data-fp="cancel"></button>' +
            '<button type="button" class="btn btn-primary" data-fp="use"></button></div>' +
            "</div></div>";
        document.body.appendChild(modalEl);

        modalEl.querySelector(".modal-title").textContent = t("fp_title", "Select file(s)");
        modalEl.querySelector('[data-fp="home"]').title = t("fp_home", "Home");
        modalEl.querySelector('[data-fp="up"]').title = t("fp_up", "Parent folder");
        modalEl.querySelector('[data-fp="use-folder"]').textContent = t("fp_use_this_folder", "Use this folder");
        modalEl.querySelector('[data-fp="cancel"]').textContent = t("fp_cancel", "Cancel");
        modalEl.querySelector('[data-fp="use"]').textContent = t("fp_use_selected", "Use selected");

        modalEl.querySelector('[data-fp="home"]').addEventListener("click", () => load(null));
        modalEl.querySelector('[data-fp="up"]').addEventListener("click", () => {
            if (state.parent) load(state.parent);
        });
        modalEl.querySelector('[data-fp="prev"]').addEventListener("click", () => {
            if (state.page > 1) load(state.current, state.page - 1);
        });
        modalEl.querySelector('[data-fp="next"]').addEventListener("click", () => {
            if (state.page < state.pages) load(state.current, state.page + 1);
        });
        modalEl.querySelector('[data-fp="use-folder"]').addEventListener("click", () => commit([state.current]));
        modalEl.querySelector('[data-fp="use"]').addEventListener("click", () => commit(Array.from(state.selected)));
    }

    function modal() {
        if (!modalEl) buildModal();
        return window.bootstrap.Modal.getOrCreateInstance(modalEl);
    }

    function commit(paths) {
        if (!paths.length || !paths[0]) return;
        state.input.value = paths.join(DELIMITER);
        // Let formRender listeners (e.g. cost estimate on form change) react.
        $(state.input).trigger("input").trigger("change");
        modal().hide();
    }

    function canSelect(type) {
        return state.selectType === "both" || state.selectType === type;
    }

    function updateFooter() {
        modalEl.querySelector('[data-fp="count"]').textContent =
            state.selected.size ? state.selected.size + " " + t("fp_selected", "selected") : "";
        modalEl.querySelector('[data-fp="use"]').disabled = state.selected.size === 0;
        modalEl.querySelector('[data-fp="use-folder"]').style.display =
            canSelect("folder") && state.current ? "" : "none";
        modalEl.querySelector('[data-fp="up"]').disabled = !state.parent;
    }

    function renderEntries(entries) {
        const list = modalEl.querySelector('[data-fp="list"]');
        list.replaceChildren();
        if (!entries.length) {
            const empty = document.createElement("div");
            empty.className = "text-muted p-2";
            empty.textContent = t("fp_empty", "This folder is empty");
            list.appendChild(empty);
            return;
        }
        entries.forEach((entry) => {
            const row = document.createElement("div");
            row.className = "list-group-item d-flex align-items-center";

            // Fixed-width checkbox column on every row (empty when the entry is not selectable),
            // so checkboxes, icons and names line up across files and folders.
            const cell = document.createElement("span");
            cell.style.cssText = "display:inline-flex;align-items:center;justify-content:center;width:1.5rem;margin:0 0.5rem 0 0.25rem;flex-shrink:0";
            row.appendChild(cell);

            if (canSelect(entry.type)) {
                const box = document.createElement("input");
                box.type = state.multiple ? "checkbox" : "radio";
                box.name = "edh-fp-choice";
                box.className = "form-check-input";
                // Inline so it applies whatever Bootstrap version styles .form-check-input
                // (Bootstrap 4 makes it position:absolute, which overlaps the file name).
                box.style.cssText = "position:static;margin:0";
                box.checked = state.selected.has(entry.path);
                box.addEventListener("change", () => {
                    if (!state.multiple) state.selected.clear();
                    if (box.checked) state.selected.add(entry.path);
                    else state.selected.delete(entry.path);
                    updateFooter();
                });
                cell.appendChild(box);
            }

            const icon = document.createElement("i");
            // fa-fw: fixed-width icons so file and folder names start at the same position.
            icon.className = (entry.type === "folder" ? "fas fa-folder text-warning" : "far fa-file text-secondary") + " fa-fw mr-2 me-2";
            row.appendChild(icon);

            const name = document.createElement(entry.type === "folder" ? "a" : "span");
            name.textContent = entry.name; // textContent: filenames are user-controlled
            if (entry.type === "folder") {
                name.href = "#";
                name.addEventListener("click", (e) => {
                    e.preventDefault();
                    load(entry.path);
                });
            }
            row.appendChild(name);
            list.appendChild(row);
        });
    }

    function updatePager() {
        // Hidden when everything fits on one page.
        modalEl.querySelector('[data-fp="pager"]').style.cssText =
            state.pages > 1 ? "" : "display:none !important";
        const pageOf = t("page_of_template", "Page %(current)s of %(total)s")
            .replace("%(current)s", state.page)
            .replace("%(total)s", state.pages);
        modalEl.querySelector('[data-fp="page"]').textContent = pageOf + " (" + state.total + ")";
        modalEl.querySelector('[data-fp="prev"]').disabled = state.page <= 1;
        modalEl.querySelector('[data-fp="next"]').disabled = state.page >= state.pages;
    }

    function load(path, page) {
        const list = modalEl.querySelector('[data-fp="list"]');
        list.replaceChildren();
        const loading = document.createElement("div");
        loading.className = "text-muted p-2";
        loading.textContent = t("fp_loading", "Loading ...");
        list.appendChild(loading);

        const params = { page: page || 1, page_size: PAGE_SIZE };
        if (path) params.path = path;
        $.getJSON("/file_explorer/browse", params)
            .done((data) => {
                const listing = data.message || {};
                state.current = listing.path;
                state.parent = listing.parent;
                state.page = listing.page || 1;
                state.pages = listing.pages || 1;
                state.total = listing.total || 0;
                modalEl.querySelector('[data-fp="path"]').textContent = listing.path || "";
                renderEntries(listing.entries || []);
                updatePager();
                updateFooter();
            })
            .fail((xhr) => {
                const msg = (xhr.responseJSON && xhr.responseJSON.message) || t("fp_error", "Unable to list this folder");
                loading.className = "alert alert-danger m-0";
                loading.textContent = msg;
                // Stay usable after a refused path: allow going back home.
                state.parent = state.parent || null;
                state.pages = 1;
                updatePager();
                updateFooter();
            });
    }

    function open(input, options) {
        modal();
        const current = (input.value || "").split(DELIMITER).map((p) => p.trim()).filter(Boolean);
        state = {
            input: input,
            multiple: options.multiple,
            selectType: options.selectType,
            selected: new Set(options.multiple ? current : current.slice(0, 1)),
            current: null,
            parent: null,
            page: 1,
            pages: 1,
            total: 0,
        };
        updatePager();
        // Tell the user what this field accepts: files / folders / both, single or multiple.
        const kinds = {
            file: t("fp_attr_files", "Files"),
            folder: t("fp_attr_folders", "Folders"),
            both: t("fp_attr_both", "Files and folders"),
        };
        modalEl.querySelector('[data-fp="hint"]').textContent =
            t("fp_allowed", "You can select:") + " " +
            (kinds[state.selectType] || kinds.file) + " (" +
            (state.multiple ? t("fp_multiple", "multiple selection") : t("fp_single", "single selection")) + ")";
        updateFooter();
        modal().show();
        load(options.startPath || null);
    }

    // -- formBuilder / formRender integration --
    const templates = {};
    templates[TYPE] = function (fieldData) {
        // Build real DOM nodes: formRender sanitizes HTML strings returned by custom templates
        // and strips <input>/<button>, which left an empty <div>.
        const name = fieldData.name || "";
        const wrapper = document.createElement("div");
        wrapper.className = "input-group";
        // formRender injects Bootstrap 3 CSS (.input-group = table, .form-control = float/100%),
        // which pushes the button onto its own line. Inline flex wins over those rules.
        wrapper.style.cssText = "display:flex;flex-wrap:nowrap;align-items:stretch;width:100%";

        const input = document.createElement("input");
        input.type = "text";
        input.className = "form-control";
        input.style.cssText = "flex:1 1 auto;width:auto;min-width:0;float:none;height:auto;border-top-left-radius:0;border-bottom-left-radius:0";
        input.autocomplete = "off";
        input.id = fieldData.id || name;
        input.name = name;
        input.value = fieldData.value || "";
        if (fieldData.placeholder) input.placeholder = fieldData.placeholder;
        if (isTrue(fieldData.required)) input.required = true;

        const btn = document.createElement("button");
        btn.type = "button";
        btn.className = "btn btn-outline-secondary";
        btn.style.cssText = "flex:0 0 auto;white-space:nowrap;border-top-right-radius:0;border-bottom-right-radius:0";
        const icon = document.createElement("i");
        icon.className = "fas fa-folder-open";
        btn.append(icon, " " + t("fp_browse", "Browse"));
        btn.addEventListener("click", () =>
            open(input, {
                multiple: isTrue(fieldData.allowMultiple),
                selectType: fieldData.selectType || "file",
                startPath: (fieldData.startPath || "").trim(),
            })
        );

        wrapper.append(btn, input);
        return { field: wrapper };
    };

    const typeUserAttrs = {};
    typeUserAttrs[TYPE] = {
        allowMultiple: { label: t("fp_attr_multiple", "Allow multiple selection"), type: "checkbox" },
        selectType: {
            label: t("fp_attr_select", "Selectable items"),
            options: {
                file: t("fp_attr_files", "Files"),
                folder: t("fp_attr_folders", "Folders"),
                both: t("fp_attr_both", "Files and folders"),
            },
        },
        startPath: { label: t("fp_attr_start", "Start directory (default: user home)"), value: "" },
    };

    window.EDHFilePicker = {
        type: TYPE,
        fields: [{ label: t("fp_field_label", "File picker"), attrs: { type: TYPE }, icon: "📁" }],
        templates: templates,
        typeUserAttrs: typeUserAttrs,
    };
})(window, jQuery);
