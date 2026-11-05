// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/*
 * EDH form steps: split a jQuery formBuilder form into steps (wizard) with a "Step" component.
 *
 * Builder: a "Step" component (type edhStep) with a title (label) and an optional description.
 * Job form: when the rendered form contains at least one Step, every Step starts a new page
 * and holds the components below it, up to the next Step. Components placed before the
 * first Step form a first "General" page. A form without Step is left untouched (one page).
 *
 * Navigation: Back / Next, a clickable step indicator, Submit only on the last step. Next
 * validates the visible fields of the current step. A step whose components are all hidden
 * by "Show only if" (edh_workflow_form_conditions.js) is skipped.
 *
 * Steps are presentation only: nothing is posted for a Step and the server is unchanged.
 *
 * Usage:
 *   formBuilder: fields: [...EDHFormSteps.fields], templates: Object.assign({}, EDHFormSteps.templates, ...),
 *                typeUserDisabledAttrs: EDHFormSteps.typeUserDisabledAttrs
 *   formRender:  templates: Object.assign({}, EDHFormSteps.templates, ...), then
 *                EDHFormSteps.apply(<form container>) AFTER EDHFormConditions.apply()
 *
 * Load AFTER common/js_i18n.html (labels are resolved when this file runs).
 */
(function (window) {
    "use strict";

    const TYPE = "edhStep";
    const t = (key, fallback) => (window.i18n && window.i18n[key]) || fallback;

    // -- formBuilder / formRender integration --
    // Builder stage: the Step preview already shows its title and description, so hide the
    // generic label / required asterisk / "?" tooltip formBuilder adds above every field.
    if (!document.getElementById("edh-step-builder-css")) {
        const css = document.createElement("style");
        css.id = "edh-step-builder-css";
        css.textContent =
            "li.edhStep-field > .field-label, li.edhStep-field > .required-asterisk," +
            " li.edhStep-field > .tooltip-element { display: none !important; }";
        document.head.appendChild(css);
    }

    const templates = {};
    templates[TYPE] = function (fieldData) {
        // DOM nodes, not an HTML string: formRender sanitizes strings returned by templates.
        const wrapper = document.createElement("div");
        wrapper.className = "edh-step-title";
        wrapper.dataset.edhStep = "1";
        if (fieldData.preview === true) {
            // Builder stage only (formBuilder sets preview=true there): make a Step look like a
            // page break with a "STEP" badge, so it is not mistaken for a Header component.
            wrapper.style.cssText = "border-top: 2px dashed #006ce0; padding-top: .5rem; margin-top: .25rem;";
            const badge = document.createElement("span");
            badge.className = "badge badge-primary bg-primary text-white mb-1";
            badge.textContent = t("fs_step_badge", "STEP") + " - " + t("fs_step_badge_hint", "a new page starts here");
            wrapper.appendChild(badge);
        }
        const title = document.createElement("h4");
        title.className = "mb-1";
        // Labels can contain formBuilder rich text: keep the text only.
        title.textContent = String(fieldData.label || t("fs_step", "Step")).replace(/<[^>]*>/g, "");
        wrapper.appendChild(title);
        if (fieldData.description) {
            const desc = document.createElement("p");
            desc.className = "text-muted mb-2";
            desc.textContent = fieldData.description;
            wrapper.appendChild(desc);
        }
        // noLabel: the step title replaces the usual field label
        return { field: wrapper, layout: "noLabel" };
    };

    // -- Job form runtime --
    function isHidden(wrapper) {
        // Hidden by "Show only if" (style.display) or by formRender (hidden inputs)
        return wrapper.style.display === "none" || wrapper.classList.contains("formbuilder-hidden");
    }

    function apply(container) {
        const rendered = container.querySelector(".rendered-form") || container;
        const children = Array.from(rendered.children);
        if (!children.some((el) => el.querySelector('[data-edh-step="1"]'))) return; // no Step: one page

        // Group the rendered components into steps.
        const steps = [];
        let current = null;
        children.forEach((el) => {
            const titleEl = el.querySelector('[data-edh-step="1"]');
            if (titleEl) {
                current = { title: titleEl.querySelector("h4").textContent, header: el, fields: [] };
                steps.push(current);
            } else {
                if (!current) {
                    current = { title: t("fs_general", "General"), header: null, fields: [] };
                    steps.push(current);
                }
                current.fields.push(el);
            }
        });

        // Wrap each step in its own container (fields stay inside the <form>).
        steps.forEach((step) => {
            step.pane = document.createElement("div");
            step.pane.className = "edh-step-pane";
            rendered.insertBefore(step.pane, step.header || step.fields[0] || null);
            if (step.header) step.pane.appendChild(step.header);
            step.fields.forEach((f) => step.pane.appendChild(f));
        });

        const form = container.closest("form") || container;
        const submitBtn = form.querySelector('button[type="submit"], input[type="submit"]');

        // Indicator (top) and navigation (bottom)
        const indicator = document.createElement("ul");
        indicator.className = "nav nav-pills mb-3 edh-step-indicator";
        rendered.parentNode.insertBefore(indicator, rendered);

        const nav = document.createElement("div");
        nav.className = "d-flex justify-content-between align-items-center mt-3 mb-3 edh-step-nav";
        const backBtn = document.createElement("button");
        backBtn.type = "button";
        backBtn.className = "btn btn-outline-secondary";
        backBtn.textContent = t("fs_back", "Back");
        const counter = document.createElement("small");
        counter.className = "text-muted";
        const nextBtn = document.createElement("button");
        nextBtn.type = "button";
        nextBtn.className = "btn btn-primary";
        nextBtn.textContent = t("fs_next", "Next");
        nav.append(backBtn, counter, nextBtn);
        rendered.parentNode.insertBefore(nav, rendered.nextSibling);

        let index = 0;

        // A step is skipped when all its components are hidden by "Show only if".
        const isActive = (step) => step.fields.length === 0 || step.fields.some((f) => !isHidden(f));
        const activeSteps = () => steps.filter(isActive);

        function controls(step) {
            return Array.from(step.pane.querySelectorAll("input, select, textarea")).filter((el) => !el.disabled);
        }

        // Validate the visible fields of a step; report the first problem.
        function validateStep(step) {
            const invalid = controls(step).find((el) => !el.checkValidity());
            if (!invalid) return true;
            show(steps.indexOf(step));
            invalid.reportValidity();
            return false;
        }

        function render() {
            const active = activeSteps();
            if (!isActive(steps[index])) {
                // Current step became empty (condition changed): move to the closest active one.
                const next = steps.slice(index).find(isActive) || active[active.length - 1];
                index = steps.indexOf(next);
            }
            steps.forEach((step, i) => { step.pane.style.display = i === index ? "" : "none"; });

            const pos = active.indexOf(steps[index]);
            const last = pos === active.length - 1;
            backBtn.disabled = pos <= 0;
            nextBtn.style.display = last ? "none" : "";
            if (submitBtn) submitBtn.style.display = last ? "" : "none";
            counter.textContent = t("fs_step_of", "Step %(current)s of %(total)s")
                .replace("%(current)s", pos + 1)
                .replace("%(total)s", active.length);

            indicator.replaceChildren();
            active.forEach((step, i) => {
                const li = document.createElement("li");
                li.className = "nav-item";
                const a = document.createElement("a");
                a.href = "#";
                a.className = "nav-link" + (step === steps[index] ? " active" : "");
                a.textContent = i + 1 + ". " + step.title;
                a.addEventListener("click", (e) => {
                    e.preventDefault();
                    // Going forward requires the steps in between to be valid.
                    const target = steps.indexOf(step);
                    if (i > pos) {
                        for (const s of active.slice(pos, i)) if (!validateStep(s)) return;
                    }
                    show(target);
                });
                li.appendChild(a);
                indicator.appendChild(li);
            });
        }

        function show(i) {
            index = i;
            render();
            container.scrollIntoView({ block: "start", behavior: "smooth" });
        }

        function move(direction) {
            const active = activeSteps();
            const pos = active.indexOf(steps[index]);
            const target = active[pos + direction];
            if (!target) return;
            if (direction > 0 && !validateStep(steps[index])) return;
            show(steps.indexOf(target));
        }

        backBtn.addEventListener("click", () => move(-1));
        nextBtn.addEventListener("click", () => move(1));

        // Fields of the other steps are hidden, so native validation cannot focus them:
        // validate ourselves. Capture phase + stopImmediatePropagation so the double-submit
        // guard of the page does not mark the form as submitted when we cancel.
        form.noValidate = true;
        form.addEventListener("submit", (e) => {
            const active = activeSteps();
            const last = active.indexOf(steps[index]) === active.length - 1;
            const ok = last && active.every((s) => validateStep(s));
            if (!last && validateStep(steps[index])) move(1);
            if (!ok) {
                e.preventDefault();
                e.stopImmediatePropagation();
            }
        }, true);

        // Conditions may hide / show whole steps: refresh the indicator after they run.
        form.addEventListener("change", () => setTimeout(render, 0));
        form.addEventListener("input", () => setTimeout(render, 0));

        render();
    }

    window.EDHFormSteps = {
        type: TYPE,
        apply: apply,
        fields: [{ label: t("fs_step", "Step"), attrs: { type: TYPE }, icon: "▶" }],
        templates: templates,
        // A Step is a title: hide the input-related attributes in the builder.
        typeUserDisabledAttrs: {
            [TYPE]: ["required", "placeholder", "value", "name", "className", "access"],
        },
        // "Show only if" (typeUserAttrs["*"]) is not supported on a Step: typeUserDisabledAttrs
        // does not cover user attributes, so drop its input when a Step is added.
        typeUserEvents: {
            [TYPE]: {
                onadd: (fld) => {
                    const wrap = fld.querySelector(".showIf-wrap");
                    if (wrap) wrap.remove();
                },
            },
        },
    };
})(window);
