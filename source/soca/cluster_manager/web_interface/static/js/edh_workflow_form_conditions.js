// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/*
 * EDH form conditions: show a jQuery formBuilder field only when other fields match.
 *
 * Adds a "Show only if" attribute (showIf) to every formBuilder field type. A condition is one
 * or more terms combined with && (AND) and || (OR). && binds tighter than ||, there are no
 * parentheses:  a && b || c  means  (a AND b) OR c.
 *
 * Terms:
 *   other_field            visible when other_field is checked / has a non-empty value
 *   !other_field           visible when other_field is empty / nothing checked
 *   other_field=a          visible when other_field equals a (select, radio, or that
 *                          checkbox option is checked); other_field=a|b matches a OR b
 *   other_field!=a         visible when other_field does not equal a (nor b with a|b)
 *   other_field>N  >=N  <N  <=N
 *                          numeric comparison; false when the value is not a number
 * Example:  solver=fluent && vcpus>=16 || queue_name=high
 *
 * Hidden fields are disabled: they skip browser validation (even when required) and are not
 * submitted. The same rules are re-evaluated server side in views/submit_job.py
 * (_is_field_visible) so a hidden field always reaches the job script empty.
 *
 * Usage:
 *   formBuilder: { typeUserAttrs: Object.assign({}, EDHFormConditions.typeUserAttrs, ...) }
 *   formRender:  EDHFormConditions.apply(<form container>, <formData array>) after render
 *
 * Load AFTER common/js_i18n.html (labels are resolved when this file runs).
 */
(function (window) {
    "use strict";

    const ATTR = "showIf";
    const t = (key, fallback) => (window.i18n && window.i18n[key]) || fallback;

    // Grammar (keep in sync with _parse_condition / _parse_expression in views/submit_job.py):
    //   expression := and_group ( "||" and_group )*
    //   and_group  := term ( "&&" term )*
    //   term       := field | !field | field=a|b | field!=a|b | field>N | >=N | <N | <=N
    const TERM_RE = /^([^!=<>\s]+)\s*(>=|<=|!=|=|>|<)\s*(.*)$/;

    function parseTerm(term) {
        const cond = String(term || "").trim();
        if (!cond) return { invalid: true, field: "", op: "invalid" }; // e.g. "a &&" or "|| b"
        if (cond.startsWith("!") && !/[=<>]/.test(cond)) {
            return { field: cond.slice(1).trim(), op: "empty", value: null };
        }
        const m = cond.match(TERM_RE);
        if (m) {
            const value = m[3].trim();
            // = and != accept several alternatives separated by a single |
            const values = m[2] === "=" || m[2] === "!=" ? value.split("|").map((v) => v.trim()) : null;
            return { field: m[1], op: m[2], value: value, values: values };
        }
        return { field: cond, op: "set", value: null };
    }

    // Returns a list of OR groups, each a list of AND terms, or null when there is no condition.
    function parse(condition) {
        const cond = String(condition || "").trim();
        if (!cond) return null;
        return cond.split("||").map((group) => group.split("&&").map(parseTerm));
    }

    function terms(expression) {
        return (expression || []).flat();
    }

    function toNumber(value) {
        const n = Number(String(value).trim());
        return String(value).trim() !== "" && Number.isFinite(n) ? n : null;
    }

    // Current values of a field: checked checkbox/radio values, selected options, or the
    // trimmed text value. Disabled (= hidden) inputs count as empty, so conditions chain.
    function values(form, name) {
        const out = [];
        const selector = '[name="' + CSS.escape(name) + '"], [name="' + CSS.escape(name + "[]") + '"]';
        form.querySelectorAll(selector).forEach((el) => {
            if (el.disabled) return;
            if (el.type === "checkbox" || el.type === "radio") {
                if (el.checked) out.push(el.value);
            } else if (el.tagName === "SELECT" && el.multiple) {
                Array.from(el.selectedOptions).forEach((o) => out.push(o.value));
            } else if (String(el.value || "").trim() !== "") {
                out.push(String(el.value).trim());
            }
        });
        return out;
    }

    function matchesTerm(term, vals) {
        switch (term.op) {
            case "invalid":
                return false;
            case "set":
                return vals.length > 0;
            case "empty":
                return vals.length === 0;
            case "=":
                return vals.some((v) => term.values.includes(v));
            case "!=":
                return !vals.some((v) => term.values.includes(v));
            default: {
                // > >= < <= : numeric only; a non-numeric (or empty) value never matches
                const expected = toNumber(term.value);
                if (expected === null) return false;
                return vals.some((v) => {
                    const n = toNumber(v);
                    if (n === null) return false;
                    if (term.op === ">") return n > expected;
                    if (term.op === ">=") return n >= expected;
                    if (term.op === "<") return n < expected;
                    return n <= expected;
                });
            }
        }
    }

    // valuesOf(fieldName) -> current values of that field
    function matches(expression, valuesOf) {
        return expression.some((group) => group.every((term) => matchesTerm(term, valuesOf(term.field))));
    }

    function setVisible(wrapper, visible) {
        wrapper.style.display = visible ? "" : "none";
        wrapper.querySelectorAll("input, select, textarea, button").forEach((el) => {
            if (!visible && !el.disabled) {
                el.disabled = true;
                el.dataset.edhConditionDisabled = "1"; // only re-enable what we disabled
            } else if (visible && el.dataset.edhConditionDisabled) {
                el.disabled = false;
                delete el.dataset.edhConditionDisabled;
            }
        });
    }

    function apply(container, formData) {
        let data = formData;
        if (typeof data === "string") {
            try { data = JSON.parse(data); } catch (e) { data = []; }
        }
        const fields = (data || [])
            .filter((f) => f && f.name && parse(f[ATTR]))
            .map((f) => ({ name: f.name, expression: parse(f[ATTR]) }));
        if (!fields.length) return;

        const form = container.closest("form") || container;
        const valuesOf = (name) => values(form, name);
        const refresh = () => {
            // Repeat until stable so chained conditions (A -> B -> C) settle in one refresh.
            for (let pass = 0; pass <= fields.length; pass++) {
                let changed = false;
                fields.forEach((f) => {
                    const wrapper = container.querySelector(".field-" + CSS.escape(f.name));
                    if (!wrapper) return;
                    const visible = matches(f.expression, valuesOf);
                    if (visible === (wrapper.style.display === "none")) {
                        setVisible(wrapper, visible);
                        changed = true;
                    }
                });
                if (!changed) break;
            }
        };
        form.addEventListener("change", refresh);
        form.addEventListener("input", refresh);
        refresh();
    }

    // Builder-side check: list "Show only if" terms that reference a field missing from the
    // form (typo), the field itself, a non-numeric comparison, or an empty && / || side.
    // Such a field could otherwise stay hidden forever.
    function validate(formData) {
        let data = formData;
        if (typeof data === "string") {
            try { data = JSON.parse(data); } catch (e) { return []; }
        }
        const names = new Set((data || []).filter((f) => f && f.name).map((f) => f.name));
        const problems = [];
        (data || []).forEach((f) => {
            const expression = f && parse(f[ATTR]);
            if (!expression) return;
            const label = String(f.label || f.name).replace(/<[^>]*>/g, "");
            terms(expression).forEach((term) => {
                if (term.invalid) {
                    problems.push(label + ": " + t("fc_empty_term", "has an empty condition around && or ||"));
                } else if (term.field === f.name) {
                    problems.push(label + ": " + t("fc_self_reference", "depends on itself") + " (" + term.field + ")");
                } else if (!names.has(term.field)) {
                    problems.push(label + ": " + t("fc_unknown_field", "references an unknown field") + " '" + term.field + "'");
                } else if ([">", ">=", "<", "<="].includes(term.op) && toNumber(term.value) === null) {
                    problems.push(label + ": " + t("fc_not_a_number", "compares to a value that is not a number") + " '" + term.value + "'");
                }
            });
        });
        return problems;
    }

    window.EDHFormConditions = {
        attr: ATTR,
        apply: apply,
        validate: validate,
        // Evaluate a condition (used by tests / debugging). valuesByField maps a field name to
        // its list of values; a plain array is used for every field.
        evaluate: (condition, valuesByField) => {
            const expression = parse(condition);
            if (!expression) return true;
            const valuesOf = Array.isArray(valuesByField)
                ? () => valuesByField
                : (name) => (valuesByField && valuesByField[name]) || [];
            return matches(expression, valuesOf);
        },
        // "*" = every field type (formBuilder merges it with the type specific attributes)
        typeUserAttrs: {
            "*": {
                showIf: {
                    label: t("fc_show_if", "Show only if"),
                    placeholder: t("fc_show_if_placeholder", "other_field or other_field=value"),
                    value: "",
                },
            },
        },
    };
})(window);
