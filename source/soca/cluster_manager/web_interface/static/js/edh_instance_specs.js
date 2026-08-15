// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Single source of truth for the instance-type spec line shown in the WebUI.
// Both the admin pool-config typeahead/card grid (software_stacks_edit.html)
// and the end-user launch modal (virtual_desktops.html) call this so the spec
// line is identical on both surfaces -- no more per-surface drift.
//
// Input `s` is one spec object from either the admin typeahead catalog
// (api/v1/dcv/instance_type_search.py) or the end-user specs endpoint
// (api/v1/dcv/instance_type_specs.py); both are produced by the shared server
// parser utils/aws/instance_type_specs.parse_instance_specs, so they carry the
// same fields. Keep the fields read here in sync with that parser's output.
//
// Returns a middot-joined facts string, e.g.
//   "8 vCPU · 32 GiB RAM · 3.5 GHz · AMD · GPU 1/8 NVIDIA L4 (24 GiB VRAM)"
// "EBS" disk is intentionally omitted (everything is EBS -- it's noise).
function edhFormatInstanceSpecs(s, opts) {
    if (!s) return '';
    var _omit = (opts && opts.omit) || {};
    const parts = [];
    if (!_omit.vcpu && s.vcpu != null) parts.push(s.vcpu + ' vCPU');
    if (!_omit.mem && s.mem_gib != null) parts.push(s.mem_gib + ' GiB RAM');
    if (!_omit.clock && s.clock_ghz) parts.push(s.clock_ghz + ' GHz');
    if (!_omit.mfr && s.cpu_mfr) parts.push(s.cpu_mfr);
    if (!_omit.gpu && s.gpu) {
        // Fractional GPU (e.g. g6f = 1/8 of an L4) -> show the exact partition
        // fraction, not "x1" (which reads as a whole card). Full GPUs keep the
        // count.
        var g = s.gpu_frac
            ? ('GPU ' + s.gpu_frac + (s.gpu_name ? ' ' + s.gpu_name : ''))
            : ('GPU x' + s.gpu + (s.gpu_name ? ' ' + s.gpu_name : ''));
        if (s.gpu_mem_gib) g += ' (' + s.gpu_mem_gib + ' GiB VRAM)';
        parts.push(g);
    }
    // Everything is EBS-backed, so an "EBS" disk value is noise -- only show a
    // real instance-store disk (e.g. "1900 GB SSD").
    if (!_omit.disk && s.disk && s.disk !== 'EBS') parts.push(s.disk);
    return parts.join(' \u00B7 ');
}
