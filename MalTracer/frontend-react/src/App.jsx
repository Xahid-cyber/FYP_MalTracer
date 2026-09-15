import { useEffect, useMemo, useRef, useState } from 'react'
import myLogo from './assets/mylogo.png'

const Icon = ({ name, className = '' }) => {
  const icons = {
    dashboard: (
      <>
        <rect x="3" y="3" width="7" height="7" rx="1"/>
        <rect x="14" y="3" width="7" height="7" rx="1"/>
        <rect x="3" y="14" width="7" height="7" rx="1"/>
        <rect x="14" y="14" width="7" height="7" rx="1"/>
      </>
    ),
    queue: (
      <>
        <circle cx="12" cy="12" r="9"/>
        <path d="M12 7v5l3 2"/>
      </>
    ),
    report: (
      <>
        <path d="M6 3h9l4 4v14H6z"/>
        <path d="M15 3v5h5M9 13h6M9 17h5"/>
      </>
    ),
    history: (
      <>
        <path d="M4 12a8 8 0 1 0 2.3-5.7L4 8.6"/>
        <path d="M4 4v4.6h4.6"/>
      </>
    ),
    upload: (
      <>
        <path d="M12 16V4M8 8l4-4 4 4"/>
        <path d="M5 14v5h14v-5"/>
      </>
    ),
    spark: (
      <>
        <path d="m12 3 1.5 4.2L18 9l-4.5 1.8L12 15l-1.5-4.2L6 9l4.5-1.8L12 3Z"/>
        <path d="m18 14 .8 2.2L21 17l-2.2.8L18 20l-.8-2.2L15 17l2.2-.8L18 14Z"/>
      </>
    ),
    search: (
      <>
        <circle cx="10" cy="10" r="6"/>
        <path d="m15 15 5 5"/>
      </>
    ),
    document: (
      <>
        <path d="M6 3h9l4 4v14H6z"/>
        <path d="M15 3v5h5M9 13h6"/>
      </>
    ),
    archive: (
      <>
        <path d="M4 7h16v13H4zM7 4h10l2 3H5z"/>
        <path d="M9 11h6"/>
      </>
    ),
    packer: (
      <>
        <path d="M8 3h8l5 5v8l-5 5H8l-5-5V8z"/>
        <path d="M9 9h6v6H9z"/>
      </>
    ),
    globe: (
      <>
        <circle cx="12" cy="12" r="9"/>
        <path d="M3 12h18M12 3c3 3 4 6 4 9s-1 6-4 9c-3-3-4-6-4-9s1-6 4-9Z"/>
      </>
    ),
    code: (
      <>
        <path d="m8 9-4 3 4 3M16 9l4 3-4 3M14 5l-4 14"/>
      </>
    ),
    brain: (
      <>
        <path d="M9 4a3 3 0 0 0-3 3v2a3 3 0 0 0 0 6v2a3 3 0 0 0 3 3M15 4a3 3 0 0 1 3 3v2a3 3 0 0 1 0 6v2a3 3 0 0 1-3 3M9 4v16M15 4v16"/>
        <path d="M9 8h6M9 12h6M9 16h6"/>
      </>
    ),
    cloud: (
      <>
        <path d="M5 17h12a4 4 0 0 0 .7-7.9A6 6 0 0 0 6.3 7.8 4.5 4.5 0 0 0 5 17Z"/>
      </>
    ),
    plus: (
      <>
        <path d="M12 5v14M5 12h14"/>
      </>
    ),
    chevron: (
      <>
        <path d="m9 18 6-6-6-6"/>
      </>
    ),
    shield: (
      <>
        <path d="M12 3 4.5 6v5.3c0 4.7 3.1 7.9 7.5 9.7 4.4-1.8 7.5-5 7.5-9.7V6L12 3Z"/>
        <path d="m9 12 2 2 4-4"/>
      </>
    ),
  }

  return (
    <svg
      className={`icon ${className}`}
      viewBox="0 0 24 24"
      aria-hidden="true"
    >
      {icons[name] || icons.shield}
    </svg>
  )
}

const navItems = [
  ['dashboard', 'Dashboard'],
  ['queue', 'Queue Monitor'],
  ['reports', 'Reports'],
  ['history', 'Scan History'],
]

const profiles = [
  { id: 'analyze', title: 'Standard Analysis', desc: 'Full static triage with YARA, hashes, MITRE, VT and risk evidence.', icon: 'search', tone: 'cyan' },
  { id: 'docs', title: 'Document', desc: 'Static document and script analysis for macros, scripts and IOCs.', icon: 'document', tone: 'violet' },
  { id: 'archive', title: 'Archive', desc: 'Archive inspection with member listing and static YARA/IOC evidence.', icon: 'archive', tone: 'amber' },
  { id: 'packer', title: 'Packer Detect', desc: 'Static packer and obfuscation indicator detection.', icon: 'packer', tone: 'red' },
  { id: 'domain', title: 'Domain / IOC', desc: 'Extract URLs, IP addresses, domains and email addresses.', icon: 'globe', tone: 'green' },
  { id: 'lang', title: 'Language', desc: 'Programming-language fingerprinting from static evidence.', icon: 'code', tone: 'violet' },
  { id: 'behavioral', title: 'ML Behavioral Scan', desc: 'EMBER2024 static ML risk inference with heuristic and family-cluster evidence.', icon: 'brain', tone: 'cyan' },
]

const APP_LOCAL_CSS = `
  @keyframes maltracerSpin { to { transform: rotate(360deg); } }
  .scan-row.data:disabled { opacity: 1; cursor: default; }
  .scan-row.data:disabled:hover { background: transparent; }
  .job-status-wrap, .job-action { display: inline-flex; align-items: center; gap: 7px; min-width: 0; }
  .mini-spinner { width: 11px; height: 11px; flex: 0 0 11px; border: 2px solid rgba(43, 220, 232, 0.18); border-top-color: var(--cyan); border-radius: 50%; animation: maltracerSpin 0.85s linear infinite; }
  .job-status-icon { width: 15px; height: 15px; display: inline-grid; place-items: center; flex: 0 0 15px; border-radius: 50%; font-size: 9px; font-style: normal; font-weight: 800; }
  .job-status-icon.queued { color: #f4c566; border: 1px solid rgba(244, 197, 102, 0.28); background: rgba(244, 197, 102, 0.07); }
  .job-status-icon.completed { color: #58dfad; border: 1px solid rgba(88, 223, 173, 0.25); background: rgba(88, 223, 173, 0.07); }
  .job-status-icon.failed { color: #ff7378; border: 1px solid rgba(255, 115, 120, 0.25); background: rgba(255, 115, 120, 0.07); }
  .job-action { color: var(--muted); font-size: 11px; font-weight: 650; white-space: nowrap; }
  .job-action.ready, .job-action.failed { color: var(--cyan); }
  .job-action.progress { color: #9fb5c5; }
  .queue-decision-banner { margin-bottom: 12px; padding: 10px 12px; border: 1px solid rgba(43, 220, 232, 0.15); border-left: 3px solid rgba(43, 220, 232, 0.72); border-radius: 11px; background: linear-gradient(90deg, rgba(43, 220, 232, 0.045), rgba(140, 124, 255, 0.025)); color: #cfe0eb; font-size: 11px; line-height: 1.45; }
  .report-header-actions { display: flex; align-items: center; gap: 9px; flex-wrap: wrap; justify-content: flex-end; }
  .pdf-download-btn, .json-download-btn { min-height: 34px; padding: 7px 11px; font-size: 10px; }
  .pdf-download-btn::before, .json-download-btn::before { display: inline-grid; place-items: center; min-width: 26px; height: 19px; margin-right: 7px; border: 1px solid rgba(43, 220, 232, 0.22); border-radius: 5px; color: var(--cyan); font-size: 8px; font-weight: 800; letter-spacing: 0.04em; }
  .pdf-download-btn::before { content: "PDF"; }
  .json-download-btn::before { content: "JSON"; }
  .dashboard-stack { gap: 8px; }
  .dashboard-stack .hero-panel { padding-top: 10px; padding-bottom: 10px; }
  .dashboard-stack .hero-panel .section-head { margin-bottom: 4px; }
  .dashboard-stack .upload-zone { min-height: 82px; margin-top: 6px; padding-top: 9px; padding-bottom: 9px; }
  .dashboard-stack .upload-zone .icon-cube { width: 38px; height: 38px; }
  .dashboard-stack .recommend-head { margin-top: 6px; }
  .dashboard-stack .smart-card { margin-top: 5px; padding-top: 7px; padding-bottom: 7px; }
  .dashboard-stack > .panel:nth-of-type(2) { padding-top: 12px; padding-bottom: 11px; }
  .dashboard-stack > .panel:nth-of-type(2) .section-head { margin-bottom: 5px; }
  .dashboard-stack > .panel:nth-of-type(2) { padding-left: 14px; padding-right: 14px; }
  .dashboard-stack .profile-grid { width: 100%; grid-template-columns: repeat(7, minmax(0, 1fr)); margin-top: 9px; gap: 5px; }
  .dashboard-stack .profile-card { width: 100%; min-width: 0; min-height: 126px; padding: 11px 7px 11px; }
  .dashboard-stack .profile-card .icon-cube { width: 42px; height: 42px; }
  .dashboard-stack .profile-card .icon-cube .icon { width: 21px; height: 21px; }
  .dashboard-stack .profile-card strong { margin-top: 8px; font-size: 11px; line-height: 1.2; }
  .dashboard-stack .profile-card span { margin-top: 5px; font-size: 8.8px; line-height: 1.32; }
  .dashboard-stack .queue-action { position: relative; z-index: 4; margin-top: 17px; margin-bottom: 3px; }
  .dashboard-stack .queue-action .btn { min-width: 260px; min-height: 41px; padding-top: 9px; padding-bottom: 9px; font-size: 12px; }
  .maltracer-toast { position: fixed; top: 82px; right: 20px; z-index: 9999; width: min(470px, calc(100vw - 36px)); padding: 15px 16px; display: grid; grid-template-columns: auto minmax(0, 1fr) auto; align-items: start; gap: 12px; border: 1px solid rgba(43, 220, 232, 0.28); border-radius: 14px; background: linear-gradient(145deg, rgba(12, 25, 37, 0.992), rgba(7, 17, 28, 0.992)); box-shadow: 0 20px 55px rgba(0, 0, 0, 0.46), 0 0 30px rgba(43, 220, 232, 0.07); backdrop-filter: blur(16px); }
  .maltracer-toast.success { border-color: rgba(88, 223, 173, 0.55); box-shadow: 0 20px 55px rgba(0, 0, 0, 0.46), 0 0 28px rgba(88, 223, 173, 0.10); }
  .maltracer-toast.warning { border-color: rgba(255, 91, 96, 0.72); background: linear-gradient(145deg, rgba(47, 18, 23, 0.992), rgba(16, 15, 24, 0.992)); box-shadow: 0 20px 55px rgba(0, 0, 0, 0.48), 0 0 32px rgba(255, 91, 96, 0.14); }
  .maltracer-toast.error { border-color: rgba(255, 91, 96, 0.78); background: linear-gradient(145deg, rgba(52, 17, 22, 0.994), rgba(17, 13, 21, 0.994)); box-shadow: 0 20px 55px rgba(0, 0, 0, 0.48), 0 0 34px rgba(255, 91, 96, 0.16); }
  .toast-indicator { width: 28px; height: 28px; display: grid; place-items: center; border-radius: 50%; color: var(--cyan); border: 1px solid rgba(43, 220, 232, 0.30); background: rgba(43, 220, 232, 0.075); font-size: 13px; font-weight: 850; }
  .maltracer-toast.success .toast-indicator { color: #58dfad; border-color: rgba(88, 223, 173, 0.25); }
  .maltracer-toast.warning .toast-indicator { color: #ff767b; border-color: rgba(255, 91, 96, 0.50); background: rgba(255, 91, 96, 0.10); }
  .maltracer-toast.error .toast-indicator { color: #ff767b; border-color: rgba(255, 91, 96, 0.55); background: rgba(255, 91, 96, 0.11); }
  .toast-copy { min-width: 0; }
  .toast-copy strong { display: block; margin: 1px 0 4px; color: #f5fbff; font-size: 13px; line-height: 1.2; }
  .toast-copy span { display: block; color: #b7c8d4; font-size: 11.5px; line-height: 1.5; overflow-wrap: anywhere; }
  .maltracer-toast.warning .toast-copy strong, .maltracer-toast.error .toast-copy strong { color: #ffb0b3; }
  .toast-close { width: 26px; height: 26px; display: grid; place-items: center; padding: 0; color: #8196a7; border: 0; border-radius: 6px; background: transparent; cursor: pointer; font-size: 15px; line-height: 1; }
  .toast-close:hover { color: #eef8ff; background: rgba(255, 255, 255, 0.04); }
  @media (max-width: 1180px) and (min-width: 761px) { .dashboard-stack .profile-card { min-height: 122px; padding-left: 5px; padding-right: 5px; } .dashboard-stack .profile-card strong { font-size: 10.2px; } .dashboard-stack .profile-card span { font-size: 8.1px; } }
  @media (max-width: 760px) { .job-action { white-space: normal; } .report-header-actions { justify-content: flex-start; } .maltracer-toast { top: 70px; left: 12px; right: 12px; width: auto; } .dashboard-stack .profile-card { min-height: 108px; } .dashboard-stack .queue-action .btn { width: 100%; min-width: 0; } }
`

function pdfAscii(value) {
  return String(value ?? '').normalize('NFKD').replace(/[^\x20-\x7E]/g, ' ').replace(/\s+/g, ' ').trim()
}

function countLabel(count, singular, plural = `${singular}s`) {
  const value = Number(count) || 0
  return `${value} ${value === 1 ? singular : plural}`
}

function pdfEscapeText(value) {
  return pdfAscii(value).replace(/\\/g, '\\\\').replace(/\(/g, '\\(').replace(/\)/g, '\\)')
}

function buildPdfString(pages) {
  const objects = []
  const pageObjectIds = []
  const contentObjectIds = []
  for (let index = 0; index < pages.length; index += 1) { pageObjectIds.push(5 + index * 2); contentObjectIds.push(6 + index * 2) }
  objects[1] = '<< /Type /Catalog /Pages 2 0 R >>'
  objects[2] = `<< /Type /Pages /Count ${pages.length} /Kids [` + `${pageObjectIds.map((id) => `${id} 0 R`).join(' ')}] >>`
  objects[3] = '<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>'
  objects[4] = '<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>'
  pages.forEach((content, index) => {
    const pageId = pageObjectIds[index]
    const contentId = contentObjectIds[index]
    objects[pageId] = `<< /Type /Page /Parent 2 0 R ` + `/MediaBox [0 0 595 842] ` + `/Resources << /Font << ` + `/F1 3 0 R /F2 4 0 R >> >> ` + `/Contents ${contentId} 0 R >>`
    objects[contentId] = `<< /Length ${content.length} >>\n` + `stream\n${content}\nendstream`
  })
  let pdf = '%PDF-1.4\n% MalTracer generated report\n'
  const offsets = [0]
  for (let id = 1; id < objects.length; id += 1) { offsets[id] = pdf.length; pdf += `${id} 0 obj\n` + `${objects[id]}\n` + `endobj\n` }
  const xrefOffset = pdf.length
  pdf += `xref\n0 ${objects.length}\n`
  pdf += '0000000000 65535 f \n'
  for (let id = 1; id < objects.length; id += 1) { pdf += `${String(offsets[id]).padStart(10, '0')} 00000 n \n` }
  pdf += `trailer\n` + `<< /Size ${objects.length} ` + `/Root 1 0 R >>\n`
  pdf += `startxref\n` + `${xrefOffset}\n` + `%%EOF`
  return pdf
}

const PDF_COLORS = { bg: [0.035, 0.055, 0.075], panel: [0.055, 0.085, 0.115], panel2: [0.065, 0.105, 0.135], border: [0.13, 0.22, 0.28], text: [0.93, 0.97, 0.99], muted: [0.52, 0.64, 0.72], cyan: [0.16, 0.80, 0.86], violet: [0.52, 0.46, 0.94], amber: [0.96, 0.70, 0.25] }

function createPdfPage() {
  const commands = []
  const pageHeight = 842
  function rgb(values) { return values.map((value) => Number(value).toFixed(3)).join(' ') }
  function fill(values) { return `${rgb(values)} rg` }
  function stroke(values) { return `${rgb(values)} RG` }
  const page = {
    rect(x, y, width, height, fillColor, strokeColor = null, lineWidth = 1) {
      const pdfY = pageHeight - y - height
      commands.push('q')
      if (fillColor) { commands.push(fill(fillColor)) }
      if (strokeColor) { commands.push(stroke(strokeColor)); commands.push(`${lineWidth} w`) }
      commands.push(`${x} ${pdfY} ` + `${width} ${height} re ` + `${fillColor && strokeColor ? 'B' : fillColor ? 'f' : 'S'}`)
      commands.push('Q')
    },
    line(x1, y1, x2, y2, color, lineWidth = 1) { commands.push(`q ${stroke(color)} ` + `${lineWidth} w ` + `${x1} ${pageHeight - y1} m ` + `${x2} ${pageHeight - y2} l ` + `S Q`) },
    text(value, x, y, size = 10, bold = false, color = PDF_COLORS.text) { commands.push(`BT /${bold ? 'F2' : 'F1'} ${size} Tf ` + `${fill(color)} ` + `${x} ${pageHeight - y} Td ` + `(${pdfEscapeText(value)}) Tj ET`) },
    wrapText(value, x, y, maxWidth, size = 10, bold = false, color = PDF_COLORS.text, lineHeight = null, maxLines = 8) {
      const text = pdfAscii(value)
      const charWidth = Math.max(1, size * 0.52)
      const maxChars = Math.max(8, Math.floor(maxWidth / charWidth))
      const words = text.split(/\s+/).filter(Boolean)
      const lines = []
      let current = ''
      let truncated = false
      for (let wordIndex = 0; wordIndex < words.length; wordIndex += 1) {
        const word = words[wordIndex]
        const candidate = current ? `${current} ${word}` : word
        if (candidate.length <= maxChars) { current = candidate; continue }
        if (current) { lines.push(current); current = ''; if (lines.length >= maxLines) { truncated = true; break } }
        if (word.length > maxChars) {
          let remaining = word
          while (remaining.length > maxChars) {
            lines.push(remaining.slice(0, maxChars))
            remaining = remaining.slice(maxChars)
            if (lines.length >= maxLines) { truncated = Boolean(remaining) || wordIndex < words.length - 1; break }
          }
          if (lines.length >= maxLines) { break }
          current = remaining
        } else { current = word }
      }
      if (current && lines.length < maxLines) { lines.push(current) } else if (current) { truncated = true }
      if (truncated && lines.length) { lines[lines.length - 1] = `${lines[lines.length - 1].slice(0, Math.max(0, maxChars - 3))}...` }
      const resolvedLineHeight = lineHeight || size * 1.35
      lines.forEach((line, index) => page.text(line, x, y + index * resolvedLineHeight, size, bold, color))
      return lines.length * resolvedLineHeight
    },
    finish() { return commands.join('\n') },
  }
  page.rect(0, 0, 595, 842, PDF_COLORS.bg)
  return page
}

function addPdfHeader(page, title, subtitle, pageNumber) {
  page.text('MalTracer', 38, 42, 18, true)
  page.text('SAFE NON-EXECUTION MALWARE ANALYSIS', 38, 61, 7.5, false, PDF_COLORS.cyan)
  page.text(title, 38, 91, 20, true)
  if (subtitle) { page.text(subtitle, 38, 109, 9, false, PDF_COLORS.muted) }
  page.line(38, 126, 557, 126, PDF_COLORS.border, 0.8)
  page.text(`Page ${pageNumber}`, 512, 812, 8, false, PDF_COLORS.muted)
  page.text('MalTracer - Preliminary analysis and decision-support report', 38, 812, 7.5, false, PDF_COLORS.muted)
}

function addPdfCard(page, x, y, width, height, title, value, note = '') {
  page.rect(x, y, width, height, PDF_COLORS.panel, PDF_COLORS.border, 0.7)
  page.text(title, x + 12, y + 18, 7.5, false, PDF_COLORS.muted)
  page.wrapText(value, x + 12, y + 40, width - 24, 15, true, PDF_COLORS.text, 18, 2)
  if (note) { page.wrapText(note, x + 12, y + height - 15, width - 24, 7, false, PDF_COLORS.muted, 9, 2) }
}

function addPdfBarChart(page, title, data, x, y, width, height, maxOverride = null, suffix = '') {
  const clean = (Array.isArray(data) ? data : [])
    .map((item) => ({ label: pdfAscii(item?.label || 'Item'), value: Math.max(0, Number(item?.value) || 0) }))
    .filter((item) => item.value > 0 || maxOverride !== null)
    .slice(0, 8)
  if (!clean.length) { return }
  page.rect(x, y, width, height, PDF_COLORS.panel, PDF_COLORS.border, 0.7)
  page.text(title, x + 12, y + 19, 10, true)
  const maxValue = maxOverride || Math.max(1, ...clean.map((item) => item.value))
  const labelWidth = Math.min(150, width * 0.34)
  const barX = x + labelWidth + 16
  const barWidth = width - labelWidth - 48
  const rowHeight = Math.min(30, (height - 44) / clean.length)
  clean.forEach((item, index) => {
    const rowY = y + 42 + index * rowHeight
    const label = item.label.length > 22 ? `${item.label.slice(0, 20)}...` : item.label
    page.text(label, x + 12, rowY + 10, 7.5)
    page.rect(barX, rowY, barWidth, 10, [0.10, 0.16, 0.21])
    const valueWidth = Math.max(1.5, Math.min(barWidth, (item.value / maxValue) * barWidth))
    page.rect(barX, rowY, valueWidth, 10, PDF_COLORS.cyan)
    page.text(`${Number.isInteger(item.value) ? item.value : item.value.toFixed(1)}${suffix}`, barX + barWidth + 6, rowY + 9, 7.5, true)
  })
}

function buildMalTracerPdf(data) {
  const job = data?.job || {}
  const ui = data?.report_ui || {}
  const hashes = Array.isArray(ui.hashes) ? ui.hashes : []
  const categories = Array.isArray(ui.categories) ? ui.categories : []
  const yaraRules = Array.isArray(ui.matched_rules_rows) ? ui.matched_rules_rows : []
  const mitreRows = Array.isArray(ui.mitre_rows) ? ui.mitre_rows : []
  const patterns = Array.isArray(ui.interesting_patterns) ? ui.interesting_patterns : []
  const apiRows = Array.isArray(ui.windows_api_categories) ? ui.windows_api_categories : []
  const metadata = Array.isArray(ui.metadata) ? ui.metadata : []
  const vt = ui.vt_section || {}
  const riskAvailable = ui.final_risk_val !== null && ui.final_risk_val !== undefined && ui.final_risk_val !== '' && Number.isFinite(Number(ui.final_risk_val))
  const risk = riskAvailable ? Math.max(0, Math.min(100, Number(ui.final_risk_val))) : null
  const mlScore = Math.max(0, Math.min(100, Number(ui.ml_raw) || 0))
  const behaviorScore = Math.max(0, Math.min(100, (Number(ui.behavior_score_val) || 0) * 100))
  const packerScore = Math.max(0, Math.min(100, (Number(ui.packer_score_val) || 0) * 100))
  function vtValue(label) { return Number((vt.summary || []).find((item) => String(item.label || '').toLowerCase() === label)?.value) || 0 }
  const vtDetections = vtValue('detections')
  const vtEngines = vtValue('engines')
  const yaraHitCount = yaraRules.reduce((sum, rule) => sum + (Number(rule.count) || 0), 0)
  const mitreCount = mitreRows.reduce((sum, tactic) => sum + (Number(tactic.technique_count) || 0), 0)
  const apiCount = apiRows.reduce((sum, item) => sum + (Number(item.count) || 0), 0)
  const pages = []
  {
    const page = createPdfPage()
    addPdfHeader(page, 'Analysis Report', `${job.sample_name || 'Unknown sample'} | ${job.preset_label || job.preset_key || 'Analysis'}`, 1)
    addPdfCard(page, 38, 146, 165, 112, 'FINAL RISK SCORE', riskAvailable ? `${risk}/100` : 'N/A', !riskAvailable ? 'No contextual risk score was produced for this profile' : risk < 20 ? 'Low risk / no strong malicious evidence' : risk < 70 ? 'Requires analyst review' : 'High risk evidence')
    addPdfCard(page, 216, 146, 341, 112, 'SAMPLE', job.sample_name || 'Unknown', `Status: ${job.status || '-'}   Duration: ${job.duration ?? '-'}s`)
    if (job.smart_auto) {
      page.rect(38, 272, 519, 56, PDF_COLORS.panel2, PDF_COLORS.border, 0.7)
      page.text('SMART AUTO ROUTING', 50, 290, 7.5, false, PDF_COLORS.violet)
      page.wrapText(`${job.auto_detected_type || 'Detected file'} -> ${job.resolved_preset_label || job.preset_key || 'Analyzer'}`, 50, 308, 495, 10, true, PDF_COLORS.text, 13, 2)
      if (job.auto_detection_reason) { page.wrapText(job.auto_detection_reason, 50, 322, 495, 7.5, false, PDF_COLORS.muted, 10, 2) }
    }
    const evidenceY = job.smart_auto ? 344 : 282
    addPdfCard(page, 38, evidenceY, 120, 74, 'VIRUSTOTAL', vt.available ? `${vtDetections}/${vtEngines}` : 'N/A', 'detections')
    addPdfCard(page, 168, evidenceY, 120, 74, 'YARA', `${yaraRules.length}`, `${yaraHitCount} evidence hits`)
    addPdfCard(page, 298, evidenceY, 120, 74, 'MITRE', `${mitreCount}`, 'static associations')
    addPdfCard(page, 428, evidenceY, 129, 74, 'EMBER ML', ui.ml_available ? `${mlScore}/100` : 'N/A', 'raw model score')
    page.text('Assessment Notes', 38, evidenceY + 104, 11, true)
    const notes = [
      vt.available ? `VirusTotal detections: ${vtDetections}/${vtEngines}. Zero detections do not guarantee safety.` : 'VirusTotal data is not available for this report.',
      yaraRules.length ? `YARA returned ${yaraRules.length} unique matched rules and ${yaraHitCount} evidence hits.` : 'No YARA rule evidence was returned.',
      mitreCount ? `MITRE ATT&CK mapping produced ${mitreCount} static tactic-technique associations from matched API evidence; these are not observed runtime actions.` : 'No MITRE ATT&CK technique associations were mapped.',
      ui.ml_available ? riskAvailable ? `EMBER raw ML score: ${mlScore}/100. This is not the final malicious probability; final contextual risk is ${risk}/100.` : `EMBER raw ML score: ${mlScore}/100. This is not a final malicious probability; this profile did not produce a contextual risk score.` : riskAvailable ? `Final contextual risk: ${risk}/100. EMBER ML scoring is not available/applicable for this sample.` : 'No final contextual risk or EMBER ML score was produced for this profile.',
    ]
    let noteY = evidenceY + 128
    notes.forEach((note, index) => {
      page.rect(38, noteY - 12, 8, 8, index === 3 ? PDF_COLORS.violet : PDF_COLORS.cyan)
      const used = page.wrapText(note, 54, noteY, 500, 8, false, PDF_COLORS.text, 11, 3)
      noteY += Math.max(28, used + 8)
    })
    page.rect(38, 704, 519, 70, [0.045, 0.075, 0.095], PDF_COLORS.border, 0.7)
    page.text('IMPORTANT INTERPRETATION', 50, 724, 8, true, PDF_COLORS.amber)
    page.wrapText('MalTracer is a non-execution preliminary analysis and decision-support toolkit. Findings such as YARA, MITRE mappings, VirusTotal results, IOCs, entropy and ML scores are evidence signals and require analyst interpretation.', 50, 742, 493, 7.5, false, PDF_COLORS.muted, 10, 4)
    pages.push(page.finish())
  }
  if (ui.ml_available || categories.length || yaraRules.length || mitreRows.length || apiRows.length) {
    const page = createPdfPage()
    addPdfHeader(page, 'Visual Evidence Summary', 'Evidence values from this report', pages.length + 1)
    let y = 145
    if (ui.ml_available) {
      addPdfBarChart(page, 'EMBER ML Risk Breakdown', [
        { label: 'Raw ML Score', value: mlScore },
        { label: 'Static Behavior Heuristic', value: behaviorScore },
        { label: 'Packer / Obfuscation', value: packerScore },
        ...(riskAvailable ? [{ label: 'Final Contextual Risk', value: risk }] : []),
      ], 38, y, 519, 190, 100, '%')
      y += 208
    }
    if (categories.length) {
      const categoryData = categories.map((item) => ({ label: item.name || 'Category', value: Number(item.count) || 0 })).filter((item) => item.value > 0).sort((a, b) => b.value - a.value).slice(0, 8)
      addPdfBarChart(page, 'Finding Categories', categoryData, 38, y, 250, 250)
    }
    const evidenceData = [
      { label: 'YARA Hits', value: yaraHitCount },
      { label: 'MITRE Associations', value: mitreCount },
      { label: 'Categorized API Entries', value: apiCount },
      { label: 'String Patterns', value: patterns.length },
    ].filter((item) => item.value > 0)
    if (evidenceData.length) { addPdfBarChart(page, 'Evidence Sources', evidenceData, 307, y, 250, 250) }
    pages.push(page.finish())
  }
  if (yaraRules.length || mitreRows.length) {
    const page = createPdfPage()
    addPdfHeader(page, 'YARA and MITRE ATT&CK', 'Static evidence interpretation', pages.length + 1)
    let y = 145
    if (yaraRules.length) {
      const yaraData = yaraRules.map((rule) => ({ label: rule.name || 'Rule', value: Number(rule.count) || 0 })).sort((a, b) => b.value - a.value).slice(0, 8)
      addPdfBarChart(page, 'Top YARA Rule Hits', yaraData, 38, y, 519, 255)
      y += 274
    }
    if (mitreRows.length) {
      const mitreData = mitreRows.map((item) => ({ label: item.tactic || 'Tactic', value: Number(item.score) || 0 })).filter((item) => item.value > 0).sort((a, b) => b.value - a.value).slice(0, 8)
      addPdfBarChart(page, 'MITRE API Evidence by Tactic', mitreData, 38, y, 519, 255)
      page.text('Static capability mapping only - not confirmation of runtime execution.', 50, y + 237, 7.5, false, PDF_COLORS.muted)
    }
    pages.push(page.finish())
  }
  {
    const page = createPdfPage()
    addPdfHeader(page, 'File Intelligence and Identity', 'VirusTotal, hashes and selected metadata', pages.length + 1)
    addPdfCard(page, 38, 145, 165, 82, 'VIRUSTOTAL DETECTIONS', vt.available ? `${vtDetections}/${vtEngines}` : 'N/A', '0 detections is not a safety guarantee')
    addPdfCard(page, 216, 145, 165, 82, 'FINAL RISK', riskAvailable ? `${risk}/100` : 'N/A', riskAvailable ? 'contextual risk' : 'not produced for this profile')
    addPdfCard(page, 394, 145, 163, 82, 'STRING PATTERNS', `${patterns.length}`, 'static patterns')
    page.text('File Identity / Hashes', 38, 258, 11, true)
    let y = 282
    hashes.slice(0, 8).forEach((item) => {
      page.text(pdfAscii(item.label || 'Field'), 38, y, 7.5, true, PDF_COLORS.cyan)
      const used = page.wrapText(item.value ?? '-', 150, y, 400, 7.5, false, PDF_COLORS.text, 10, 3)
      y += Math.max(18, used + 3)
    })
    if (metadata.length && y < 620) {
      page.text('Selected Metadata', 38, y + 12, 11, true)
      y += 36
      metadata.slice(0, 10).forEach((item) => {
        page.text(pdfAscii(item.label || 'Field'), 38, y, 7.5, true, PDF_COLORS.muted)
        const used = page.wrapText(item.value ?? '-', 180, y, 370, 7.5, false, PDF_COLORS.text, 10, 2)
        y += Math.max(18, used + 3)
      })
    }
    page.text(`Generated: ${new Date().toISOString()}`, 38, 776, 7.5, false, PDF_COLORS.muted)
    pages.push(page.finish())
  }
  return buildPdfString(pages)
}

function downloadMalTracerPdf(data) {
  if (!data?.report_loaded) { return }
  const pdf = buildMalTracerPdf(data)
  const blob = new Blob([pdf], { type: 'application/pdf' })
  const url = URL.createObjectURL(blob)
  const sampleName = pdfAscii(data?.job?.sample_name || 'sample').replace(/[^A-Za-z0-9._-]+/g, '_').replace(/^_+|_+$/g, '') || 'sample'
  const link = document.createElement('a')
  const profileName = pdfAscii(data?.job?.preset_label || data?.job?.preset_key || 'Analysis').replace(/[^A-Za-z0-9._-]+/g, '_').replace(/^_+|_+$/g, '') || 'Analysis'
  const jobToken = pdfAscii(data?.job?.id || '').replace(/[^A-Za-z0-9]+/g, '').slice(0, 8) || 'job'
  link.href = url
  link.download = `MalTracer_${sampleName}_${profileName}_${jobToken}_Report.pdf`
  document.body.appendChild(link)
  link.click()
  link.remove()
  window.setTimeout(() => { URL.revokeObjectURL(url) }, 1500)
}

function downloadMalTracerJson(data) {
  if (!data?.report_loaded) { return }
  const json = JSON.stringify(data, null, 2)
  const blob = new Blob([json], { type: 'application/json;charset=utf-8' })
  const url = URL.createObjectURL(blob)
  const sampleName = pdfAscii(data?.job?.sample_name || 'sample').replace(/[^A-Za-z0-9._-]+/g, '_').replace(/^_+|_+$/g, '') || 'sample'
  const profileName = pdfAscii(data?.job?.preset_label || data?.job?.preset_key || 'Analysis').replace(/[^A-Za-z0-9._-]+/g, '_').replace(/^_+|_+$/g, '') || 'Analysis'
  const jobToken = pdfAscii(data?.job?.id || '').replace(/[^A-Za-z0-9]+/g, '').slice(0, 8) || 'job'
  const link = document.createElement('a')
  link.href = url
  link.download = `MalTracer_${sampleName}_${profileName}_${jobToken}_Report.json`
  document.body.appendChild(link)
  link.click()
  link.remove()
  window.setTimeout(() => { URL.revokeObjectURL(url) }, 1500)
}

function CyberCoreBackground() {
  const canvasRef = useRef(null)
  useEffect(() => {
    const canvas = canvasRef.current
    if (!canvas) { return undefined }
    const host = canvas.parentElement
    const appShell = host?.parentElement
    const context = canvas.getContext('2d')
    if (!host || !appShell || !context) { return undefined }
    const teal = [45, 212, 191]
    const violet = [139, 124, 246]
    let width = 1
    let height = 1
    let dpr = 1
    let animationFrame = 0
    let particles = []
    const reducedMotionQuery = window.matchMedia('(prefers-reduced-motion: reduce)')
    function createParticles() {
      particles = Array.from({ length: 45 }, () => {
        const isViolet = Math.random() < 0.2
        return { x: Math.random() * width, y: Math.random() * height, vx: (Math.random() - 0.5) * 0.18, vy: (Math.random() - 0.5) * 0.18, radius: 0.8 + Math.random() * 1.4, color: isViolet ? violet : teal, alpha: 0.18 + Math.random() * 0.30 }
      })
    }
    function resizeCanvas() {
      const rect = appShell.getBoundingClientRect()
      width = Math.max(1, Math.floor(rect.width))
      height = Math.max(1, Math.floor(Math.max(rect.height, appShell.scrollHeight)))
      dpr = Math.min(window.devicePixelRatio || 1, 2)
      canvas.width = Math.floor(width * dpr)
      canvas.height = Math.floor(height * dpr)
      canvas.style.width = `${width}px`
      canvas.style.height = `${height}px`
      context.setTransform(dpr, 0, 0, dpr, 0, 0)
      if (particles.length === 0) { createParticles() } else { particles.forEach((particle) => { particle.x = Math.min(width, Math.max(0, particle.x)); particle.y = Math.min(height, Math.max(0, particle.y)) }) }
    }
    function updateParticles() {
      particles.forEach((particle) => {
        particle.x += particle.vx; particle.y += particle.vy
        if (particle.x <= 0 || particle.x >= width) { particle.vx *= -1; particle.x = Math.min(width, Math.max(0, particle.x)) }
        if (particle.y <= 0 || particle.y >= height) { particle.vy *= -1; particle.y = Math.min(height, Math.max(0, particle.y)) }
      })
    }
    function drawNetwork() {
      context.clearRect(0, 0, width, height)
      const connectionDistance = 130
      for (let first = 0; first < particles.length; first += 1) {
        const a = particles[first]
        for (let second = first + 1; second < particles.length; second += 1) {
          const b = particles[second]
          const dx = a.x - b.x; const dy = a.y - b.y
          const distance = Math.sqrt(dx * dx + dy * dy)
          if (distance >= connectionDistance) { continue }
          const proximity = 1 - distance / connectionDistance
          const violetConnection = a.color === violet || b.color === violet
          const lineColor = violetConnection ? violet : teal
          const lineAlpha = 0.035 + proximity * 0.11
          context.beginPath(); context.moveTo(a.x, a.y); context.lineTo(b.x, b.y)
          context.strokeStyle = `rgba(${lineColor[0]}, ${lineColor[1]}, ${lineColor[2]}, ${lineAlpha})`
          context.lineWidth = 0.7; context.stroke()
        }
      }
      particles.forEach((particle) => {
        const [red, green, blue] = particle.color
        context.beginPath(); context.arc(particle.x, particle.y, particle.radius, 0, Math.PI * 2)
        context.fillStyle = `rgba(${red}, ${green}, ${blue}, ${particle.alpha})`; context.fill()
      })
    }
    function animate() { if (!reducedMotionQuery.matches) { updateParticles() } drawNetwork(); animationFrame = window.requestAnimationFrame(animate) }
    resizeCanvas()
    const resizeObserver = typeof ResizeObserver !== 'undefined' ? new ResizeObserver(resizeCanvas) : null
    resizeObserver?.observe(appShell)
    window.addEventListener('resize', resizeCanvas)
    animationFrame = window.requestAnimationFrame(animate)
    return () => { window.cancelAnimationFrame(animationFrame); window.removeEventListener('resize', resizeCanvas); resizeObserver?.disconnect() }
  }, [])
  return (
    <div className="cyber-core-background" aria-hidden="true">
      <canvas ref={canvasRef} className="cyber-particle-canvas" />
      <div className="cyber-grid-overlay"></div>
      <div className="cyber-core-scene">
        <div className="cyber-core-glow"></div>
        <div className="cyber-radar-sweep"></div>
        <div className="cyber-orb">
          <span className="cyber-orb-ring cyber-ring-teal"></span>
          <span className="cyber-orb-ring cyber-ring-violet"></span>
          <span className="cyber-orb-ring cyber-ring-cyan"></span>
          <div className="cyber-file-emblem">
            <svg className="cyber-file-svg" viewBox="0 0 120 150" role="presentation">
              <path className="cyber-file-outline" d="M27 10h44l22 22v108H27z" />
              <path className="cyber-file-fold-line" d="M71 10v23h22" />
              <path className="cyber-file-detail" d="M43 57h33M43 70h28M43 83h22" />
              <circle className="cyber-file-reticle" cx="60" cy="111" r="17" />
              <circle className="cyber-file-reticle-inner" cx="60" cy="111" r="7" />
            </svg>
            <span className="cyber-file-scanline"></span>
          </div>
          <span className="cyber-orbit orbit-teal"><i></i></span>
          <span className="cyber-orbit orbit-violet"><i></i></span>
          <span className="cyber-orbit orbit-amber"><i></i></span>
        </div>
      </div>
    </div>
  )
}

function App() {
  const [view, setView] = useState('dashboard')
  const [selectedProfile, setSelectedProfile] = useState('analyze')
  const [selectedFile, setSelectedFile] = useState(null)
  const [jobs, setJobs] = useState([])
  const [queueStats, setQueueStats] = useState({ queued: 0, running: 0, total: 0 })
  const [search, setSearch] = useState('')
  const [isSubmitting, setIsSubmitting] = useState(false)
  const [message, setMessage] = useState('')
  const [backendOnline, setBackendOnline] = useState(true)
  const [smartAutoPending, setSmartAutoPending] = useState(false)
  const [toast, setToast] = useState(null)
  const [selectedReport, setSelectedReport] = useState(null)
  const [reportLoading, setReportLoading] = useState(false)
  const [reportError, setReportError] = useState('')
  const [reportTab, setReportTab] = useState('overview')
  const fileInputRef = useRef(null)
  const toastTimerRef = useRef(null)

  function clearToast() {
    if (toastTimerRef.current) { window.clearTimeout(toastTimerRef.current); toastTimerRef.current = null }
    setToast(null)
  }

  function showToast(text, tone = 'info', duration = 3400) {
    if (toastTimerRef.current) { window.clearTimeout(toastTimerRef.current) }
    setToast({ text, tone })
    toastTimerRef.current = window.setTimeout(() => { setToast(null); toastTimerRef.current = null }, duration)
  }

  async function refreshJobs() {
    try {
      const response = await fetch('/api/jobs')
      if (!response.ok) { throw new Error(`HTTP ${response.status}`) }
      const data = await response.json()
      setJobs(Array.isArray(data.jobs) ? data.jobs : [])
      setQueueStats({ queued: data.queue?.queued ?? 0, running: data.queue?.running ?? 0, total: data.queue?.total ?? 0 })
      setBackendOnline(true)
    } catch (error) {
      console.error('Failed to load jobs:', error)
      setBackendOnline(false)
    }
  }

  useEffect(() => { refreshJobs(); const timer = window.setInterval(() => { refreshJobs() }, 2000); return () => { window.clearInterval(timer) } }, [])
  useEffect(() => { return () => { if (toastTimerRef.current) { window.clearTimeout(toastTimerRef.current) } } }, [])

  const normalizedJobs = useMemo(() => {
    return jobs.map((job) => {
      const hasRisk = job.final_risk !== null && job.final_risk !== undefined && job.final_risk !== '' && Number.isFinite(Number(job.final_risk))
      return {
        id: job.id,
        name: job.sample_name || 'Unknown file',
        profile: job.preset_label || job.preset_key || 'Unknown',
        status: job.status || 'Unknown',
        risk: hasRisk ? `${Math.round(Number(job.final_risk))}/100` : 'N/A',
        date: job.finished_at_text || job.started_at_text || job.created_at_text || '—',
      }
    })
  }, [jobs])

  const filteredJobs = useMemo(() => {
    const term = search.trim().toLowerCase()
    if (!term) { return normalizedJobs }
    return normalizedJobs.filter((job) => `${job.name} ${job.id} ${job.profile} ${job.status}`.toLowerCase().includes(term))
  }, [normalizedJobs, search])

  const completedJobs = useMemo(() => normalizedJobs.filter((job) => job.status.toLowerCase() === 'completed').length, [normalizedJobs])
  const failedJobs = useMemo(() => normalizedJobs.filter((job) => job.status.toLowerCase() === 'failed').length, [normalizedJobs])

  const pageTitle = { dashboard: 'Security Analysis Dashboard', queue: 'Queue Monitor', reports: 'Reports', history: 'Scan History', report: 'Analysis Report' }[view]

  function chooseFile() { fileInputRef.current?.click() }

  function fileExtension(file) {
    const name = String(file?.name || '').trim().toLowerCase()
    const dotIndex = name.lastIndexOf('.')
    if (dotIndex <= 0 || dotIndex === name.length - 1) { return '' }
    return name.slice(dotIndex)
  }

  function profileCompatibilityError(file, presetKey) {
    if (!file || !presetKey) { return '' }
    const extension = fileExtension(file)
    if (presetKey === 'archive') {
      const archiveExtensions = new Set(['.zip', '.rar', '.7z', '.tar', '.gz', '.tgz', '.bz2', '.xz', '.cab'])
      if (extension && !archiveExtensions.has(extension)) {
        return `Archive profile expects an archive file ` + `(ZIP/RAR/7Z/TAR/GZ/BZ2/XZ/CAB). ` + `${file.name} uses ${extension}. ` + `Choose the matching profile or use Smart Auto Analysis.`
      }
    }
    return ''
  }

  function validateFile(file) {
    if (!file) { return 'Please select a file first.' }
    const maxBytes = 48 * 1024 * 1024
    if (file.size > maxBytes) { return 'File is larger than the 48 MB upload limit.' }
    return ''
  }

  function handleFile(file) {
    const validationError = validateFile(file)
    if (validationError) { setSelectedFile(null); showToast(validationError, 'error'); return false }
    setSelectedFile(file); setMessage(''); return true
  }

  function handleFileInput(event) {
    const file = event.target.files?.[0]
    if (!file) { setSmartAutoPending(false); clearToast(); return }
    const accepted = handleFile(file)
    if (accepted && smartAutoPending) { setSmartAutoPending(false); window.setTimeout(() => { runSmartAnalysis(file) }, 0) }
  }

  function handleDrop(event) {
    event.preventDefault()
    const file = event.dataTransfer.files?.[0]
    if (file) { handleFile(file) }
  }

  async function submitAnalysis({ file, presetKey = '', smartAuto = false }) {
    const validationError = validateFile(file)
    if (validationError) { showToast('Select a file before queuing analysis.', 'warning'); return null }
    if (!smartAuto && !presetKey) { showToast('Select an analysis profile before queuing.', 'warning'); return null }
    if (!smartAuto) {
      const compatibilityError = profileCompatibilityError(file, presetKey)
      if (compatibilityError) { showToast(compatibilityError, 'warning', 6200); setMessage(compatibilityError); return null }
    }
    setIsSubmitting(true); setMessage('')
    try {
      const formData = new FormData()
      formData.append('sample', file)
      if (!smartAuto) { formData.append('preset', presetKey) }
      const endpoint = smartAuto ? '/api/smart-analyze' : '/analyze'
      const response = await fetch(endpoint, { method: 'POST', body: formData })
      const contentType = response.headers.get('content-type') || ''
      let jsonPayload = null
      if (contentType.includes('application/json')) { jsonPayload = await response.json() }
      if (!response.ok) { throw new Error(jsonPayload?.error || `HTTP ${response.status}`) }
      let result = null
      if (smartAuto) {
        if (!jsonPayload) { throw new Error('Smart Auto API returned HTML instead of JSON. Restart the Flask backend after replacing web_app.py.') }
        result = jsonPayload
      }
      setSelectedFile(null)
      if (fileInputRef.current) { fileInputRef.current.value = '' }
      await refreshJobs()
      if (smartAuto && result) {
        const notice = `Smart Auto detected ${result.detected_type} and selected ${result.selected_preset_label}.`
        setMessage(notice); showToast(notice, 'success', 4200)
      } else {
        const notice = 'Analysis queued successfully.'
        setMessage(notice); showToast(notice, 'success')
      }
      setView('queue')
      return result
    } catch (error) {
      console.error('Analysis submission failed:', error)
      setMessage('')
      showToast(smartAuto ? `Smart Auto could not route this file: ${error.message}` : 'Could not queue analysis. Check the Flask backend.', 'error', 5200)
      return null
    } finally { setIsSubmitting(false) }
  }

  async function queueAnalysis() { await submitAnalysis({ file: selectedFile, presetKey: selectedProfile, smartAuto: false }) }

  async function runSmartAnalysis(fileOverride = null) {
    const file = fileOverride || selectedFile
    if (!file) { setSmartAutoPending(true); showToast('Select a file for Smart Auto Analysis.', 'info', 2600); fileInputRef.current?.click(); return }
    setSmartAutoPending(false)
    await submitAnalysis({ file, smartAuto: true })
  }

  async function openReport(scan) {
    if (!scan?.id) { return }
    setReportLoading(true); setReportError(''); setSelectedReport(null); setReportTab('overview'); setView('report')
    try {
      const response = await fetch(`/api/jobs/${encodeURIComponent(scan.id)}`)
      if (!response.ok) { throw new Error(`HTTP ${response.status}`) }
      const data = await response.json()
      setSelectedReport(data)
    } catch (error) {
      console.error('Report API failed:', error)
      setReportError('Could not load this report from the MalTracer backend.')
    } finally { setReportLoading(false) }
  }

  function newAnalysis() {
    setView('dashboard'); setSelectedReport(null); setReportError(''); setReportTab('overview'); setMessage(''); clearToast()
  }

  return (
    <div className="app-shell">
      <style>{APP_LOCAL_CSS}</style>
      {toast && (
        <div className={`maltracer-toast ${toast.tone || 'info'}`} role="status" aria-live="polite">
          <span className="toast-indicator">
            {toast.tone === 'success' ? '✓' : toast.tone === 'error' ? '!' : toast.tone === 'warning' ? '!' : 'i'}
          </span>
          <div className="toast-copy">
            <strong>{toast.tone === 'success' ? 'Success' : toast.tone === 'error' ? 'Action failed' : toast.tone === 'warning' ? 'Action required' : 'MalTracer'}</strong>
            <span>{toast.text}</span>
          </div>
          <button type="button" className="toast-close" aria-label="Close notification" onClick={clearToast}>×</button>
        </div>
      )}
      <CyberCoreBackground />
      <aside className="sidebar">
        <div className="brand">
          <div className="brand-eye"><img src="/myfavicon.png" alt="MalTracer favicon" /></div>
          <div><strong>MalTracer</strong><span>Analysis Toolkit</span></div>
        </div>
        <nav className="nav">
          {navItems.map(([id, label]) => (
            <button key={id} className={view === id ? 'nav-item active' : 'nav-item'} onClick={() => setView(id)}>
              <Icon name={id === 'reports' ? 'report' : id} />
              <span>{label}</span>
            </button>
          ))}
        </nav>
        <div className="engine-card">
          <div className="engine-title">Engine Status</div>
          <div><span>Backend</span><b className={backendOnline ? 'ok' : 'optional'}>{backendOnline ? 'Connected' : 'Offline'}</b></div>
          <div title="Local YARA analysis is integrated into MalTracer. Runtime success is confirmed when a scan executes."><span>YARA</span><b className="ok">Integrated</b></div>
          <div title="EMBER ML is available as a separate analysis profile."><span>EMBER ML</span><b className="ok">Available</b></div>
          <div title="VirusTotal is an external hash-reputation service and depends on API configuration and network access."><span>VirusTotal</span><b className="optional">External API</b></div>
        </div>
      </aside>
      <main className="main">
        <header className="topbar">
          <div className="top-brand">
            <img className="top-logo" src={myLogo} alt="MalTracer logo" />
            <div>
              <div className="eyebrow">SAFE NON-EXECUTION MALWARE ANALYSIS</div>
              <h1>{pageTitle}</h1>
            </div>
          </div>
          <div className="top-actions">
            {view === 'report' && (<button className="btn secondary" onClick={() => setView('queue')}>← Back to Queue</button>)}
            <button className="btn primary" onClick={newAnalysis}><Icon name="plus"/>New Analysis</button>
          </div>
        </header>

        {view === 'dashboard' && (
          <section className="stack dashboard-stack">
            <section className="panel hero-panel">
              <div className="section-head">
                <div>
                  <div className="eyebrow">START A NEW SCAN</div>
                  <h2>Upload suspicious file</h2>
                  <p>MalTracer inspects the file without executing it.</p>
                </div>
                <span className="badge">48 MB max</span>
              </div>
              <input ref={fileInputRef} type="file" hidden onChange={handleFileInput} />
              <button type="button" className="upload-zone" onClick={chooseFile} onDragOver={(event) => event.preventDefault()} onDrop={handleDrop}>
                <div className="icon-cube cyan"><Icon name="upload"/></div>
                <strong>{selectedFile ? selectedFile.name : 'Drop sample here or click to browse'}</strong>
                <span>{selectedFile ? `${(selectedFile.size / 1024 / 1024).toFixed(2)} MB` : 'EXE · DLL · PDF · DOCX · XLS · VBS · ZIP'}</span>
              </button>
              <div className="recommend-head">
                <div><strong>Recommended</strong><span>Let MalTracer choose the relevant analysis modules.</span></div>
                <span className="badge">NEW</span>
              </div>
              <button className="smart-card" onClick={() => runSmartAnalysis()} disabled={isSubmitting}>
                <div className="icon-cube violet"><Icon name="spark"/></div>
                <div>
                  <strong>{isSubmitting ? 'Analyzing Selection...' : 'Smart Auto Analysis'}</strong>
                  <span>Inspect file signature → choose supported analyzer → queue integrated scan → report verdict</span>
                </div>
                <Icon name="chevron"/>
              </button>
            </section>
            <section className="panel">
              <div className="section-head compact">
                <div><h2>Manual Analysis Profiles</h2><p>Select the analysis mode that should process the uploaded file.</p></div>
              </div>
              <div className="profile-grid">
                {profiles.map((profile) => (
                  <button key={profile.id} className={selectedProfile === profile.id ? 'profile-card selected' : 'profile-card'} onClick={() => {
                    setSelectedProfile(profile.id); setMessage('')
                    const compatibilityError = profileCompatibilityError(selectedFile, profile.id)
                    if (compatibilityError) { showToast(compatibilityError, 'warning', 6200) }
                  }}>
                    <div className={`icon-cube ${profile.tone}`}><Icon name={profile.icon} /></div>
                    <strong>{profile.title}</strong>
                    <span>{profile.desc}</span>
                  </button>
                ))}
              </div>
              <div className="queue-action">
                <button className="btn primary" onClick={queueAnalysis} disabled={isSubmitting}>{isSubmitting ? 'Queuing Analysis...' : 'Queue Analysis'}</button>
              </div>
            </section>
            <section className="panel">
              <div className="section-head compact">
                <div><h2>Recent Scans</h2><p>Live jobs received from the backend.</p></div>
                <button className="btn secondary small" onClick={() => setView('history')}>View History</button>
              </div>
              <ScanTable scans={normalizedJobs.slice(0, 3)} onOpen={openReport} />
            </section>
          </section>
        )}

        {view === 'queue' && (<QueueView jobs={normalizedJobs} queueStats={queueStats} onOpenReport={openReport} message={message} />)}
        {view === 'history' && (<HistoryView scans={filteredJobs} search={search} setSearch={setSearch} onOpenReport={openReport} />)}
        {view === 'reports' && (<ReportsView scans={normalizedJobs} completedJobs={completedJobs} failedJobs={failedJobs} onOpenReport={openReport} />)}
        {view === 'report' && (<ReportView data={selectedReport} loading={reportLoading} error={reportError} tab={reportTab} setTab={setReportTab} />)}
      </main>
    </div>
  )
}

function ScanTable({ scans, onOpen }) {
  function statusConfig(status) {
    const key = String(status || '').toLowerCase()
    if (key === 'running') { return { key, canOpen: false, statusLabel: 'running', actionLabel: 'Analysis in progress', icon: 'spinner' } }
    if (key === 'queued') { return { key, canOpen: false, statusLabel: 'queued', actionLabel: 'Waiting in queue', icon: 'queued' } }
    if (key === 'completed') { return { key, canOpen: true, statusLabel: 'completed', actionLabel: 'Open Report →', icon: 'completed' } }
    if (key === 'failed') { return { key, canOpen: true, statusLabel: 'failed', actionLabel: 'View Error →', icon: 'failed' } }
    return { key: key || 'unknown', canOpen: false, statusLabel: status || 'unknown', actionLabel: 'Not ready', icon: 'queued' }
  }
  return (
    <div className="scan-table">
      <div className="scan-row head"><span>Sample</span><span>Profile</span><span>Status</span><span>Risk</span><span>Open</span></div>
      {scans.length === 0 ? (
        <div className="scan-row data">
          <span><b>No jobs yet</b><small>Backend queue is currently empty.</small></span>
          <span>—</span><span>—</span><span>—</span><span>—</span>
        </div>
      ) : (
        scans.map((scan) => {
          const config = statusConfig(scan.status)
          return (
            <button key={scan.id} className={`scan-row data ` + `scan-row-${config.key}`} disabled={!config.canOpen} onClick={() => { if (config.canOpen) { onOpen(scan) } }}>
              <span><b>{scan.name}</b><small>{scan.date}</small></span>
              <span>{scan.profile}</span>
              <span>
                <span className="job-status-wrap">
                  {config.icon === 'spinner' ? (<i className="mini-spinner"></i>) : (
                    <i className={`job-status-icon ` + `${config.icon}`}>
                      {config.icon === 'completed' ? '✓' : config.icon === 'failed' ? '!' : '○'}
                    </i>
                  )}
                  <em className="status">{config.statusLabel}</em>
                </span>
              </span>
              <span>{scan.risk}</span>
              <span className={`job-action ` + `${config.key === 'completed' ? 'ready' : config.key === 'failed' ? 'failed' : 'progress'}`}>
                {config.key === 'running' && (<i className="mini-spinner"></i>)}
                {config.actionLabel}
              </span>
            </button>
          )
        })
      )}
    </div>
  )
}

function QueueView({ jobs, queueStats, onOpenReport, message }) {
  return (
    <section className="stack">
      <section className="panel">
        <div className="section-head">
          <div>
            <div className="eyebrow">LIVE JOB CONTROL</div>
            <h2>Queue Monitor</h2>
            <p>Track queued, running and completed analysis jobs.</p>
          </div>
          <span className="badge live">Live</span>
        </div>
        <div className="metric-grid three">
          <Metric label="Queued" value={queueStats.queued ?? 0} />
          <Metric label="Running" value={queueStats.running ?? 0} />
          <Metric label="Total Jobs" value={queueStats.total ?? 0} />
        </div>
      </section>
      <section className="panel">
        <div className="section-head compact">
          <div><h2>All Jobs</h2><p>Live data from the MalTracer backend.</p></div>
        </div>
        {message && (<div className="queue-decision-banner">{message}</div>)}
        <ScanTable scans={jobs} onOpen={onOpenReport} />
      </section>
    </section>
  )
}

function HistoryView({ scans, search, setSearch, onOpenReport }) {
  return (
    <section className="stack">
      <section className="panel">
        <div className="section-head">
          <div>
            <div className="eyebrow">ANALYSIS RECORDS</div>
            <h2>Scan History</h2>
            <p>Search jobs maintained by the current backend session.</p>
          </div>
        </div>
        <input className="search-box" value={search} onChange={(event) => setSearch(event.target.value)} placeholder="Search sample, job ID, profile or status" />
      </section>
      <section className="panel"><ScanTable scans={scans} onOpen={onOpenReport} /></section>
    </section>
  )
}

function ReportsView({ scans, completedJobs, failedJobs, onOpenReport }) {
  return (
    <section className="stack">
      <section className="panel">
        <div className="section-head">
          <div>
            <div className="eyebrow">ANALYSIS OUTPUT</div>
            <h2>Reports</h2>
            <p>Open completed reports directly inside the React interface.</p>
          </div>
        </div>
        <div className="metric-grid three">
          <Metric label="Completed" value={completedJobs} />
          <Metric label="Total Jobs" value={scans.length} />
          <Metric label="Failed" value={failedJobs} />
        </div>
      </section>
      <section className="panel"><ScanTable scans={scans} onOpen={onOpenReport} /></section>
    </section>
  )
}

function ReportView({ data, loading, error }) {
  if (loading) { return (<section className="stack"><section className="panel"><div className="eyebrow">ANALYSIS REPORT</div><h2>Loading report...</h2><p>Retrieving structured report data from the MalTracer backend.</p></section></section>) }
  if (error) { return (<section className="stack"><section className="panel"><div className="eyebrow">REPORT ERROR</div><h2>Report could not be loaded</h2><p>{error}</p></section></section>) }
  if (!data) { return null }

  const job = data.job || {}
  const ui = data.report_ui || {}
  const summary = Array.isArray(ui.summary) ? ui.summary : []
  const categories = Array.isArray(ui.categories) ? ui.categories : []
  const yaraRules = Array.isArray(ui.matched_rules_rows) ? ui.matched_rules_rows : []
  const mitreRows = Array.isArray(ui.mitre_rows) ? ui.mitre_rows : []
  const patterns = Array.isArray(ui.interesting_patterns) ? ui.interesting_patterns : []
  const sourcePatternRows = Array.isArray(ui.source_pattern_rows) ? ui.source_pattern_rows : []
  const sections = Array.isArray(ui.sections) ? ui.sections : []
  const extraPanels = Array.isArray(ui.extra_panels) ? ui.extra_panels : []
  const windowsApis = Array.isArray(ui.windows_api_categories) ? ui.windows_api_categories : []
  const hashes = Array.isArray(ui.hashes) ? ui.hashes : []
  const vt = ui.vt_section || {}
  const permissions = ui.permissions_section || {}
  const scriptAnalysis = ui.script_analysis_section || {}
  const archiveSection = ui.archive_section || {}
  const packerSection = ui.packer_section || {}
  const iocSection = ui.ioc_section || {}
  const languageSection = ui.language_section || {}

  const riskAvailable = ui.final_risk_val !== null && ui.final_risk_val !== undefined && ui.final_risk_val !== '' && Number.isFinite(Number(ui.final_risk_val))
  const finalRisk = riskAvailable ? Number(ui.final_risk_val) : null
  const mlAvailable = Boolean(ui.ml_available)
  const mlRaw = Math.max(0, Math.min(100, Number(ui.ml_raw) || 0))
  const behaviorPercent = Math.max(0, Math.min(100, (Number(ui.behavior_score_val) || 0) * 100))
  const packerPercent = Math.max(0, Math.min(100, (Number(ui.packer_score_val) || 0) * 100))

  const resolvedProfileKey = String(job.resolved_preset_key || job.preset_key || '').toLowerCase()
  const isBehavioral = resolvedProfileKey === 'behavioral'
  const isStandard = resolvedProfileKey === 'analyze'
  const isDocument = resolvedProfileKey === 'docs'
  const isArchive = resolvedProfileKey === 'archive'
  const isPacker = resolvedProfileKey === 'packer'
  const isDomain = resolvedProfileKey === 'domain'
  const isLanguage = resolvedProfileKey === 'lang'

  function summaryValue(...labels) {
    const wanted = labels.map((label) => String(label).trim().toLowerCase())
    const match = summary.find((item) => wanted.includes(String(item?.label || '').trim().toLowerCase()))
    return match?.value ?? ''
  }

  const targetType = summaryValue('Target Type') || 'Unknown'
  const sha256 = summaryValue('SHA-256', 'SHA256') || hashes.find((item) => String(item?.label || '').toLowerCase() === 'sha256')?.value || 'N/A'
  const malwareFamily = summaryValue('Malware Family', 'ML Family Cluster', 'Family Cluster') || 'N/A'
  const malwareName = summaryValue('Malware Name') || job.vt_threat_label || 'N/A'
  const heuristicNotes = Array.isArray(ui.heuristic_notes) ? ui.heuristic_notes : []

  const modelMap = { Win32: 'EMBER2024 Win32', Win64: 'EMBER2024 Win64', DotNet: 'EMBER2024 .NET', ELF: 'EMBER2024 ELF', APK: 'EMBER2024 APK', PDF: 'EMBER2024 PDF', PE: 'EMBER2024 PE' }
  const modelUsed = modelMap[targetType] || 'EMBER2024'

  const riskLabel = !riskAvailable ? 'Risk N/A' : finalRisk >= 70 ? 'High Risk' : finalRisk >= 40 ? 'Needs Review' : finalRisk >= 20 ? 'Low–Moderate Risk' : 'Low Risk'

  const duplicateCoreTitles = new Set(['categories', 'interesting string patterns', 'matched rules', 'virustotal file'])
  const filteredExtraPanels = extraPanels.filter((panel) => !duplicateCoreTitles.has(String(panel?.title || '').trim().toLowerCase()))
  const hasCoreFindings = sections.length > 0 || filteredExtraPanels.length > 0 || archiveSection.available || packerSection.available || iocSection.available || languageSection.available

  function ReportSection({ title, children, className = '' }) {
    return (<section className={`panel msr-section ${className}`}><h2>{title}</h2>{children}</section>)
  }

  function PlainSummary() {
    if (summary.length === 0) { return null }
    const seen = new Set()
    const dedupedRows = summary.filter((item) => {
      const key = String(item?.label || '').trim().toLowerCase()
      if (!key) { return false }
      if (key === 'sha256' && seen.has('sha-256')) { return false }
      if (key === 'sha-256') { seen.add('sha-256') }
      if (seen.has(key)) { return false }
      seen.add(key)
      return true
    })
    const standardSummaryOrder = ['Target Type', 'Malware Name', 'Filename', 'Final Contextual Risk']
    const rows = isStandard ? standardSummaryOrder.map((label) => dedupedRows.find((item) => String(item?.label || '').trim().toLowerCase() === label.toLowerCase())).filter(Boolean) : dedupedRows
    return (
      <ReportSection title="Analysis Summary" className="maltracer-summary-section">
        <div className="maltracer-summary-layout">
          <aside className="maltracer-summary-gauge-card">
            <div className="maltracer-summary-gauge-head">Risk Score</div>
            <div className="maltracer-summary-gauge-body">
              <RiskGauge value={finalRisk} available={riskAvailable} />
              <span className={`maltracer-risk-pill ` + `${!riskAvailable ? 'na' : finalRisk >= 70 ? 'high' : finalRisk >= 40 ? 'medium' : 'low'}`}>{riskAvailable ? riskLabel : 'Risk N/A'}</span>
              <small>{riskAvailable ? 'Final contextual risk' : 'This profile does not produce a contextual risk score'}</small>
            </div>
          </aside>
          <dl className="msr-rail-list">
            {rows.map((item, index) => (
              <div key={`${item.label}-${index}`}>
                <dt>{item.label}</dt>
                <dd className={item.severity ? `risk-${item.severity}` : ''}>{item.value}</dd>
              </div>
            ))}
          </dl>
        </div>
      </ReportSection>
    )
  }

  function panelByTitle(title) {
    const wanted = String(title || '').trim().toLowerCase()
    return extraPanels.find((panel) => String(panel?.title || '').trim().toLowerCase() === wanted) || null
  }

  function panelItemValue(panel, key) {
    if (!panel || !Array.isArray(panel.items)) { return '' }
    const wanted = String(key || '').trim().toLowerCase()
    const row = panel.items.find((item) => String(item || '').trim().toLowerCase().startsWith(`${wanted}:`))
    if (!row) { return '' }
    return String(row).split(':').slice(1).join(':').trim()
  }

  const macroPanel = panelByTitle('Macros')
  const decryptionPanel = panelByTitle('Decryption')
  const documentScriptCategories = Array.isArray(scriptAnalysis.categories) ? scriptAnalysis.categories : []
  const documentScriptFindingCount = documentScriptCategories.reduce((total, category) => total + (Number(category?.count) || 0), 0)
  const documentYaraCount = Number(summaryValue('Matched YARA')) || yaraRules.length || 0
  const documentEmbeddedCount = Number(summaryValue('Embedded Files')) || 0
  const documentUrlCount = Number(summaryValue('Extracted URLs')) || (Array.isArray(iocSection.urls) ? iocSection.urls.length : 0)
  const documentLanguage = scriptAnalysis.language || languageSection.primary_language || 'Unknown'
  const macroExtractedRaw = panelItemValue(macroPanel, 'extracted')
  const macroVbaRaw = panelItemValue(macroPanel, 'vba')
  const macroXlmRaw = panelItemValue(macroPanel, 'xlm')
  const decryptionAttemptedRaw = panelItemValue(decryptionPanel, 'attempted')
  const decryptionSuccessRaw = panelItemValue(decryptionPanel, 'success')

  function yesNoValue(raw) {
    const normalized = String(raw || '').trim().toLowerCase()
    if (normalized === 'true') { return 'Yes' }
    if (normalized === 'false') { return 'No' }
    return raw || 'N/A'
  }

  function DocumentSummaryReport() {
    return (
      <ReportSection title="Analysis Summary" className="maltracer-summary-section maltracer-document-summary">
        <div className="maltracer-summary-layout">
          <aside className="maltracer-summary-gauge-card">
            <div className="maltracer-summary-gauge-head">Risk Score</div>
            <div className="maltracer-summary-gauge-body">
              <RiskGauge value={finalRisk} available={riskAvailable} />
              <span className={`maltracer-risk-pill ` + `${!riskAvailable ? 'na' : finalRisk >= 70 ? 'high' : finalRisk >= 40 ? 'medium' : 'low'}`}>{riskAvailable ? riskLabel : 'Risk N/A'}</span>
              <small>{riskAvailable ? 'Final contextual risk' : 'Document profile does not assign a contextual risk score'}</small>
            </div>
          </aside>
          <div className="document-summary-content">
            <div className="document-summary-grid">
              <Metric label="Language / Type" value={documentLanguage} />
              <Metric label="Script Findings" value={documentScriptFindingCount} />
              <Metric label="Matched YARA" value={documentYaraCount} />
              <Metric label="Embedded Files" value={documentEmbeddedCount} />
              <Metric label="Extracted URLs" value={documentUrlCount} />
            </div>
            <dl className="msr-rail-list document-summary-identity">
              <div><dt>Filename</dt><dd>{job.sample_name || summaryValue('Filename') || 'N/A'}</dd></div>
              <div><dt>Malware Name</dt><dd>{malwareName}</dd></div>
            </dl>
          </div>
        </div>
      </ReportSection>
    )
  }

  function DocumentFindingsReport() {
    const createObjectCount = Array.isArray(scriptAnalysis.createobject_values) ? scriptAnalysis.createobject_values.length : 0
    const shellCount = Array.isArray(scriptAnalysis.shell_commands) ? scriptAnalysis.shell_commands.length : 0
    const decodedCount = Array.isArray(scriptAnalysis.decoded_payload_hints) ? scriptAnalysis.decoded_payload_hints.length : 0
    return (
      <ReportSection title="Document & Script Findings" className="maltracer-document-findings">
        <p className="msr-section-note">Static document and script evidence only; no file execution is performed.</p>
        <div className="document-finding-grid">
          <section className="document-finding-card">
            <header><div><strong>Script Profile</strong><span>Detected static language and script indicators</span></div><b>{documentLanguage}</b></header>
            <div className="document-finding-metrics">
              <div><span>Pattern Findings</span><strong>{documentScriptFindingCount}</strong></div>
              <div><span>CreateObject</span><strong>{createObjectCount}</strong></div>
              <div><span>Shell Commands</span><strong>{shellCount}</strong></div>
              <div><span>Decoded Hints</span><strong>{decodedCount}</strong></div>
              <div><span>VBE Encoded</span><strong>{scriptAnalysis.vbe_encoded ? 'Yes' : 'No'}</strong></div>
            </div>
          </section>
          <section className="document-finding-card">
            <header><div><strong>Macro Evidence</strong><span>Macro extraction and VBA/XLM evidence</span></div><b>{macroExtractedRaw ? yesNoValue(macroExtractedRaw) : 'N/A'}</b></header>
            <div className="document-kv-rows">
              <div><span>Extracted</span><strong>{yesNoValue(macroExtractedRaw)}</strong></div>
              <div><span>VBA</span><strong>{macroVbaRaw || '0 items'}</strong></div>
              <div><span>XLM</span><strong>{macroXlmRaw || '0 items'}</strong></div>
            </div>
          </section>
          <section className="document-finding-card">
            <header><div><strong>Decryption</strong><span>Static document decryption workflow status</span></div><b>{decryptionAttemptedRaw ? (String(decryptionAttemptedRaw).toLowerCase() === 'true' ? 'Attempted' : 'Not Attempted') : 'N/A'}</b></header>
            <div className="document-kv-rows">
              <div><span>Attempted</span><strong>{yesNoValue(decryptionAttemptedRaw)}</strong></div>
              <div><span>Success</span><strong>{yesNoValue(decryptionSuccessRaw)}</strong></div>
            </div>
          </section>
          <section className="document-finding-card">
            <header><div><strong>IOC / Embedded Evidence</strong><span>Extracted static indicators from the document</span></div><b>{documentUrlCount + documentEmbeddedCount}</b></header>
            <div className="document-kv-rows">
              <div><span>URLs</span><strong>{documentUrlCount}</strong></div>
              <div><span>Embedded Files</span><strong>{documentEmbeddedCount}</strong></div>
              <div><span>YARA Rules</span><strong>{documentYaraCount}</strong></div>
            </div>
          </section>
        </div>
        {documentScriptCategories.length > 0 ? (
          <div className="document-pattern-grid">
            {documentScriptCategories.map((category, index) => (
              <section className="msr-signal-card" key={`${category.name}-${index}`}>
                <header><h3>{category.name}</h3><span>{category.count || 0}</span></header>
                <ul>{(category.hits || []).map((hit, hitIndex) => (<li key={hitIndex}><code>{hit}</code></li>))}</ul>
              </section>
            ))}
          </div>
        ) : (
          <div className="document-clean-note">No executable script-pattern categories were identified by the available static checks.</div>
        )}
        {createObjectCount > 0 && (
          <details className="msr-inner-details document-detail-block">
            <summary>CreateObject Values ({createObjectCount})</summary>
            <div className="msr-inner-body"><SimpleList items={scriptAnalysis.createobject_values} /></div>
          </details>
        )}
        {shellCount > 0 && (
          <details className="msr-inner-details document-detail-block">
            <summary>Shell Commands ({shellCount})</summary>
            <div className="msr-inner-body"><SimpleList items={scriptAnalysis.shell_commands} /></div>
          </details>
        )}
        {decodedCount > 0 && (
          <details className="msr-inner-details document-detail-block">
            <summary>Decoded Payload Hints ({decodedCount})</summary>
            <div className="msr-inner-body"><SimpleList items={scriptAnalysis.decoded_payload_hints} /></div>
          </details>
        )}
      </ReportSection>
    )
  }

  function DocumentIocReport() {
    if (!iocSection.available) { return null }
    const groups = [['URLs', iocSection.urls], ['Domains', iocSection.domains], ['IP Addresses', iocSection.ips], ['Emails', iocSection.emails], ['File Paths', iocSection.file_paths], ['Hashes', iocSection.hashes]].filter(([, values]) => Array.isArray(values) && values.length > 0)
    if (groups.length === 0) { return null }
    return (
      <ReportSection title="Extracted IOCs" className="maltracer-document-ioc">
        <p className="msr-section-note">Extracted values are supporting evidence and are not proof of maliciousness.</p>
        <div className="msr-signal-grid">
          {groups.map(([title, values]) => (
            <section className="msr-signal-card" key={title}>
              <header><h3>{title}</h3><span>{values.length}</span></header>
              <ul>{values.map((value, index) => (<li key={index}>{value}</li>))}</ul>
            </section>
          ))}
        </div>
      </ReportSection>
    )
  }

  function DocumentTechnicalEvidence() {
    if (!isDocument) { return null }
    const rawPanels = filteredExtraPanels.filter((panel) => !['macros', 'decryption'].includes(String(panel?.title || '').trim().toLowerCase()))
    const hasEvidence = hashes.length > 0 || sourcePatternRows.length > 0 || rawPanels.length > 0
    if (!hasEvidence) { return null }
    return (
      <section className="panel msr-section maltracer-document-tech">
        <details className="msr-tech-details">
          <summary><span>Document Technical Evidence</span><small>Hashes and raw supporting details</small></summary>
          <div className="msr-tech-body">
            {hashes.length > 0 && (<details className="msr-inner-details"><summary>File Hashes ({hashes.length})</summary><div className="msr-inner-body"><KeyValueList items={hashes} /></div></details>)}
            {sourcePatternRows.length > 0 && (
              <details className="msr-inner-details">
                <summary>Source Pattern Findings ({sourcePatternRows.length})</summary>
                <div className="msr-inner-body">
                  <div className="msr-signal-grid">
                    {sourcePatternRows.map((row, index) => (
                      <section className="msr-signal-card" key={`${row.file_name}-${index}`}>
                        <header><h3>{row.file_name}</h3><span>{row.pattern_count || 0}</span></header>
                        <ul>{(row.patterns || []).map((pattern, patternIndex) => (<li key={patternIndex}>{pattern}</li>))}</ul>
                      </section>
                    ))}
                  </div>
                </div>
              </details>
            )}
            {rawPanels.map((panel, index) => (
              <details className="msr-inner-details" key={`${panel.title}-${index}`}>
                <summary>{panel.title} ({panel.count ?? (Array.isArray(panel.items) ? panel.items.length : 0)})</summary>
                <div className="msr-inner-body"><SimpleList items={Array.isArray(panel.items) ? panel.items : []} /></div>
              </details>
            ))}
          </div>
        </details>
      </section>
    )
  }

  const archiveMembers = Array.isArray(archiveSection.members) ? archiveSection.members : []
  const archiveScannedMembersPanel = filteredExtraPanels.find((panel) => String(panel?.title || '').trim().toLowerCase() === 'scanned members') || null
  const archiveRulesByMemberPanel = filteredExtraPanels.find((panel) => String(panel?.title || '').trim().toLowerCase() === 'matched rules by member') || null
  const archiveMatchedRulesPanel = filteredExtraPanels.find((panel) => String(panel?.title || '').trim().toLowerCase() === 'matched rules') || null
  const archiveMatchedYaraCount = Number(summaryValue('Matched YARA')) || yaraRules.length || 0

  function ArchiveSummaryReport() {
    return (
      <ReportSection title="Analysis Summary" className="maltracer-summary-section maltracer-archive-summary">
        <div className="maltracer-summary-layout">
          <aside className="maltracer-summary-gauge-card">
            <div className="maltracer-summary-gauge-head">Risk Score</div>
            <div className="maltracer-summary-gauge-body">
              <RiskGauge value={finalRisk} available={riskAvailable} />
              <span className={`maltracer-risk-pill ` + `${!riskAvailable ? 'na' : finalRisk >= 70 ? 'high' : finalRisk >= 40 ? 'medium' : 'low'}`}>{riskAvailable ? riskLabel : 'Risk N/A'}</span>
              <small>{riskAvailable ? 'Final contextual risk' : 'Archive profile does not assign a contextual risk score'}</small>
            </div>
          </aside>
          <div className="archive-summary-content">
            <div className="archive-summary-grid">
              <Metric label="Archive Type" value={archiveSection.archive_type || summaryValue('Target Type') || 'Unknown'} />
              <Metric label="Members" value={Number(archiveSection.member_count) || archiveMembers.length || 0} />
              <Metric label="Files" value={Number(archiveSection.file_count) || 0} />
              <Metric label="Directories" value={Number(archiveSection.directory_count) || 0} />
              <Metric label="Matched YARA" value={archiveMatchedYaraCount} />
            </div>
            <dl className="msr-rail-list archive-summary-identity">
              <div><dt>Filename</dt><dd>{job.sample_name || summaryValue('Filename') || 'N/A'}</dd></div>
              <div><dt>Malware Name</dt><dd>{malwareName}</dd></div>
            </dl>
          </div>
        </div>
      </ReportSection>
    )
  }

  function ArchiveContentsReport() {
    if (!archiveSection.available) { return null }
    return (
      <ReportSection title="Archive Inspection" className="maltracer-archive-findings">
        <p className="msr-section-note">Archive members are inspected statically without executing extracted content.</p>
        <div className="archive-overview-strip">
          <div><span>Archive Type</span><strong>{archiveSection.archive_type || 'Unknown'}</strong></div>
          <div><span>Total Members</span><strong>{Number(archiveSection.member_count) || archiveMembers.length || 0}</strong></div>
          <div><span>Files</span><strong>{Number(archiveSection.file_count) || 0}</strong></div>
          <div><span>Directories</span><strong>{Number(archiveSection.directory_count) || 0}</strong></div>
        </div>
        {archiveMembers.length > 0 ? (
          <div className="archive-member-table-wrap">
            <table className="msr-data-table archive-member-table">
              <thead><tr><th>Member</th><th>Size</th><th>Type</th></tr></thead>
              <tbody>
                {archiveMembers.map((item, index) => (
                  <tr key={index}>
                    <td>{item.name || 'entry'}</td>
                    <td>{Number(item.size) || 0} bytes</td>
                    <td>{item.is_dir ? 'Directory' : 'File'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="archive-clean-note">No archive members were returned by the analyzer.</div>
        )}
        {Array.isArray(archiveScannedMembersPanel?.items) && archiveScannedMembersPanel.items.length > 0 && (
          <details className="msr-inner-details archive-detail-block">
            <summary>Scanned Members ({archiveScannedMembersPanel.count ?? archiveScannedMembersPanel.items.length})</summary>
            <div className="msr-inner-body"><SimpleList items={archiveScannedMembersPanel.items} /></div>
          </details>
        )}
        {Array.isArray(archiveRulesByMemberPanel?.items) && archiveRulesByMemberPanel.items.length > 0 && (
          <details className="msr-inner-details archive-detail-block">
            <summary>Matched Rules by Member ({archiveRulesByMemberPanel.count ?? archiveRulesByMemberPanel.items.length})</summary>
            <div className="msr-inner-body"><SimpleList items={archiveRulesByMemberPanel.items} /></div>
          </details>
        )}
        {Array.isArray(archiveMatchedRulesPanel?.items) && archiveMatchedRulesPanel.items.length > 0 && (
          <details className="msr-inner-details archive-detail-block">
            <summary>Archive Rule Summary ({archiveMatchedRulesPanel.count ?? archiveMatchedRulesPanel.items.length})</summary>
            <div className="msr-inner-body"><SimpleList items={archiveMatchedRulesPanel.items} /></div>
          </details>
        )}
      </ReportSection>
    )
  }

  function ArchiveTechnicalEvidence() {
    if (!isArchive) { return null }
    const excluded = new Set(['archive contents', 'scanned members', 'matched rules by member', 'matched rules'])
    const rawPanels = filteredExtraPanels.filter((panel) => !excluded.has(String(panel?.title || '').trim().toLowerCase()))
    const hasEvidence = hashes.length > 0 || rawPanels.length > 0
    if (!hasEvidence) { return null }
    return (
      <section className="panel msr-section maltracer-archive-tech">
        <details className="msr-tech-details">
          <summary><span>Archive Technical Evidence</span><small>File hashes and raw supporting details</small></summary>
          <div className="msr-tech-body">
            {hashes.length > 0 && (<details className="msr-inner-details"><summary>File Hashes ({hashes.length})</summary><div className="msr-inner-body"><KeyValueList items={hashes} /></div></details>)}
            {rawPanels.map((panel, index) => (
              <details className="msr-inner-details" key={`${panel.title}-${index}`}>
                <summary>{panel.title} ({panel.count ?? (Array.isArray(panel.items) ? panel.items.length : 0)})</summary>
                <div className="msr-inner-body"><SimpleList items={Array.isArray(panel.items) ? panel.items : []} /></div>
              </details>
            ))}
          </div>
        </details>
      </section>
    )
  }

  const packerYaraHitCount = yaraRules.reduce((total, rule) => total + (Number(rule?.count) || 0), 0)
  const packerMatchedYaraCount = Number(summaryValue('Matched YARA')) || yaraRules.length || 0

  function PackerSummaryReport() {
    return (
      <ReportSection title="Analysis Summary" className="maltracer-summary-section maltracer-packer-summary">
        <div className="maltracer-summary-layout">
          <aside className="maltracer-summary-gauge-card">
            <div className="maltracer-summary-gauge-head">Risk Score</div>
            <div className="maltracer-summary-gauge-body">
              <RiskGauge value={finalRisk} available={riskAvailable} />
              <span className={`maltracer-risk-pill ` + `${!riskAvailable ? 'na' : finalRisk >= 70 ? 'high' : finalRisk >= 40 ? 'medium' : 'low'}`}>{riskAvailable ? riskLabel : 'Risk N/A'}</span>
              <small>{riskAvailable ? 'Final contextual risk' : 'Packer profile does not assign a contextual risk score'}</small>
            </div>
          </aside>
          <div className="packer-summary-content">
            <div className="packer-summary-grid">
              <Metric label="Packed Verdict" value={packerSection.packed ? 'Packed' : 'Not Packed'} />
              <Metric label="String Packer Hits" value={Number(packerSection.string_hits_count) || 0} />
              <Metric label="Matched YARA" value={packerMatchedYaraCount} />
              <Metric label="YARA Evidence Hits" value={packerYaraHitCount} />
              <Metric label="YARA Evidence Only" value={packerSection.yara_evidence_only ? 'Yes' : 'No'} />
            </div>
            <dl className="msr-rail-list packer-summary-identity">
              <div><dt>Filename</dt><dd>{job.sample_name || summaryValue('Filename') || 'N/A'}</dd></div>
              <div><dt>Malware Name</dt><dd>{malwareName}</dd></div>
            </dl>
          </div>
        </div>
      </ReportSection>
    )
  }

  function PackerAssessmentReport() {
    if (!packerSection.available) { return null }
    const hasDirectPackerSignal = Boolean(packerSection.packed) || (Number(packerSection.string_hits_count) || 0) > 0
    return (
      <ReportSection title="Packer / Obfuscation Assessment" className="maltracer-packer-assessment">
        <p className="msr-section-note">Static packer and obfuscation indicators only; no file execution is performed.</p>
        <div className="packer-verdict-layout">
          <section className={`packer-verdict-card ` + `${packerSection.packed ? 'packed' : 'not-packed'}`}>
            <div className="packer-verdict-icon">{packerSection.packed ? '!' : '✓'}</div>
            <div>
              <span>Static Verdict</span>
              <strong>{packerSection.packed ? 'Packed' : 'Not Packed'}</strong>
              <small>{hasDirectPackerSignal ? 'Direct static packer indicators were identified.' : 'No direct static packer signature was identified.'}</small>
            </div>
          </section>
          <div className="packer-evidence-grid">
            <div><span>String Packer Hits</span><strong>{Number(packerSection.string_hits_count) || 0}</strong></div>
            <div><span>YARA Rules</span><strong>{packerMatchedYaraCount}</strong></div>
            <div><span>YARA Evidence Hits</span><strong>{packerYaraHitCount}</strong></div>
            <div><span>YARA Evidence Only</span><strong>{packerSection.yara_evidence_only ? 'Yes' : 'No'}</strong></div>
          </div>
        </div>
        <div className="packer-interpretation-note">
          {packerSection.yara_evidence_only ? 'YARA matches are supporting evidence only and are not proof that the file is packed.' : 'Packer verdict is based on the combined static indicators returned by this profile.'}
        </div>
      </ReportSection>
    )
  }

  function PackerYaraReport() {
    if (yaraRules.length === 0) { return null }
    const previewLimit = 8
    return (
      <ReportSection title="Supporting YARA Evidence" className="maltracer-packer-yara">
        <p className="msr-section-note">Rule matches below are supporting static evidence. Compiler/build signatures can match benign software and are not proof of packing.</p>
        <div className="packer-yara-grid">
          {yaraRules.map((rule, index) => {
            const samples = Array.isArray(rule.samples) ? rule.samples : []
            const visibleSamples = samples.slice(0, previewLimit)
            const remainingSamples = samples.slice(previewLimit)
            return (
              <section className="packer-yara-card" key={`${rule.name}-${index}`}>
                <header><div><strong>{rule.name}</strong><span>Supporting YARA evidence</span></div><b>{rule.count || 0} hits</b></header>
                {visibleSamples.length > 0 && (
                  <div className="msr-table-wrap">
                    <table className="msr-data-table compact">
                      <thead><tr><th>Offset</th><th>Pattern</th></tr></thead>
                      <tbody>
                        {visibleSamples.map((sample, sampleIndex) => (
                          <tr key={sampleIndex}><td>{sample.offset || '—'}</td><td>{sample.pattern || '—'}</td></tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
                {remainingSamples.length > 0 && (
                  <details className="packer-yara-more">
                    <summary>View remaining {remainingSamples.length} hits</summary>
                    <div className="msr-table-wrap">
                      <table className="msr-data-table compact">
                        <tbody>
                          {remainingSamples.map((sample, sampleIndex) => (
                            <tr key={sampleIndex}><td>{sample.offset || '—'}</td><td>{sample.pattern || '—'}</td></tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  </details>
                )}
              </section>
            )
          })}
        </div>
      </ReportSection>
    )
  }

  function PackerTechnicalEvidence() {
    if (!isPacker) { return null }
    const excluded = new Set(['matched rules', 'packer / obfuscation'])
    const rawPanels = filteredExtraPanels.filter((panel) => !excluded.has(String(panel?.title || '').trim().toLowerCase()))
    const hasEvidence = hashes.length > 0 || rawPanels.length > 0
    if (!hasEvidence) { return null }
    return (
      <section className="panel msr-section maltracer-packer-tech">
        <details className="msr-tech-details">
          <summary><span>Packer Technical Evidence</span><small>File hashes and raw supporting details</small></summary>
          <div className="msr-tech-body">
            {hashes.length > 0 && (<details className="msr-inner-details"><summary>File Hashes ({hashes.length})</summary><div className="msr-inner-body"><KeyValueList items={hashes} /></div></details>)}
            {rawPanels.map((panel, index) => (
              <details className="msr-inner-details" key={`${panel.title}-${index}`}>
                <summary>{panel.title} ({panel.count ?? (Array.isArray(panel.items) ? panel.items.length : 0)})</summary>
                <div className="msr-inner-body"><SimpleList items={Array.isArray(panel.items) ? panel.items : []} /></div>
              </details>
            ))}
          </div>
        </details>
      </section>
    )
  }

  const domainUrls = Array.isArray(iocSection.urls) ? iocSection.urls : []
  const domainIps = Array.isArray(iocSection.ips) ? iocSection.ips : []
  const domainDomains = Array.isArray(iocSection.domains) ? iocSection.domains : []
  const domainEmails = Array.isArray(iocSection.emails) ? iocSection.emails : []
  const domainFilePaths = Array.isArray(iocSection.file_paths) ? iocSection.file_paths : []
  const domainHashes = Array.isArray(iocSection.hashes) ? iocSection.hashes : []
  const domainTotalIocs = domainUrls.length + domainIps.length + domainDomains.length + domainEmails.length + domainFilePaths.length + domainHashes.length

  function DomainSummaryReport() {
    return (
      <ReportSection title="Analysis Summary" className="maltracer-summary-section maltracer-domain-summary">
        <div className="maltracer-summary-layout">
          <aside className="maltracer-summary-gauge-card">
            <div className="maltracer-summary-gauge-head">Risk Score</div>
            <div className="maltracer-summary-gauge-body">
              <RiskGauge value={finalRisk} available={riskAvailable} />
              <span className={`maltracer-risk-pill ` + `${!riskAvailable ? 'na' : finalRisk >= 70 ? 'high' : finalRisk >= 40 ? 'medium' : 'low'}`}>{riskAvailable ? riskLabel : 'Risk N/A'}</span>
              <small>{riskAvailable ? 'Final contextual risk' : 'Domain / IOC profile does not assign a contextual risk score'}</small>
            </div>
          </aside>
          <div className="domain-summary-content">
            <div className="domain-summary-grid">
              <Metric label="URLs" value={domainUrls.length} />
              <Metric label="IP Addresses" value={domainIps.length} />
              <Metric label="Domains" value={domainDomains.length} />
              <Metric label="Emails" value={domainEmails.length} />
              <Metric label="File Paths" value={domainFilePaths.length} />
            </div>
            <dl className="msr-rail-list domain-summary-identity">
              <div><dt>Filename</dt><dd>{job.sample_name || summaryValue('Filename') || 'N/A'}</dd></div>
              <div><dt>Total Extracted Indicators</dt><dd>{domainTotalIocs}</dd></div>
            </dl>
          </div>
        </div>
      </ReportSection>
    )
  }

  function DomainIocReport() {
    const groups = [
      { title: 'URLs', values: domainUrls, accent: 'url' },
      { title: 'IP Addresses', values: domainIps, accent: 'ip' },
      { title: 'Domains', values: domainDomains, accent: 'domain' },
      { title: 'Emails', values: domainEmails, accent: 'email' },
      { title: 'File Paths', values: domainFilePaths, accent: 'path' },
      { title: 'Hashes', values: domainHashes, accent: 'hash' },
    ].filter((group) => group.values.length > 0)
    return (
      <ReportSection title="Extracted IOC Evidence" className="maltracer-domain-findings">
        <p className="msr-section-note">Values are extracted statically. Their presence is supporting evidence and does not by itself prove maliciousness.</p>
        {groups.length > 0 ? (
          <div className="domain-ioc-grid">
            {groups.map((group) => (
              <section className={`domain-ioc-card ` + `domain-ioc-${group.accent}`} key={group.title}>
                <header><div><strong>{group.title}</strong><span>Extracted static indicators</span></div><b>{group.values.length}</b></header>
                <ul>{group.values.map((value, index) => (<li key={index}><code>{value}</code></li>))}</ul>
              </section>
            ))}
          </div>
        ) : (
          <div className="domain-clean-note">No URL, IP, domain, email, file-path or hash indicators were extracted.</div>
        )}
        <div className="domain-interpretation-note">IOC extraction is syntactic/static analysis. Analysts should validate reputation and context separately before treating an indicator as malicious.</div>
      </ReportSection>
    )
  }

  function DomainTechnicalEvidence() {
    if (!isDomain) { return null }
    const excluded = new Set(['urls', 'ip addresses', 'domains', 'emails', 'extracted urls', 'ioc matches'])
    const rawPanels = filteredExtraPanels.filter((panel) => !excluded.has(String(panel?.title || '').trim().toLowerCase()))
    const hasEvidence = hashes.length > 0 || rawPanels.length > 0
    if (!hasEvidence) { return null }
    return (
      <section className="panel msr-section maltracer-domain-tech">
        <details className="msr-tech-details">
          <summary><span>IOC Technical Evidence</span><small>File hashes and raw supporting details</small></summary>
          <div className="msr-tech-body">
            {hashes.length > 0 && (<details className="msr-inner-details"><summary>File Hashes ({hashes.length})</summary><div className="msr-inner-body"><KeyValueList items={hashes} /></div></details>)}
            {rawPanels.map((panel, index) => (
              <details className="msr-inner-details" key={`${panel.title}-${index}`}>
                <summary>{panel.title} ({panel.count ?? (Array.isArray(panel.items) ? panel.items.length : 0)})</summary>
                <div className="msr-inner-body"><SimpleList items={Array.isArray(panel.items) ? panel.items : []} /></div>
              </details>
            ))}
          </div>
        </details>
      </section>
    )
  }

  const languageDetectedPanel = filteredExtraPanels.find((panel) => String(panel?.title || '').trim().toLowerCase() === 'detected languages') || null
  const languageFileProfilePanel = filteredExtraPanels.find((panel) => String(panel?.title || '').trim().toLowerCase() === 'file profile') || null
  const languageDetectedCount = Number(summaryValue('Detected Languages')) || (Array.isArray(languageDetectedPanel?.items) ? languageDetectedPanel.items.length : 0) || (languageSection.available ? 1 : 0)
  const languagePrimary = languageSection.primary_language || 'Unknown'
  const languageEvidenceBasis = String(languageSection.evidence_basis || 'unknown').replaceAll('_', ' ')
  const languagePatternHits = Number(languageSection.pattern_hits) || 0
  const languageRelativeShare = Number(languageSection.relative_score_share) || 0

  function LanguageSummaryReport() {
    return (
      <ReportSection title="Analysis Summary" className="maltracer-summary-section maltracer-language-summary">
        <div className="maltracer-summary-layout">
          <aside className="maltracer-summary-gauge-card">
            <div className="maltracer-summary-gauge-head">Risk Score</div>
            <div className="maltracer-summary-gauge-body">
              <RiskGauge value={finalRisk} available={riskAvailable} />
              <span className={`maltracer-risk-pill ` + `${!riskAvailable ? 'na' : finalRisk >= 70 ? 'high' : finalRisk >= 40 ? 'medium' : 'low'}`}>{riskAvailable ? riskLabel : 'Risk N/A'}</span>
              <small>{riskAvailable ? 'Final contextual risk' : 'Language profile does not assign a contextual risk score'}</small>
            </div>
          </aside>
          <div className="language-summary-content">
            <div className="language-summary-grid">
              <Metric label="Primary Language" value={languagePrimary} />
              <Metric label="Evidence Basis" value={languageEvidenceBasis} />
              <Metric label="Pattern Hits" value={languagePatternHits} />
              <Metric label="Relative Score Share" value={`${languageRelativeShare}%`} />
              <Metric label="Detected Languages" value={languageDetectedCount} />
            </div>
            <dl className="msr-rail-list language-summary-identity">
              <div><dt>Filename</dt><dd>{job.sample_name || summaryValue('Filename') || 'N/A'}</dd></div>
              <div><dt>Interpretation</dt><dd>Static programming-language fingerprint</dd></div>
            </dl>
          </div>
        </div>
      </ReportSection>
    )
  }

  function LanguageFingerprintReport() {
    if (!languageSection.available) { return null }
    return (
      <ReportSection title="Language Fingerprint" className="maltracer-language-findings">
        <p className="msr-section-note">Programming-language identification is based on static evidence and relative candidate scoring.</p>
        <div className="language-fingerprint-layout">
          <section className="language-primary-card">
            <div className="language-primary-mark">&lt;/&gt;</div>
            <div><span>Primary Language</span><strong>{languagePrimary}</strong><small>Evidence basis: {languageEvidenceBasis}</small></div>
          </section>
          <div className="language-evidence-grid">
            <div><span>Pattern Hits</span><strong>{languagePatternHits}</strong></div>
            <div><span>Relative Score Share</span><strong>{languageRelativeShare}%</strong></div>
            <div><span>Detected Candidates</span><strong>{languageDetectedCount}</strong></div>
          </div>
        </div>
        <div className="language-score-bar">
          <div className="language-score-label"><span>Relative Score Share</span><strong>{languageRelativeShare}%</strong></div>
          <div className="language-score-track"><i style={{ width: `${Math.max(0, Math.min(100, languageRelativeShare))}%` }}></i></div>
        </div>
        <div className="language-interpretation-note">Relative score share compares detected language candidates; it is not an absolute probability or malware score.</div>
      </ReportSection>
    )
  }

  function LanguageTechnicalEvidence() {
    if (!isLanguage) { return null }
    const excluded = new Set(['language fingerprint', 'detected languages', 'file profile'])
    const rawPanels = filteredExtraPanels.filter((panel) => !excluded.has(String(panel?.title || '').trim().toLowerCase()))
    const candidateItems = Array.isArray(languageDetectedPanel?.items) ? languageDetectedPanel.items : []
    const fileProfileItems = Array.isArray(languageFileProfilePanel?.items) ? languageFileProfilePanel.items : []
    const hasEvidence = hashes.length > 0 || candidateItems.length > 0 || fileProfileItems.length > 0 || rawPanels.length > 0
    if (!hasEvidence) { return null }
    return (
      <section className="panel msr-section maltracer-language-tech">
        <details className="msr-tech-details">
          <summary><span>Language Technical Evidence</span><small>Candidate details, file profile and raw supporting evidence</small></summary>
          <div className="msr-tech-body">
            {candidateItems.length > 0 && (<details className="msr-inner-details"><summary>Detected Language Candidates ({candidateItems.length})</summary><div className="msr-inner-body"><SimpleList items={candidateItems} /></div></details>)}
            {fileProfileItems.length > 0 && (<details className="msr-inner-details"><summary>File Profile ({fileProfileItems.length})</summary><div className="msr-inner-body"><SimpleList items={fileProfileItems} /></div></details>)}
            {hashes.length > 0 && (<details className="msr-inner-details"><summary>File Hashes ({hashes.length})</summary><div className="msr-inner-body"><KeyValueList items={hashes} /></div></details>)}
            {rawPanels.map((panel, index) => (
              <details className="msr-inner-details" key={`${panel.title}-${index}`}>
                <summary>{panel.title} ({panel.count ?? (Array.isArray(panel.items) ? panel.items.length : 0)})</summary>
                <div className="msr-inner-body"><SimpleList items={Array.isArray(panel.items) ? panel.items : []} /></div>
              </details>
            ))}
          </div>
        </details>
      </section>
    )
  }

  function formatBehavioralContextNote(note) {
    const clean = String(note || '').replace(/^\s*\[-\]\s*/, '').trim()
    if (clean.toLowerCase().startsWith('verified publisher:')) {
      const org = clean.match(/(?:^|,\s*)O=([^,]+)/i)?.[1]?.trim()
      const commonName = clean.match(/(?:^|:\s*)CN=([^,]+)/i)?.[1]?.trim()
      if (org) { return { title: 'Verified Publisher', summary: org, detail: commonName && commonName !== org ? commonName : '' } }
    }
    return { title: 'Contextual Evidence', summary: clean || 'Supporting static evidence', detail: '' }
  }

  function BehavioralReport() {
    if (!isBehavioral || !mlAvailable) { return null }
    const scoreDrop = riskAvailable ? Math.max(0, mlRaw - finalRisk) : 0
    const contextualNotes = heuristicNotes.map(formatBehavioralContextNote)
    const hasVtLabel = malwareName && malwareName !== 'N/A'
    return (
      <ReportSection title="ML Behavioral Analysis Output" className="msr-beh-shell maltracer-behavioral-section">
        <p className="msr-section-note behavioral-profile-note">Static EMBER2024 inference with heuristic context. No file execution or runtime behavior monitoring is performed.</p>
        <div className="msr-beh-report">
          <div className="msr-beh-card behavioral-main-card">
            <div className="msr-beh-card-head"><strong>Analysis Metrics & Risk Score</strong><span>Static ML + Context</span></div>
            <div className="msr-beh-row">
              <div className="msr-beh-metrics">
                <div className="msr-beh-card-head"><strong>EMBER2024 Metrics</strong><span>{modelUsed}</span></div>
                <div className="msr-beh-subhead">MODEL & PIPELINE DETAILS</div>
                <div className="msr-beh-metric"><span>Model Used</span><b>{modelUsed}</b></div>
                <div className="msr-beh-metric">
                  <span>Pipeline Stages</span>
                  <b className="msr-pills">
                    <i>Static Features</i><i>Packer</i><i>Behavior Heuristic</i>
                    {malwareFamily !== 'N/A' && (<i>Family Cluster</i>)}
                  </b>
                </div>
                <div className="msr-beh-metric"><span>Feature Vector</span><b>2,568-dim EMBER</b></div>
                <div className="msr-beh-metric"><span>Raw ML Score</span><b className="behavioral-score-value">{mlRaw} / 100</b></div>
                <div className="msr-beh-metric"><span>Static Behavior Heuristic</span><b>{behaviorPercent.toFixed(1)}%</b></div>
                <div className="msr-beh-metric"><span>Packer / Obfuscation</span><b>{packerPercent.toFixed(1)}%</b></div>
                <div className="msr-beh-metric"><span>ML Family Cluster</span><b>{malwareFamily}</b></div>
              </div>
              <div className="msr-beh-gauge-box behavioral-gauge-box">
                <div className="msr-beh-card-head"><strong>Final Risk</strong></div>
                <div className="msr-beh-gauge-col">
                  <RiskGauge value={finalRisk} available={riskAvailable} />
                  <span className={`maltracer-risk-pill ` + `${!riskAvailable ? 'na' : finalRisk >= 70 ? 'high' : finalRisk >= 40 ? 'medium' : 'low'}`}>{riskAvailable ? riskLabel : 'Risk N/A'}</span>
                  <small>Final contextual risk</small>
                </div>
              </div>
            </div>
          </div>
          <div className="behavioral-evidence-strip">
            <div><span>Raw ML</span><strong>{mlRaw}/100</strong><small>model output</small></div>
            <div><span>Static Behavior</span><strong>{behaviorPercent.toFixed(1)}%</strong><small>heuristic signal</small></div>
            <div><span>Packer</span><strong>{packerPercent.toFixed(1)}%</strong><small>obfuscation signal</small></div>
            <div><span>Family Cluster</span><strong>{malwareFamily}</strong><small>ML association</small></div>
          </div>
          <div className="msr-beh-card behavioral-context-card">
            <div className="msr-beh-card-head"><strong>Contextual Risk Evaluation</strong><span>Supporting evidence</span></div>
            <div className="msr-heu-list">
              <div className="msr-heu-step">
                <span className="msr-heu-icon">ML</span>
                <div><strong>EMBER2024 Raw Score: {mlRaw}/100</strong><small>Official pre-trained EMBER2024 static model output.</small></div>
              </div>
              {contextualNotes.map((note, index) => (
                <div className="msr-heu-step" key={index}>
                  <span className="msr-heu-icon trusted">✓</span>
                  <div>
                    <strong>{note.title}: {note.summary}</strong>
                    {note.detail && (<small>{note.detail}</small>)}
                  </div>
                </div>
              ))}
              <div className="msr-heu-step final-risk-step">
                <span className="msr-heu-icon final">=</span>
                <div>
                  <strong>Final Contextual Risk: {riskAvailable ? `${finalRisk}/100` : 'N/A'}</strong>
                  <small>{riskAvailable && scoreDrop > 0 ? `${Math.round(scoreDrop)} point reduction after contextual supporting evidence.` : 'Final score after contextual evaluation.'}</small>
                </div>
              </div>
            </div>
          </div>
          {hasVtLabel && (
            <div className="behavioral-vt-label">
              <span>VirusTotal Malware Name</span>
              <strong>{malwareName}</strong>
              <small>External consensus threat intelligence; separate from the ML family cluster.</small>
            </div>
          )}
          <div className="msr-beh-card behavioral-file-card">
            <div className="msr-beh-card-head"><strong>File Identity</strong></div>
            <div className="msr-file-id-table">
              <div className="head"><span>Target Type</span><span>SHA-256</span><span>Filename</span></div>
              <div>
                <span>{targetType}</span>
                <span className="mono">{sha256}</span>
                <span>{job.sample_name || summaryValue('Filename', 'Sample Name') || 'N/A'}</span>
              </div>
            </div>
          </div>
          <div className="msr-beh-card behavioral-explanation-card">
            <div className="msr-beh-card-head"><strong>Score Explanation</strong></div>
            <div className="msr-score-explain">
              <p>
                The official pre-trained EMBER2024 model produced a raw static score of{' '}
                <strong>{mlRaw}/100</strong>.{' '}
                MalTracer then evaluated supporting static evidence and contextual trust signals to produce{' '}
                <strong>{riskAvailable ? `${finalRisk}/100` : 'N/A'}</strong>{' '}
                as the final contextual risk. The raw EMBER score is supporting evidence and is not the final malware probability.
              </p>
            </div>
          </div>
        </div>
      </ReportSection>
    )
  }

  function BehavioralTechnicalEvidence() {
    if (!isBehavioral) { return null }
    const hasEvidence = hashes.length > 0 || heuristicNotes.length > 0 || patterns.length > 0 || windowsApis.length > 0
    if (!hasEvidence) { return null }
    return (
      <section className="panel msr-section maltracer-behavioral-tech">
        <details className="msr-tech-details">
          <summary><span>ML Behavioral Technical Evidence</span><small>Raw hashes, certificate context and supporting static details</small></summary>
          <div className="msr-tech-body">
            {hashes.length > 0 && (<details className="msr-inner-details"><summary>File Hashes ({hashes.length})</summary><div className="msr-inner-body"><KeyValueList items={hashes} /></div></details>)}
            {heuristicNotes.length > 0 && (
              <details className="msr-inner-details">
                <summary>Raw Contextual Evidence ({heuristicNotes.length})</summary>
                <div className="msr-inner-body"><SimpleList items={heuristicNotes.map((note) => String(note).replace(/^\s*\[-\]\s*/, ''))} /></div>
              </details>
            )}
            {patterns.length > 0 && (<details className="msr-inner-details"><summary>Interesting String Patterns ({patterns.length})</summary><div className="msr-inner-body"><SimpleList items={patterns} /></div></details>)}
            {windowsApis.length > 0 && (
              <details className="msr-inner-details">
                <summary>Windows API Evidence ({windowsApis.length} categories)</summary>
                <div className="msr-inner-body">
                  <div className="msr-signal-grid">
                    {windowsApis.map((category, index) => (
                      <section className="msr-signal-card" key={`${category.name}-${index}`}>
                        <header><h3>{category.name}</h3><span>{category.count || 0}</span></header>
                        <ul>{(category.apis || []).map((api, apiIndex) => (<li key={apiIndex}>{api}</li>))}</ul>
                      </section>
                    ))}
                  </div>
                </div>
              </details>
            )}
          </div>
        </details>
      </section>
    )
  }

  function VirusTotalReport() {
    if (!vt.available && !vt.error) { return null }
    const vtSummary = Array.isArray(vt.summary) ? vt.summary : []
    const threatLabel = job.vt_threat_label || summaryValue('Malware Name') || 'N/A'
    return (
      <ReportSection title="VirusTotal File Scan" className="maltracer-vt-section">
        {vt.error ? (
          <p className="msr-meta">{vt.error}</p>
        ) : (
          <>
            <div className="msr-summary-grid">
              <article className="metric"><span>Threat Label</span><strong>{threatLabel}</strong></article>
              {vtSummary.filter((item) => String(item?.label || '').trim().toLowerCase() !== 'generated at').map((item, index) => (
                <article className="metric" key={`${item.label}-${index}`}><span>{item.label}</span><strong>{item.value}</strong></article>
              ))}
            </div>
            {(Array.isArray(vt.threat_categories) && vt.threat_categories.length > 0) || (Array.isArray(vt.threat_names) && vt.threat_names.length > 0) ? (
              <div className="msr-signal-grid">
                {Array.isArray(vt.threat_categories) && vt.threat_categories.length > 0 && (
                  <section className="msr-signal-card">
                    <header><h3>Threat Categories</h3><span>{vt.threat_categories.length}</span></header>
                    <ul>{vt.threat_categories.map((item, index) => (<li key={index}>{item.value} ({item.count})</li>))}</ul>
                  </section>
                )}
                {Array.isArray(vt.threat_names) && vt.threat_names.length > 0 && (
                  <section className="msr-signal-card">
                    <header><h3>Threat Names</h3><span>{vt.threat_names.length}</span></header>
                    <ul>{vt.threat_names.map((item, index) => (<li key={index}>{item.value} ({item.count})</li>))}</ul>
                  </section>
                )}
              </div>
            ) : null}
            {Array.isArray(vt.verdict_stats) && vt.verdict_stats.length > 0 && (
              <div className="msr-vt-stats">
                {vt.verdict_stats.map((item, index) => (<span key={`${item.key}-${index}`}>{item.label}: <b>{item.value}</b></span>))}
              </div>
            )}
            {Array.isArray(vt.detections) && vt.detections.length > 0 && (
              <div className="msr-table-wrap">
                <table className="msr-data-table">
                  <thead><tr><th>Engine</th><th>Result</th><th>Category</th><th>Method</th></tr></thead>
                  <tbody>
                    {vt.detections.map((row, index) => (
                      <tr key={index}>
                        <td>{row.engine}</td>
                        <td>{row.result}</td>
                        <td>{row.category || '—'}</td>
                        <td>{row.method || '—'}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
            <p className="msr-footnote">Zero detections do not guarantee safety.</p>
          </>
        )}
      </ReportSection>
    )
  }

  function CategoryHeatmap() {
    if (categories.length === 0) { return null }
    const maxCount = Math.max(1, ...categories.map((item) => Number(item.count) || 0))
    return (
      <ReportSection title="Category Heatmap" className="maltracer-heat-section">
        <div className="msr-heatmap">
          {categories.map((row, index) => {
            const count = Number(row.count) || 0
            return (
              <div className="msr-heat-row" key={`${row.name}-${index}`}>
                <span className="name">{row.name}</span>
                <span className="bar"><i style={{ width: `${Math.max(2, (count / maxCount) * 100)}%` }}></i></span>
                <span className="value">{count}</span>
              </div>
            )
          })}
        </div>
      </ReportSection>
    )
  }

  function PermissionsReport() {
    if (!permissions.available) { return null }
    const rows = Array.isArray(permissions.rows) ? permissions.rows : []
    return (
      <ReportSection title="Android Permissions">
        <div className="msr-summary-grid three">
          <Metric label="Dangerous" value={permissions.counts?.dangerous ?? 0} />
          <Metric label="Special" value={permissions.counts?.special ?? 0} />
          <Metric label="Info" value={permissions.counts?.info ?? 0} />
        </div>
        {rows.length > 0 && (
          <div className="msr-table-wrap">
            <table className="msr-data-table">
              <thead><tr><th>Permission</th><th>State</th></tr></thead>
              <tbody>
                {rows.map((row, index) => (<tr key={index}><td>{row.name}</td><td>{row.state_label || row.state}</td></tr>))}
              </tbody>
            </table>
          </div>
        )}
      </ReportSection>
    )
  }

  function MitreReport() {
    if (mitreRows.length === 0) { return null }
    return (
      <ReportSection title="MITRE ATT&CK Static Capability Mapping" className="maltracer-mitre-section">
        <p className="msr-section-note">Static capability associations from API overlap; not confirmation of runtime technique execution.</p>
        <div className="msr-rules-grid">
          {mitreRows.map((tactic, index) => (
            <section className="msr-rule-card" key={`${tactic.tactic}-${index}`}>
              <header><h3>{tactic.tactic}</h3><span>{tactic.technique_count || 0} techniques · {tactic.api_match_count ?? tactic.score ?? 0} API matches</span></header>
              <div className="msr-table-wrap">
                <table className="msr-data-table compact">
                  <thead><tr><th>Technique</th><th>ID</th><th>Score</th><th>Matched APIs</th></tr></thead>
                  <tbody>
                    {(Array.isArray(tactic.techniques) ? tactic.techniques : []).map((row, rowIndex) => (
                      <tr key={rowIndex}>
                        <td>{row.technique}</td>
                        <td>{row.tid || '—'}</td>
                        <td>{row.score ?? row.api_match_count ?? 0}</td>
                        <td>{Array.isArray(row.matched_apis) && row.matched_apis.length > 0 ? row.matched_apis.join(', ') : '—'}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </section>
          ))}
        </div>
      </ReportSection>
    )
  }

  function InterestingPatternsReport() {
    if (patterns.length === 0) { return null }
    return (
      <ReportSection title="Interesting String Patterns">
        <ul className="msr-pattern-list">
          {patterns.map((value, index) => (<li key={index}>{value}</li>))}
        </ul>
      </ReportSection>
    )
  }

  function SourcePatternsReport() {
    if (sourcePatternRows.length === 0) { return null }
    return (
      <ReportSection title="Source Pattern Findings">
        <div className="msr-rules-grid">
          {sourcePatternRows.map((row, index) => (
            <section className="msr-rule-card" key={`${row.file_name}-${index}`}>
              <header><h3>{row.file_name}</h3><span>{row.pattern_count || 0} patterns</span></header>
              {Array.isArray(row.categories) && row.categories.length > 0 && (<p className="msr-meta">Categories: {row.categories.join(', ')}</p>)}
              {Array.isArray(row.patterns) && row.patterns.length > 0 && (
                <ul className="msr-pattern-list compact">
                  {row.patterns.map((pattern, patternIndex) => (<li key={patternIndex}>{pattern}</li>))}
                </ul>
              )}
            </section>
          ))}
        </div>
      </ReportSection>
    )
  }

  function YaraReport() {
    if (yaraRules.length === 0) { return null }
    return (
      <ReportSection title="Matched YARA Rules" className="maltracer-yara-section">
        <p className="msr-section-note">YARA matches are evidence signals and are not proof of maliciousness by themselves.</p>
        <div className="msr-rules-grid">
          {yaraRules.map((rule, index) => (
            <section className="msr-rule-card" key={`${rule.name}-${index}`}>
              <header><h3>{rule.name}</h3><span>{rule.count || 0} hits</span></header>
              <div className="msr-table-wrap">
                <table className="msr-data-table compact">
                  <thead><tr><th>Offset</th><th>Pattern</th></tr></thead>
                  <tbody>
                    {(Array.isArray(rule.samples) ? rule.samples : []).map((sample, sampleIndex) => (
                      <tr key={sampleIndex}><td>{sample.offset || '—'}</td><td>{sample.pattern || '—'}</td></tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </section>
          ))}
        </div>
      </ReportSection>
    )
  }

  function ProfileSpecificCoreCards() {
    const cards = []
    if (archiveSection.available) {
      cards.push({
        title: 'Archive Contents',
        count: archiveSection.member_count || 0,
        items: Array.isArray(archiveSection.members)
          ? archiveSection.members.map((item) => `${item.name || 'entry'} · ${Number(item.size) || 0} bytes${item.is_dir ? ' · directory' : ''}`)
          : [],
      })
    }
    if (packerSection.available) {
      cards.push({
        title: 'Packer / Obfuscation',
        count: packerSection.string_hits_count || 0,
        items: [
          `Packed verdict: ${packerSection.packed ? 'Packed' : 'Not Packed'}`,
          `String packer hits: ${packerSection.string_hits_count || 0}`,
          `YARA evidence only: ${packerSection.yara_evidence_only ? 'Yes' : 'No'}`,
        ],
      })
    }
    if (iocSection.available) {
      const iocGroups = [['URLs', iocSection.urls], ['Domains', iocSection.domains], ['IP Addresses', iocSection.ips], ['Emails', iocSection.emails], ['File Paths', iocSection.file_paths], ['Hashes', iocSection.hashes]]
      iocGroups.forEach(([title, values]) => {
        if (Array.isArray(values) && values.length > 0) { cards.push({ title, count: values.length, items: values }) }
      })
    }
    if (languageSection.available) {
      cards.push({
        title: 'Language Fingerprint',
        count: languageSection.pattern_hits || 0,
        items: [
          `Primary Language: ${languageSection.primary_language || 'Unknown'}`,
          `Evidence Basis: ${String(languageSection.evidence_basis || 'unknown').replaceAll('_', ' ')}`,
          `Pattern Hits: ${languageSection.pattern_hits || 0}`,
          `Relative Score Share: ${languageSection.relative_score_share || 0}%`,
        ],
      })
    }
    return cards
  }

  function CoreFindingsReport() {
    if (!hasCoreFindings) { return null }
    const profileCards = ProfileSpecificCoreCards()
    return (
      <ReportSection title="Core Findings">
        <div className="msr-signal-grid">
          {profileCards.map((section, index) => (
            <section className="msr-signal-card" key={`profile-${index}`}>
              <header><h3>{section.title}</h3><span>{section.count}</span></header>
              <ul>{(section.items || []).map((item, itemIndex) => (<li key={itemIndex}>{typeof item === 'string' ? item : JSON.stringify(item)}</li>))}</ul>
            </section>
          ))}
          {sections.map((section, index) => (
            <section className="msr-signal-card" key={`section-${index}`}>
              <header><h3>{section.title}</h3><span>{section.count}</span></header>
              <ul>{(section.items || []).map((item, itemIndex) => (<li key={itemIndex}>{typeof item === 'string' ? item : JSON.stringify(item)}</li>))}</ul>
            </section>
          ))}
          {filteredExtraPanels.map((section, index) => (
            <section className="msr-signal-card muted" key={`extra-${index}`}>
              <header><h3>{section.title}</h3><span>{section.count ?? (Array.isArray(section.items) ? section.items.length : 0)}</span></header>
              <ul>{(section.items || []).map((item, itemIndex) => (<li key={itemIndex}>{typeof item === 'string' ? item : JSON.stringify(item)}</li>))}</ul>
            </section>
          ))}
        </div>
      </ReportSection>
    )
  }

  function StandardTechnicalEvidence() {
    if (!isStandard) { return null }
    const linkedDlls = sections.find((section) => String(section?.title || '').trim().toLowerCase() === 'linked dlls')
    const peSections = sections.find((section) => String(section?.title || '').trim().toLowerCase() === 'sections')
    const hasEvidence = patterns.length > 0 || windowsApis.length > 0 || Array.isArray(linkedDlls?.items) || Array.isArray(peSections?.items)
    if (!hasEvidence) { return null }
    return (
      <section className="panel msr-section">
        <details className="msr-tech-details">
          <summary><span>Technical Evidence</span><small>Strings, DLLs, PE sections and Windows API details</small></summary>
          <div className="msr-tech-body">
            {patterns.length > 0 && (
              <details className="msr-inner-details">
                <summary>Interesting String Patterns ({patterns.length})</summary>
                <div className="msr-inner-body">
                  <ul className="msr-pattern-list">{patterns.map((value, index) => (<li key={index}>{value}</li>))}</ul>
                </div>
              </details>
            )}
            {Array.isArray(linkedDlls?.items) && linkedDlls.items.length > 0 && (
              <details className="msr-inner-details">
                <summary>Linked DLLs ({linkedDlls.count || linkedDlls.items.length})</summary>
                <div className="msr-inner-body"><SimpleList items={linkedDlls.items} /></div>
              </details>
            )}
            {Array.isArray(peSections?.items) && peSections.items.length > 0 && (
              <details className="msr-inner-details">
                <summary>PE Sections ({peSections.count || peSections.items.length})</summary>
                <div className="msr-inner-body"><SimpleList items={peSections.items} /></div>
              </details>
            )}
            {windowsApis.length > 0 && (
              <details className="msr-inner-details">
                <summary>Windows API Categories ({windowsApis.length})</summary>
                <div className="msr-inner-body">
                  <div className="msr-signal-grid">
                    {windowsApis.map((section, index) => (
                      <section className="msr-signal-card" key={`${section.name}-${index}`}>
                        <header><h3>{section.name}</h3><span>{section.count}</span></header>
                        <ul>{(section.apis || []).map((api, apiIndex) => (<li key={apiIndex}>{api}</li>))}</ul>
                      </section>
                    ))}
                  </div>
                </div>
              </details>
            )}
          </div>
        </details>
      </section>
    )
  }

  function WindowsApiReport() {
    if (windowsApis.length === 0) { return null }
    return (
      <ReportSection title="Windows API Categories">
        <p className="msr-section-note">Static capability association only; API presence is not proof of maliciousness.</p>
        <div className="msr-signal-grid">
          {windowsApis.map((section, index) => (
            <section className="msr-signal-card" key={`${section.name}-${index}`}>
              <header><h3>{section.name}</h3><span>{section.count}</span></header>
              <ul>{(section.apis || []).map((api, apiIndex) => (<li key={apiIndex}>{api}</li>))}</ul>
            </section>
          ))}
        </div>
      </ReportSection>
    )
  }

  function ScriptAnalysisReport() {
    if (!scriptAnalysis.available) { return null }
    const scriptCategories = Array.isArray(scriptAnalysis.categories) ? scriptAnalysis.categories : []
    return (
      <ReportSection title="Script Analysis">
        <div className="msr-script-badges">
          {scriptAnalysis.language && (<span>{scriptAnalysis.language}</span>)}
          {scriptAnalysis.vbe_encoded && (<span className="danger">VBE Encoded</span>)}
        </div>
        {scriptCategories.length > 0 && (
          <div className="msr-signal-grid">
            {scriptCategories.map((category, index) => (
              <section className="msr-signal-card" key={`${category.name}-${index}`}>
                <header><h3>{category.name}</h3><span>{category.count}</span></header>
                <ul>{(category.hits || []).map((hit, hitIndex) => (<li key={hitIndex}><code>{hit}</code></li>))}</ul>
              </section>
            ))}
          </div>
        )}
        {Array.isArray(scriptAnalysis.createobject_values) && scriptAnalysis.createobject_values.length > 0 && (
          <><h3 className="msr-subtitle">CreateObject Values</h3><SimpleList items={scriptAnalysis.createobject_values} /></>
        )}
        {Array.isArray(scriptAnalysis.shell_commands) && scriptAnalysis.shell_commands.length > 0 && (
          <><h3 className="msr-subtitle">Shell Commands</h3><SimpleList items={scriptAnalysis.shell_commands} /></>
        )}
        {Array.isArray(scriptAnalysis.decoded_payload_hints) && scriptAnalysis.decoded_payload_hints.length > 0 && (
          <><h3 className="msr-subtitle">Decoded Payload Hints</h3><SimpleList items={scriptAnalysis.decoded_payload_hints} /></>
        )}
      </ReportSection>
    )
  }

  return (
    <section className="stack report-shell msr-report-page">
      <section className="panel report-header msr-report-hero">
        <div>
          <div className="eyebrow">ANALYSIS WORKSPACE</div>
          <h2>{job.sample_name || 'Unknown Sample'}</h2>
          <p>
            Mode: {job.preset_label || job.preset_key || 'Analysis'}{' · '}
            Status: {job.status || 'Unknown'}
            {job.duration !== null && job.duration !== undefined ? ` · Duration: ${job.duration}s` : ''}
          </p>
          {job.smart_auto && (
            <div className="smart-auto-trace">
              <strong>Smart Auto:</strong>
              <span>{job.auto_detected_type || 'Detected file'}{' → '}{job.resolved_preset_label || job.preset_label || job.preset_key}</span>
              {job.auto_detection_reason && (<small>{job.auto_detection_reason}</small>)}
            </div>
          )}
        </div>
        <div className="report-header-actions">
          <span className="badge live">{job.status || 'Unknown'}</span>
          {data.report_loaded && (
            <>
              <button type="button" className="btn secondary pdf-download-btn" onClick={() => downloadMalTracerPdf(data)}>Download PDF</button>
              <button type="button" className="btn secondary json-download-btn" onClick={() => downloadMalTracerJson(data)}>Download JSON</button>
            </>
          )}
        </div>
      </section>
      {!data.report_loaded ? (
        <section className="panel">
          <div className="eyebrow">REPORT STATUS</div>
          <h2>Report not available yet</h2>
          <p>{data.report_load_error || 'The analysis may still be running or no report was generated.'}</p>
        </section>
      ) : (
        <>
          {isBehavioral ? <BehavioralReport/> : isDocument ? <DocumentSummaryReport/> : isArchive ? <ArchiveSummaryReport/> : isPacker ? <PackerSummaryReport/> : isDomain ? <DomainSummaryReport/> : isLanguage ? <LanguageSummaryReport/> : <PlainSummary/>}
          <VirusTotalReport/>
          <CategoryHeatmap/>
          <PermissionsReport/>
          <MitreReport/>
          {isStandard ? (
            <><YaraReport/><StandardTechnicalEvidence/></>
          ) : isDocument ? (
            <><YaraReport/><DocumentFindingsReport/><DocumentIocReport/><DocumentTechnicalEvidence/></>
          ) : isArchive ? (
            <><ArchiveContentsReport/><YaraReport/><ArchiveTechnicalEvidence/></>
          ) : isPacker ? (
            <><PackerAssessmentReport/><PackerYaraReport/><PackerTechnicalEvidence/></>
          ) : isDomain ? (
            <><DomainIocReport/><DomainTechnicalEvidence/></>
          ) : isLanguage ? (
            <><LanguageFingerprintReport/><LanguageTechnicalEvidence/></>
          ) : isBehavioral ? (
            <><YaraReport/><BehavioralTechnicalEvidence/></>
          ) : (
            <><InterestingPatternsReport/><SourcePatternsReport/><YaraReport/><CoreFindingsReport/><WindowsApiReport/><ScriptAnalysisReport/></>
          )}
        </>
      )}
    </section>
  )
}

function ReportBarChart({ title, subtitle, data, compact = false, valueSuffix = '', maxValueOverride = null }) {
  const cleanData = Array.isArray(data) ? data.map((item) => ({ label: String(item?.label || 'Item'), value: Math.max(0, Number(item?.value) || 0) })).filter((item) => item.value > 0 || maxValueOverride !== null) : []
  if (cleanData.length === 0) { return null }
  const observedMax = Math.max(...cleanData.map((item) => item.value), 1)
  const maxValue = Number.isFinite(Number(maxValueOverride)) && Number(maxValueOverride) > 0 ? Number(maxValueOverride) : observedMax
  const chartWidth = 760
  const leftMargin = 178
  const rightMargin = 34
  const topMargin = 22
  const bottomMargin = 38
  const rowHeight = 42
  const chartHeight = topMargin + bottomMargin + cleanData.length * rowHeight
  const plotWidth = chartWidth - leftMargin - rightMargin
  const tickCount = 4
  const ticks = Array.from({ length: tickCount + 1 }, (_, index) => (maxValue / tickCount) * index)
  function formatValue(value) { if (Number.isInteger(value)) { return `${value}${valueSuffix}` } return `${value.toFixed(1)}${valueSuffix}` }
  function shortLabel(label) { return label.length > 24 ? `${label.slice(0, 22)}…` : label }
  return (
    <div className={compact ? 'report-chart-card compact professional-chart-card' : 'report-chart-card professional-chart-card'}>
      <div className="report-chart-heading">
        <div><h3>{title}</h3>{subtitle && (<p>{subtitle}</p>)}</div>
        <span className="report-chart-count">{cleanData.length}</span>
      </div>
      <div className="professional-chart-wrap">
        <svg className="professional-bar-svg" viewBox={`0 0 ${chartWidth} ${chartHeight}`} role="img" aria-label={title}>
          {ticks.map((tick, index) => {
            const x = leftMargin + (tick / maxValue) * plotWidth
            return (
              <g key={`tick-${index}`}>
                <line className="chart-grid-line" x1={x} y1={topMargin - 4} x2={x} y2={chartHeight - bottomMargin + 4} />
                <text className="chart-axis-text" x={x} y={chartHeight - 12} textAnchor="middle">{formatValue(tick)}</text>
              </g>
            )
          })}
          {cleanData.map((item, index) => {
            const y = topMargin + index * rowHeight
            const width = Math.max(2, Math.min(plotWidth, (item.value / maxValue) * plotWidth))
            return (
              <g className="professional-bar-row" key={`${item.label}-${index}`}>
                <text className="chart-category-text" x={leftMargin - 12} y={y + 20} textAnchor="end">{shortLabel(item.label)}</text>
                <rect className="chart-bar-bg" x={leftMargin} y={y + 7} width={plotWidth} height="18" rx="9" />
                <rect className="chart-bar-value" x={leftMargin} y={y + 7} width={width} height="18" rx="9">
                  <title>{`${item.label}: ${formatValue(item.value)}`}</title>
                </rect>
                <text className="chart-value-text" x={Math.min(leftMargin + width + 8, chartWidth - rightMargin)} y={y + 20}>{formatValue(item.value)}</text>
              </g>
            )
          })}
        </svg>
      </div>
    </div>
  )
}

function ReportDonutChart({ title, subtitle, data, centerValue, centerLabel }) {
  const cleanData = Array.isArray(data) ? data.map((item) => ({ label: String(item?.label || 'Item'), value: Math.max(0, Number(item?.value) || 0) })).filter((item) => item.value > 0) : []
  const total = cleanData.reduce((sum, item) => sum + item.value, 0)
  if (cleanData.length === 0 || total <= 0) { return null }
  let cursor = 0
  const slices = cleanData.map((item, index) => {
    const start = (cursor / total) * 100
    cursor += item.value
    const end = (cursor / total) * 100
    return { ...item, index, start, end }
  })
  const palette = ['rgba(255,86,109,.86)', 'rgba(255,201,103,.82)', 'rgba(43,220,232,.86)', 'rgba(76,224,161,.78)', 'rgba(140,124,255,.72)', 'rgba(143,164,184,.62)']
  const gradient = slices.map((slice) => { const color = palette[slice.index % palette.length]; return `${color} ${slice.start}% ${slice.end}%` }).join(', ')
  return (
    <div className="report-chart-card">
      <div className="report-chart-heading">
        <div><h3>{title}</h3>{subtitle && (<p>{subtitle}</p>)}</div>
      </div>
      <div className="report-donut-layout">
        <div className="report-donut" style={{ background: `conic-gradient(${gradient})` }}>
          <div className="report-donut-center">
            <strong>{centerValue || total}</strong>
            <span>{centerLabel || 'total'}</span>
          </div>
        </div>
        <div className="report-donut-legend">
          {slices.map((slice) => (
            <div className="report-donut-item" key={slice.label}>
              <span className="report-dot" style={{ background: palette[slice.index % palette.length] }}></span>
              <span>{slice.label}</span>
              <strong>{slice.value}</strong>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}

function GenericPanel({ panel }) {
  if (!panel) { return null }
  return (
    <div className="info-block" style={{ marginTop: 18 }}>
      <h3>{panel.title || 'Details'}{panel.count !== undefined ? ` · ${panel.count}` : ''}</h3>
      {panel.kind === 'table' && Array.isArray(panel.rows) ? (
        <div style={{ overflowX: 'auto' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse' }}>
            <thead><tr>{(panel.columns || []).map((column) => (<th key={column} style={{ textAlign: 'left', padding: 10, opacity: 0.75 }}>{column}</th>))}</tr></thead>
            <tbody>
              {panel.rows.map((row, rowIndex) => (
                <tr key={rowIndex}>
                  {(Array.isArray(row) ? row : []).map((value, valueIndex) => (
                    <td key={valueIndex} style={{ padding: 10, borderTop: '1px solid rgba(120,170,200,.15)' }}>{String(value ?? '—')}</td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : panel.kind === 'kv' && Array.isArray(panel.rows) ? (
        <KeyValueList items={panel.rows.map((row) => ({ label: row.key || row.label || 'Field', value: row.value ?? '—' }))} />
      ) : (
        <SimpleList items={panel.items || []} />
      )}
    </div>
  )
}

function KeyValueList({ items }) {
  return (
    <div style={{ display: 'grid', gap: 10 }}>
      {items.map((item, index) => (
        <div key={index} style={{ padding: 12, border: '1px solid rgba(120,170,200,.16)', borderRadius: 10, overflowWrap: 'anywhere' }}>
          <small style={{ display: 'block', opacity: 0.65, marginBottom: 5 }}>{item.label || item.key}</small>
          <strong>{String(item.value ?? '—')}</strong>
        </div>
      ))}
    </div>
  )
}

function SimpleList({ items }) {
  if (!Array.isArray(items) || items.length === 0) { return (<EmptyState text="No data available."/>) }
  return (
    <div style={{ display: 'grid', gap: 8, marginTop: 10 }}>
      {items.map((item, index) => (
        <div key={index} style={{ padding: '9px 12px', border: '1px solid rgba(120,170,200,.14)', borderRadius: 8, overflowWrap: 'anywhere' }}>
          {typeof item === 'string' ? item : JSON.stringify(item)}
        </div>
      ))}
    </div>
  )
}

function EmptyState({ text }) {
  return (<div className="info-block" style={{ marginTop: 12 }}><p>{text}</p></div>)
}

function SectionTitle({ title }) {
  return (<h3 style={{ marginTop: 24, marginBottom: 14 }}>{title}</h3>)
}

function Metric({ label, value }) {
  return (<div className="metric"><span>{label}</span><strong>{value}</strong></div>)
}

function RiskGauge({ value, available = true }) {
  const safeValue = available ? Math.min(100, Math.max(0, Number(value) || 0)) : 0
  const gaugeColor = !available ? '#61778b' : safeValue >= 70 ? '#ff6675' : safeValue >= 40 ? '#ffc967' : '#64f0d2'
  return (
    <div className={available ? 'risk-gauge' : 'risk-gauge risk-gauge-na'} style={{ '--risk': `${safeValue * 3.6}deg`, '--risk-color': gaugeColor }}>
      <div>
        <strong>{available ? safeValue : 'N/A'}</strong>
        <span>{available ? '/100' : 'risk'}</span>
      </div>
    </div>
  )
}

export default App
