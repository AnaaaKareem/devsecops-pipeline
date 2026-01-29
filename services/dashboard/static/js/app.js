/**
 * Nexus Security Dashboard - Application JavaScript
 * ================================================
 * Handles all frontend logic including:
 * - Stats fetching and display
 * - Project carousel management
 * - Findings table with filtering and pagination
 * - AI Fix diff modal
 * - Delete confirmation
 */

// === Global State ===
const API_BASE = '/api';
let riskChart = null;
let ciChart = null;
let currentPage = 1;
let totalPages = 1;
let currentFilters = {
    repo: '',
    tool: '',
    severity: ''
};
let selectedRepo = '';

// === Initialization ===
document.addEventListener('DOMContentLoaded', () => {
    initDashboard();
});

async function initDashboard() {
    await Promise.all([
        fetchProjects(),
        fetchStats(),
        fetchFilterOptions(),
        fetchFindings()
    ]);

    // Auto-refresh every 3 seconds
    setInterval(() => {
        fetchStats(selectedRepo);
        fetchProjects();
    }, 3000);

    // Refresh findings less frequently
    setInterval(() => {
        fetchFindings();
    }, 5000);
}

// === Stats Fetching ===
async function fetchStats(repo = '') {
    try {
        const url = repo ? `${API_BASE}/stats?repo=${encodeURIComponent(repo)}` : `${API_BASE}/stats`;
        const res = await fetch(url);
        const data = await res.json();

        updateStatsDisplay(data);
        updateCharts(data);
    } catch (e) {
        console.error('Stats fetch error:', e);
    }
}

function updateStatsDisplay(data) {
    // Total Findings
    const totalFindings = document.getElementById('statTotalFindings');
    if (totalFindings) totalFindings.textContent = data.total_findings || 0;

    // Critical Issues
    const critical = document.getElementById('statCritical');
    if (critical) critical.textContent = data.severity?.critical || 0;

    // High Issues
    const high = document.getElementById('statHigh');
    if (high) high.textContent = data.severity?.high || 0;

    // AI Fixes Available
    const aiFixes = document.getElementById('statAiFixes');
    if (aiFixes) aiFixes.textContent = data.ai_metrics?.auto_fixed || 0;

    // True Positives
    const tp = document.getElementById('statTruePositives');
    if (tp) {
        const tpCount = data.total_findings - (data.ai_metrics?.false_positives || 0);
        tp.textContent = Math.max(0, tpCount);
    }

    // Total Repos
    const repos = document.getElementById('statRepos');
    if (repos) repos.textContent = data.total_repos || 0;
}

// === Projects/Carousel ===
async function fetchProjects() {
    try {
        const res = await fetch(`${API_BASE}/projects`);
        const projects = await res.json();

        renderProjectCarousel(projects);
        updateActiveProgress();
    } catch (e) {
        console.error('Projects fetch error:', e);
    }
}

function renderProjectCarousel(projects) {
    const carousel = document.getElementById('projectCarousel');
    if (!carousel) return;

    // Keep "All Projects" card
    let html = `
        <div class="project-card glass-card ${selectedRepo === '' ? 'selected' : ''}" 
             data-repo="" onclick="selectRepo('')">
            <div class="project-header">
                <div class="project-icon">
                    <svg width="24" height="24" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" 
                              d="M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14 0V9a2 2 0 00-2-2M5 11V9a2 2 0 012-2m0 0V5a2 2 0 012-2h6a2 2 0 012 2v2M7 7h10"/>
                    </svg>
                </div>
                <div class="project-info">
                    <div class="project-name">All Projects</div>
                    <div class="project-repo">Global Overview</div>
                </div>
            </div>
        </div>
    `;

    projects.forEach(p => {
        const isActive = p.is_active;
        const isSelected = selectedRepo === p.name;
        const timeLabel = isActive ? 'Scanning...' : formatTime(p.last_run);
        const parts = p.name.split('/');
        const userName = parts[0] || p.name;
        const repoName = parts[1] || '';

        // Provider icon
        let providerIcon = getProviderIcon(p.provider);

        html += `
            <div class="project-card glass-card ${isActive ? 'scanning' : ''} ${isSelected ? 'selected' : ''}" 
                 data-repo="${p.name}" onclick="selectRepo('${p.name}')">
                <button class="delete-btn" onclick="event.stopPropagation(); confirmDelete('${p.name}')" title="Delete Project">
                    <svg width="14" height="14" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"/>
                    </svg>
                </button>
                <div class="project-header">
                    <div class="project-icon">${providerIcon}</div>
                    <div class="project-info">
                        <div class="project-name">${userName}</div>
                        ${repoName ? `<div class="project-repo">${repoName}</div>` : ''}
                        <div class="project-branch">🌿 ${p.branch || 'main'}</div>
                    </div>
                </div>
                ${isActive ? `
                    <div class="progress-container" id="progress-${p.name.replace(/\//g, '-')}">
                        <div class="progress-header">
                            <span class="progress-stage">Initializing...</span>
                            <span class="progress-percent">0%</span>
                        </div>
                        <div class="progress-bar-bg">
                            <div class="progress-bar-fill" style="width: 5%"></div>
                        </div>
                    </div>
                ` : ''}
                <div class="project-footer">
                    <span class="project-provider">${p.provider || 'github'}</span>
                    <span class="project-time">${timeLabel}</span>
                </div>
            </div>
        `;
    });

    carousel.innerHTML = html;
}

function getProviderIcon(provider) {
    const p = (provider || '').toLowerCase();

    if (p.includes('gitlab')) {
        return `<svg width="24" height="24" viewBox="0 0 24 24" fill="#FC6D26"><path d="M22.65 14.39L12 22.13 1.35 14.39a.84.84 0 0 1-.3-.94l1.22-3.78 2.44-7.51A.42.42 0 0 1 4.82 2a.43.43 0 0 1 .58.18l2.44 7.51h8.32l2.44-7.51a.43.43 0 0 1 .58-.18.42.42 0 0 1 .11.18l2.44 7.51 1.22 3.78a.84.84 0 0 1-.3.94z"/></svg>`;
    }
    if (p.includes('bitbucket')) {
        return `<svg width="24" height="24" viewBox="0 0 24 24" fill="#0052CC"><path d="M2.65 3C2.25 3 2 3.32 2 3.75v.1l1.54 16.3c.04.5.47.88.97.88h14.98c.5 0 .93-.38.97-.88l1.54-16.4V3.75C22.02 3.32 21.75 3 21.35 3H2.65zM13.63 15h-3.26l-1.07-5.73h5.4L13.63 15z"/></svg>`;
    }
    if (p.includes('azure') || p.includes('devops')) {
        return `<svg width="24" height="24" viewBox="0 0 24 24" fill="#0078D7"><path d="M4.63 2.5a.3.3 0 0 0-.25.13L.1 10.3a.3.3 0 0 0 .1.35C5.8 14.7 13.56 20.35 24 22V2.5H4.63z" opacity=".4"/><path d="M3.5 12.3L24 22V11.5L3.5 12.3z" opacity=".6"/><path d="M24 22V2.5L10.3 8.3L2.25 11l-.88.35a.3.3 0 0 0 .07.56L24 22z"/></svg>`;
    }

    // Default to GitHub
    return `<svg width="24" height="24" fill="currentColor" viewBox="0 0 24 24"><path d="M12 0c-6.626 0-12 5.373-12 12 0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23.957-.266 1.983-.399 3.003-.404 1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.652.242 2.873.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576 4.765-1.589 8.199-6.086 8.199-11.386 0-6.627-5.373-12-12-12z"/></svg>`;
}

function formatTime(isoString) {
    if (!isoString) return '-';
    const date = new Date(isoString);
    return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
}

function selectRepo(repoName) {
    selectedRepo = repoName;
    currentPage = 1;
    currentFilters.repo = repoName;

    // Update visual selection
    document.querySelectorAll('.project-card').forEach(card => {
        card.classList.toggle('selected', card.dataset.repo === repoName);
    });

    // Refresh data
    fetchStats(repoName);
    fetchFindings();
}

function scrollCarousel(direction) {
    const carousel = document.getElementById('projectCarousel');
    if (carousel) {
        carousel.scrollBy({ left: direction * 300, behavior: 'smooth' });
    }
}

// === Active Progress Polling ===
async function updateActiveProgress() {
    const containers = document.querySelectorAll('[id^="progress-"]');

    for (const container of containers) {
        const repoName = container.id.replace('progress-', '').replace(/-/g, '/');

        try {
            const res = await fetch(`${API_BASE}/activity`);
            const activity = await res.json();
            const activeScan = activity.find(s => s.project === repoName);

            if (activeScan) {
                const progressRes = await fetch(`${API_BASE}/scan/${activeScan.id}/progress`);
                const progress = await progressRes.json();

                const stageEl = container.querySelector('.progress-stage');
                const percentEl = container.querySelector('.progress-percent');
                const barEl = container.querySelector('.progress-bar-fill');

                if (stageEl) stageEl.textContent = progress.stage || 'Processing';
                if (percentEl) percentEl.textContent = `${progress.progress_percent || 0}%`;
                if (barEl) barEl.style.width = `${progress.progress_percent || 0}%`;
            }
        } catch (e) {
            console.error(`Progress error for ${repoName}:`, e);
        }
    }
}

// === Filter Options ===
async function fetchFilterOptions() {
    try {
        const res = await fetch(`${API_BASE}/filters`);
        const filters = await res.json();

        // Populate repo filter
        const repoSelect = document.getElementById('filterRepo');
        if (repoSelect && filters.repos) {
            repoSelect.innerHTML = '<option value="">All Repos</option>';
            filters.repos.forEach(r => {
                repoSelect.innerHTML += `<option value="${r}">${r}</option>`;
            });
        }

        // Populate tool filter
        const toolSelect = document.getElementById('filterTool');
        if (toolSelect && filters.tools) {
            toolSelect.innerHTML = '<option value="">All Tools</option>';
            filters.tools.forEach(t => {
                toolSelect.innerHTML += `<option value="${t}">${t}</option>`;
            });
        }

        // Populate severity filter
        const severitySelect = document.getElementById('filterSeverity');
        if (severitySelect && filters.severities) {
            severitySelect.innerHTML = '<option value="">All Severities</option>';
            filters.severities.forEach(s => {
                severitySelect.innerHTML += `<option value="${s}">${s}</option>`;
            });
        }
    } catch (e) {
        console.error('Filters fetch error:', e);
    }
}

function applyFilters() {
    currentFilters.repo = document.getElementById('filterRepo')?.value || '';
    currentFilters.tool = document.getElementById('filterTool')?.value || '';
    currentFilters.severity = document.getElementById('filterSeverity')?.value || '';
    currentPage = 1;
    fetchFindings();
}

// === Findings Table ===
async function fetchFindings() {
    try {
        let url = `${API_BASE}/findings/all?page=${currentPage}&per_page=15`;
        if (currentFilters.repo) url += `&repo=${encodeURIComponent(currentFilters.repo)}`;
        if (currentFilters.tool) url += `&tool=${encodeURIComponent(currentFilters.tool)}`;
        if (currentFilters.severity) url += `&severity=${encodeURIComponent(currentFilters.severity)}`;

        const res = await fetch(url);
        const data = await res.json();

        renderFindingsTable(data.findings || []);
        updatePagination(data.total || 0, data.page || 1, data.per_page || 15);
    } catch (e) {
        console.error('Findings fetch error:', e);
        // Fallback to old endpoint
        fallbackFetchFindings();
    }
}

async function fallbackFetchFindings() {
    try {
        const url = selectedRepo
            ? `${API_BASE}/findings?repo=${encodeURIComponent(selectedRepo)}`
            : `${API_BASE}/findings`;
        const res = await fetch(url);
        const findings = await res.json();
        renderFindingsTable(findings);
        // Hide pagination for fallback
        const pagination = document.querySelector('.pagination');
        if (pagination) pagination.style.display = 'none';
    } catch (e) {
        console.error('Fallback findings error:', e);
    }
}

function renderFindingsTable(findings) {
    const tbody = document.getElementById('findingsBody');
    if (!tbody) return;

    if (findings.length === 0) {
        tbody.innerHTML = `
            <tr>
                <td colspan="7" class="text-center" style="padding: 3rem; color: var(--text-muted);">
                    No security findings found. Run a scan to get started.
                </td>
            </tr>
        `;
        return;
    }

    tbody.innerHTML = findings.map(f => `
        <tr onclick="openFindingModal(${f.id})">
            <td>
                <span class="severity-badge ${f.severity?.toLowerCase()}">${f.severity || 'Unknown'}</span>
            </td>
            <td><span class="tool-badge">${f.tool || '-'}</span></td>
            <td><span class="location-cell" title="${f.location || ''}">${f.location || '-'}</span></td>
            <td>${f.project || '-'}</td>
            <td><span class="risk-score">${f.risk_score?.toFixed(1) || '-'}</span></td>
            <td>
                <span class="ai-fix-badge ${f.has_fix ? 'available' : 'unavailable'}">
                    ${f.has_fix ? '✓' : '—'}
                </span>
            </td>
            <td>
                <button class="view-btn" onclick="event.stopPropagation(); openFindingModal(${f.id})">
                    <svg width="16" height="16" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" 
                              d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"/>
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" 
                              d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z"/>
                    </svg>
                </button>
            </td>
        </tr>
    `).join('');
}

function updatePagination(total, page, perPage) {
    totalPages = Math.ceil(total / perPage);
    currentPage = page;

    const pageInfo = document.getElementById('pageInfo');
    const prevBtn = document.getElementById('prevPage');
    const nextBtn = document.getElementById('nextPage');
    const countInfo = document.getElementById('findingsCount');

    if (pageInfo) pageInfo.textContent = `Page ${page} of ${totalPages || 1}`;
    if (prevBtn) prevBtn.disabled = page <= 1;
    if (nextBtn) nextBtn.disabled = page >= totalPages;
    if (countInfo) {
        const start = (page - 1) * perPage + 1;
        const end = Math.min(page * perPage, total);
        countInfo.textContent = total > 0 ? `Showing ${start}-${end} of ${total}` : 'No findings';
    }
}

function changePage(delta) {
    const newPage = currentPage + delta;
    if (newPage >= 1 && newPage <= totalPages) {
        currentPage = newPage;
        fetchFindings();
    }
}

// === Finding Modal ===
async function openFindingModal(findingId) {
    const modal = document.getElementById('findingModal');
    const content = document.getElementById('modalContent');

    if (!modal || !content) return;

    // Show loading state
    modal.classList.add('active');
    content.innerHTML = '<div class="skeleton" style="height: 200px;"></div>';

    try {
        const res = await fetch(`${API_BASE}/finding/${findingId}`);
        const finding = await res.json();

        renderFindingModal(finding);
    } catch (e) {
        console.error('Finding detail error:', e);
        content.innerHTML = `
            <div style="text-align: center; padding: 2rem; color: var(--text-muted);">
                Failed to load finding details.
                <br><br>
                <button class="action-btn secondary" onclick="closeModal()">Close</button>
            </div>
        `;
    }
}

function renderFindingModal(f) {
    const content = document.getElementById('modalContent');
    if (!content) return;

    const hasfix = f.remediation_patch && f.remediation_patch.trim();

    content.innerHTML = `
        <button class="modal-close" onclick="closeModal()">
            <svg width="18" height="18" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"/>
            </svg>
        </button>
        
        <div class="modal-header">
            <div class="modal-title">${hasfix ? '✅ AI-Generated Fix Available' : '📋 Finding Details'}</div>
            <div class="modal-subtitle">${f.file || 'Unknown file'}:${f.line || '?'}</div>
        </div>
        
        <div class="modal-meta">
            <div class="meta-item">
                <div class="meta-label">Severity</div>
                <div class="meta-value"><span class="severity-badge ${f.severity?.toLowerCase()}">${f.severity || 'Unknown'}</span></div>
            </div>
            <div class="meta-item">
                <div class="meta-label">Tool</div>
                <div class="meta-value">${f.tool || '-'}</div>
            </div>
            <div class="meta-item">
                <div class="meta-label">Risk Score</div>
                <div class="meta-value">${f.risk_score?.toFixed(1) || '-'}</div>
            </div>
            <div class="meta-item">
                <div class="meta-label">AI Confidence</div>
                <div class="meta-value">${f.ai_confidence ? (f.ai_confidence * 100).toFixed(0) + '%' : '-'}</div>
            </div>
            <div class="meta-item">
                <div class="meta-label">AI Verdict</div>
                <div class="meta-value">${f.ai_verdict === 'TP' ? '🔴 True Positive' : '🟢 False Positive'}</div>
            </div>
        </div>
        
        ${f.ai_reasoning ? `
            <div class="modal-section">
                <div class="modal-section-title">📝 AI Reasoning</div>
                <div class="reasoning-text">${escapeHtml(f.ai_reasoning)}</div>
            </div>
        ` : ''}
        
        ${f.snippet ? `
            <div class="modal-section">
                <div class="modal-section-title">📄 Original Code</div>
                <div class="code-block original">
                    <pre>${escapeHtml(f.snippet)}</pre>
                </div>
            </div>
        ` : ''}
        
        ${hasfix ? `
            <div class="modal-section">
                <div class="modal-section-title">✅ AI-Generated Fix</div>
                <div class="code-block fixed">
                    <pre>${escapeHtml(f.remediation_patch)}</pre>
                </div>
            </div>
        ` : `
            <div class="modal-section">
                <div style="padding: 1.5rem; background: rgba(255,255,255,0.03); border-radius: var(--radius-md); text-align: center; color: var(--text-muted);">
                    No AI fix generated for this finding.
                </div>
            </div>
        `}
        
        <div class="modal-actions">
            ${hasfix ? `
                <button class="action-btn primary" onclick="copyFix()">
                    <svg width="16" height="16" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 5H6a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2v-1M8 5a2 2 0 002 2h2a2 2 0 002-2M8 5a2 2 0 012-2h2a2 2 0 012 2m0 0h2a2 2 0 012 2v3m2 4H10m0 0l3-3m-3 3l3 3"/>
                    </svg>
                    Copy Fix
                </button>
            ` : ''}
            ${f.pr_url ? `
                <a href="${f.pr_url}" target="_blank" class="action-btn secondary">
                    <svg width="16" height="16" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14"/>
                    </svg>
                    View PR
                </a>
            ` : ''}
            <button class="action-btn secondary" onclick="closeModal()">Close</button>
        </div>
    `;

    // Store fix for copy functionality
    window.currentFix = f.remediation_patch;
}

function closeModal() {
    const modal = document.getElementById('findingModal');
    if (modal) modal.classList.remove('active');
}

function copyFix() {
    if (window.currentFix) {
        navigator.clipboard.writeText(window.currentFix).then(() => {
            // Show brief success feedback
            const btn = document.querySelector('.action-btn.primary');
            if (btn) {
                const originalText = btn.innerHTML;
                btn.innerHTML = '✓ Copied!';
                setTimeout(() => { btn.innerHTML = originalText; }, 1500);
            }
        });
    }
}

function escapeHtml(text) {
    if (!text) return '';
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// === Delete Confirmation ===
let repoToDelete = null;

function confirmDelete(repoName) {
    repoToDelete = repoName;
    const modal = document.getElementById('deleteModal');
    const nameEl = document.getElementById('deleteRepoName');

    if (nameEl) nameEl.textContent = repoName;
    if (modal) modal.classList.add('active');
}

function cancelDelete() {
    repoToDelete = null;
    const modal = document.getElementById('deleteModal');
    if (modal) modal.classList.remove('active');
}

async function executeDelete() {
    if (!repoToDelete) return;

    const btn = document.getElementById('deleteConfirmBtn');
    if (btn) {
        btn.textContent = 'Deleting...';
        btn.disabled = true;
    }

    try {
        const res = await fetch(`${API_BASE}/project?repo=${encodeURIComponent(repoToDelete)}`, {
            method: 'DELETE'
        });
        const data = await res.json();

        if (data.status === 'success') {
            // Remove card
            const card = document.querySelector(`[data-repo="${repoToDelete}"]`);
            if (card) card.remove();

            // Reset if viewing deleted repo
            if (selectedRepo === repoToDelete) {
                selectRepo('');
            }

            fetchProjects();
        } else {
            alert('Delete failed: ' + (data.error || 'Unknown error'));
        }
    } catch (e) {
        alert('Delete error: ' + e.message);
    } finally {
        if (btn) {
            btn.textContent = 'Delete';
            btn.disabled = false;
        }
        cancelDelete();
    }
}

// === Charts ===
let toolChart = null;
let aiFixChart = null;

function updateCharts(data) {
    const isRepoView = data.devsecops_metrics?.trend_data?.mode === 'repo';

    // Toggle CI Chart visibility
    const ciContainer = document.getElementById('ciChartContainer');
    if (ciContainer) {
        ciContainer.style.display = isRepoView ? 'none' : 'block';
    }

    updateRiskChart(data);
    updateToolChart(data);
    updateAiFixChart(data);
    if (!isRepoView) updateCiChart(data);
}

function updateRiskChart(data) {
    const ctx = document.getElementById('riskChart');
    if (!ctx) return;

    const trend = data.devsecops_metrics?.trend_data || { labels: [], critical: [], high: [], medium: [] };

    // iOS 26 Colors
    const colors = {
        critical: 'rgba(255, 69, 58, 0.8)', // Red
        high: 'rgba(255, 159, 10, 0.8)',    // Orange
        medium: 'rgba(255, 214, 10, 0.8)'   // Yellow
    };

    if (riskChart) {
        // Destroy and recreate if mode changes to handle stacking properly or dataset structure changes
        // Using simple update for now, assuming structure is compatible
        if (riskChart._mode !== trend.mode) {
            riskChart.destroy();
            riskChart = null;
        }
    }

    if (!riskChart) {
        const chartCtx = ctx.getContext('2d');
        riskChart = new Chart(chartCtx, {
            type: 'bar',
            data: {
                labels: trend.labels,
                datasets: [
                    {
                        label: 'Critical',
                        data: trend.critical,
                        backgroundColor: colors.critical,
                        borderRadius: 6
                    },
                    {
                        label: 'High',
                        data: trend.high,
                        backgroundColor: colors.high,
                        borderRadius: 6
                    },
                    {
                        label: 'Medium',
                        data: trend.medium,
                        backgroundColor: colors.medium,
                        borderRadius: 6
                    }
                ]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    y: {
                        beginAtZero: true,
                        stacked: trend.mode === 'global',
                        grid: { color: 'rgba(255,255,255,0.05)' },
                        ticks: { color: '#8E8E93' }
                    },
                    x: {
                        stacked: trend.mode === 'global',
                        grid: { display: false },
                        ticks: { color: '#8E8E93' }
                    }
                },
                plugins: {
                    legend: { display: trend.mode === 'global', labels: { color: 'white' } }
                }
            }
        });
        riskChart._mode = trend.mode;
    } else {
        riskChart.data.labels = trend.labels;
        // In repo mode, trend.critical allows containing the counts for C, H, M as a list
        // However, the backend sends [C, H, M] in the 'critical' field for Repo Mode.
        // We need to map that correctly. 
        // Note: The previous backend logic (lines 244 in main.py) put [c, h, m] into trend_data["critical"]
        // But for Global mode, it put [c1, c2...] into critical, [h1, h2...] into high.

        if (trend.mode === 'repo') {
            // Repo Mode: labels are ["Critical", "High", "Medium"]
            // Dataset 0 should map to Critical bars? No, we need 1 dataset with 3 bars colored differently.
            // Or reuse the 3 datasets but only 1 value each?
            // Easier: Destroy and recreate as simple bar chart with 1 dataset but multicolor

            // For now, let's keep it consistent:
            // "Critical" dataset gets [count_critical, 0, 0]
            // "High" dataset gets [0, count_high, 0] ...

            // Actually, best is simply 1 dataset.
            // Let's destroy riskChart if mode changes as handled above.

            // If already repo mode:
            // We expect main.py to send:
            // labels: ["Critical", "High", "Medium"]
            // critical: [CountC, CountH, CountM]  <-- wait, main.py did this
            // But we have 3 datasets.
            // We should use a single dataset for repo mode ideally.
            // Let's quick-fix the chart config on creation to start with 1 dataset if repo mode.

            // Since we destroy on mode change, let's refine creation logic above for Repo Mode specifically.
        } else {
            riskChart.data.datasets[0].data = trend.critical;
            riskChart.data.datasets[1].data = trend.high;
            riskChart.data.datasets[2].data = trend.medium;
        }
        riskChart.update('none');
    }
}

// Redefining risk chart logic to be more robust
function updateRiskChart(data) {
    const ctx = document.getElementById('riskChart');
    if (!ctx) return;

    const trend = data.devsecops_metrics?.trend_data || { labels: [], critical: [], high: [], medium: [] };
    const mode = trend.mode || 'global';

    if (riskChart && riskChart._mode !== mode) {
        riskChart.destroy();
        riskChart = null;
    }

    const iosColors = {
        red: 'rgba(255, 69, 58, 0.8)',
        orange: 'rgba(255, 159, 10, 0.8)',
        yellow: 'rgba(255, 214, 10, 0.8)'
    };

    if (riskChart) {
        if (mode === 'global') {
            riskChart.data.labels = trend.labels;
            riskChart.data.datasets[0].data = trend.critical;
            riskChart.data.datasets[1].data = trend.high;
            riskChart.data.datasets[2].data = trend.medium;
        } else {
            // Repo Mode: single dataset logic
            riskChart.data.labels = trend.labels; // ["Critical", "High", "Medium"]
            // trend.critical contains the values [c, h, m]
            riskChart.data.datasets[0].data = trend.critical;
        }
        riskChart.update('none');
    } else {
        const chartCtx = ctx.getContext('2d');
        let config;

        if (mode === 'global') {
            config = {
                type: 'bar',
                data: {
                    labels: trend.labels,
                    datasets: [
                        { label: 'Critical', data: trend.critical, backgroundColor: iosColors.red, borderRadius: 4 },
                        { label: 'High', data: trend.high, backgroundColor: iosColors.orange, borderRadius: 4 },
                        { label: 'Medium', data: trend.medium, backgroundColor: iosColors.yellow, borderRadius: 4 }
                    ]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    scales: {
                        x: { stacked: true, grid: { display: false }, ticks: { color: '#8E8E93' } },
                        y: { stacked: true, grid: { color: 'rgba(255,255,255,0.05)' }, ticks: { color: '#8E8E93' } }
                    },
                    plugins: { legend: { display: true, labels: { color: 'white' } } }
                }
            };
        } else {
            // Repo Mode
            config = {
                type: 'bar',
                data: {
                    labels: trend.labels,
                    datasets: [{
                        label: 'Results',
                        data: trend.critical, // [C, H, M]
                        backgroundColor: [iosColors.red, iosColors.orange, iosColors.yellow],
                        borderRadius: 6
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    scales: {
                        x: { grid: { display: false }, ticks: { color: '#8E8E93' } },
                        y: { grid: { color: 'rgba(255,255,255,0.05)' }, ticks: { color: '#8E8E93' } }
                    },
                    plugins: { legend: { display: false } }
                }
            };
        }

        riskChart = new Chart(chartCtx, config);
        riskChart._mode = mode;
    }
}

function updateToolChart(data) {
    const ctx = document.getElementById('toolChart');
    if (!ctx) return;

    const toolData = data.devsecops_metrics?.tool_distribution || {};
    const labels = Object.keys(toolData);
    const values = Object.values(toolData);

    const iosPalette = [
        '#0A84FF', '#30D158', '#5E5CE6', '#FF9F0A', '#FF375F', '#64D2FF'
    ];

    if (toolChart) {
        toolChart.data.labels = labels;
        toolChart.data.datasets[0].data = values;
        toolChart.update('none');
    } else {
        const chartCtx = ctx.getContext('2d');
        toolChart = new Chart(chartCtx, {
            type: 'doughnut',
            data: {
                labels: labels,
                datasets: [{
                    data: values,
                    backgroundColor: iosPalette,
                    borderWidth: 0
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                cutout: '70%',
                plugins: {
                    legend: { position: 'right', labels: { color: 'white', font: { size: 10 } } }
                }
            }
        });
    }
}

function updateAiFixChart(data) {
    const ctx = document.getElementById('aiFixChart');
    if (!ctx) return;

    const total = data.total_findings || 0;
    const fixed = data.ai_metrics?.auto_fixed || 0;
    const notFixed = Math.max(0, total - fixed);

    if (aiFixChart) {
        aiFixChart.data.datasets[0].data = [fixed, notFixed];
        aiFixChart.update('none');
    } else {
        const chartCtx = ctx.getContext('2d');
        aiFixChart = new Chart(chartCtx, {
            type: 'doughnut',
            data: {
                labels: ['Fix Available', 'No Fix'],
                datasets: [{
                    data: [fixed, notFixed],
                    backgroundColor: ['#30D158', '#3a3a3c'], // Green and Dark Gray
                    borderWidth: 0
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                cutout: '70%',
                plugins: {
                    legend: { position: 'bottom', labels: { color: 'white' } }
                }
            }
        });
    }
}

function updateCiChart(data) {
    const ctx = document.getElementById('ciChart');
    if (!ctx) return;

    const ciData = data.devsecops_metrics?.ci_distribution || {};

    if (ciChart) {
        ciChart.data.labels = Object.keys(ciData);
        ciChart.data.datasets[0].data = Object.values(ciData);
        ciChart.update('none');
    } else {
        const chartCtx = ctx.getContext('2d');
        ciChart = new Chart(chartCtx, {
            type: 'pie',
            data: {
                labels: Object.keys(ciData),
                datasets: [{
                    data: Object.values(ciData),
                    backgroundColor: ['#5E5CE6', '#BF5AF2', '#64D2FF', '#30D158'],
                    borderWidth: 0
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { position: 'right', labels: { color: 'white' } }
                }
            }
        });
    }
}
