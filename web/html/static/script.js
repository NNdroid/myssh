document.addEventListener('DOMContentLoaded', () => {
    // --- i18n Dictionary ---
    let translations = {};

    // 智能检测语言逻辑
    const detectLanguage = () => {
        const savedLang = localStorage.getItem('lang');
        if (savedLang) return savedLang;
        const browserLang = navigator.language || navigator.userLanguage;
        if (browserLang.toLowerCase().startsWith('zh')) return 'zh-CN';
        return 'en';
    };

    let currentLang = detectLanguage();
    if (!localStorage.getItem('lang')) {
        localStorage.setItem('lang', currentLang);
    }

    const i18n = {
        t: (key, ...args) => {
            let translation = translations[currentLang]?.[key] || translations['en']?.[key] || key;
            if (args.length > 0) {
                args.forEach((arg, index) => {
                    translation = translation.replace(`{${index}}`, arg);
                });
            }
            return translation;
        },
        setLang: (lang) => {
            currentLang = lang;
            localStorage.setItem('lang', lang);
            i18n.updateUI();
        },
        updateUI: () => {
            document.querySelectorAll('[data-i18n]').forEach(el => {
                const key = el.dataset.i18n;
                el.textContent = i18n.t(key);
            });
            document.querySelectorAll('[data-i18n-placeholder]').forEach(el => {
                const key = el.dataset.i18nPlaceholder;
                el.placeholder = i18n.t(key);
            });
            render.status();
            render.nodes();
        }
    };

    // --- Toast System ---
    const showToast = (message, type = 'info') => {
        const container = document.getElementById('toast-container');
        if (!container) return;
        const toast = document.createElement('div');
        toast.className = `toast ${type}`;
        
        const textSpan = document.createElement('span');
        textSpan.textContent = message;
        toast.appendChild(textSpan);

        const closeBtn = document.createElement('span');
        closeBtn.className = 'toast-close';
        closeBtn.innerHTML = '&times;';
        closeBtn.onclick = () => {
            clearTimeout(timeoutId);
            toast.classList.add('fade-out');
            toast.addEventListener('transitionend', () => toast.remove());
        };
        toast.appendChild(closeBtn);

        container.appendChild(toast);
        requestAnimationFrame(() => {
            toast.style.opacity = '1';
        });
        
        const timeoutId = setTimeout(() => {
            if (toast.parentElement) {
                toast.classList.add('fade-out');
                toast.addEventListener('transitionend', () => toast.remove());
            }
        }, 5000);
    };

    // --- Global State & Elements ---
    let state = {
        nodes: [],
        settings: {},
        status: { running: false, running_node: "" },
        logs: { content: '', lastFetchFull: true },
        currentNodeId: null,
        controlsLocked: false,
    };

    const el = (id) => document.getElementById(id);
    const setVis = (selector, isVisible) => {
        const element = document.querySelector(selector);
        if (element) element.style.display = isVisible ? '' : 'none';
    };

    // --- Control Locking ---
    const setControlsLocked = (locked) => {
        state.controlsLocked = locked;
        document.querySelectorAll('button:not([data-panel])').forEach(button => {
            button.disabled = locked;
        });
        const startBtn = el('start-btn');
        if (startBtn) {
            startBtn.textContent = locked ? i18n.t('btn_starting') : i18n.t('btn_start_proxy');
        }
    };

    // --- API Helper ---
    const getHeaders = (isFormData = false) => {
        const headers = {};
        const token = localStorage.getItem('jwt_token');
        if (token) headers['Authorization'] = `Bearer ${token}`;
        if (!isFormData) headers['Content-Type'] = 'application/json';
        return headers;
    };

    const handleAuthError = (res) => {
        if (res.status === 401) {
            localStorage.removeItem('jwt_token');
            el('login-overlay').style.display = 'flex';
            el('main-ui').style.display = 'none';
            throw new Error('Unauthorized');
        }
        return res;
    };

    const api = {
        get: (endpoint) => fetch(`/api/v1${endpoint}`, { headers: getHeaders() }).then(handleAuthError).then(res => res.json()).catch(e => { console.error(e); return {}; }),
        post: (endpoint, body) => fetch(`/api/v1${endpoint}`, { method: 'POST', headers: getHeaders(), body: JSON.stringify(body) }).then(handleAuthError).then(res => res.json()).catch(e => { console.error(e); return { error: e.message }; }),
        put: (endpoint, body) => fetch(`/api/v1${endpoint}`, { method: 'PUT', headers: getHeaders(), body: JSON.stringify(body) }).then(handleAuthError).then(res => res.json()).catch(e => { console.error(e); return { error: e.message }; }),
        delete: (endpoint) => fetch(`/api/v1${endpoint}`, { method: 'DELETE', headers: getHeaders() }).then(handleAuthError).then(res => res.json()).catch(e => { console.error(e); return { error: e.message }; }),
    };

    // --- Render Functions ---
    const render = {
        status: () => {
            const { running, running_node, sys_cpu, sys_mem, sys_goroutine, traf_rate, traf_total, traf_conns, top_domains } = state.status;
            
            // --- 原有的基础状态更新 ---
            el('status-indicator').classList.toggle('active', running);
            el('status-text').textContent = running ? i18n.t('status_connected') : i18n.t('status_disconnected');
            const runningNode = state.nodes.find(n => n.id === running_node);
            el('status-node').textContent = runningNode ? `${i18n.t('status_node_prefix')}: ${runningNode.name}` : '-';
            el('start-btn').style.display = running ? 'none' : 'block';
            el('stop-btn').style.display = running ? 'block' : 'none';

            // --- 新增：渲染系统资源和流量统计 ---
            if (el('sysCpu')) el('sysCpu').textContent = sys_cpu || '0.0%';
            if (el('sysMem')) el('sysMem').textContent = sys_mem || '0/0 MB';
            if (el('sysGoroutine')) el('sysGoroutine').textContent = sys_goroutine || '0';

            if (el('trafRate')) el('trafRate').textContent = traf_rate || '0/0 KB/s';
            if (el('trafTotal')) el('trafTotal').textContent = traf_total || '0/0 MB';
            if (el('trafConns')) el('trafConns').textContent = traf_conns || '0/0';

            // --- 新增：渲染热门域名 ---
            const domainListEl = el('domainList');
            if (domainListEl) {
                domainListEl.innerHTML = '';
                if (!top_domains || top_domains.length === 0) {
                    domainListEl.innerHTML = `<li class="empty-state">${i18n.t('text_no_nodes')}</li>`; // 或者添加一个 "No active domains" 的翻译
                } else {
                    top_domains.forEach(d => {
                        const li = document.createElement('li');
                        const txMB = (d.tx_rate / 1024).toFixed(1);
                        const rxMB = (d.rx_rate / 1024).toFixed(1);
                        li.innerHTML = `<span class="domain-name">${d.domain}</span><span class="domain-rates">↑${txMB} ↓${rxMB} KB/s</span>`;
                        domainListEl.appendChild(li);
                    });
                }
            }
        },
        nodes: () => {
            const list = el('node-list');
            list.innerHTML = '';
            if (!Array.isArray(state.nodes) || state.nodes.length === 0) {
                list.innerHTML = `<p style="text-align:center; color: #aaa;">${i18n.t('text_no_nodes')}</p>`;
                return;
            }
            state.nodes.forEach(node => {
                const item = document.createElement('div');
                item.className = 'node-item';
                item.innerHTML = `
                    <div class="node-item-info">
                        <h4>${node.name} <span class="node-tag">${node.tunnelType || 'base'}</span></h4>
                        <p>${node.user}@${node.sshAddr}</p>
                    </div>
                    <div class="node-actions">
                        <button class="primary" data-action="start" data-id="${node.id}">${i18n.t('btn_start_proxy')}</button>
                        <button data-action="edit" data-id="${node.id}">${i18n.t('title_edit_node')}</button>
                        <button class="danger" data-action="delete" data-id="${node.id}">${i18n.t('btn_delete')}</button>
                    </div>
                `;
                list.appendChild(item);
            });
        },
        logs: (isIncremental) => {
            const logsEl = el('logs');
            if (isIncremental) logsEl.textContent += state.logs.content;
            else logsEl.textContent = state.logs.content;
            logsEl.scrollTop = logsEl.scrollHeight;
        },
    };

    // --- Modal Logic ---
    const modal = {
        open: (node = null) => {
            const form = el('node-form');
            form.reset();
            state.currentNodeId = node ? node.id : null;
            el('modal-title').textContent = node ? i18n.t('title_edit_node') : i18n.t('title_add_node');
            if (node) {
                for (const key in node) {
                    const input = form.elements[key];
                    if (input) {
                        if (input.type === 'checkbox') input.checked = node[key];
                        else input.value = node[key];
                    }
                }
            }
            modal.updateVisibility();
            el('node-modal').style.display = 'flex';
        },
        close: () => el('node-modal').style.display = 'none',
        updateVisibility: () => {
            const authType = el('authType').value;
            setVis('[data-auth="password"]', authType === 'password');
            setVis('[data-auth="key"]', authType === 'key');

            const tunnelType = el('tunnelType').value;
            const isHttp = tunnelType === 'http';
            const isBase = tunnelType === 'base';
            const isMasque = tunnelType === 'masque';
            const isWss = ['ws', 'wss'].includes(tunnelType);
            const isTls = ['tls', 'wss', 'h2', 'quic', 'xhttp', 'grpc', 'h3', 'wt', 'masque'].includes(tunnelType);
            const isCustomPathSupported = ['ws', 'wss', 'h2', 'h2c', 'grpc', 'grpcc', 'h3', 'wt', 'xhttp', 'xhttpc'].includes(tunnelType);
            
            setVis('[data-visibility-key="proxyAddr"]', !isBase);
            setVis('[data-visibility-key="customHost"]', !isBase && tunnelType !== 'tls' && tunnelType !== 'quic');
            setVis('[data-visibility-key="serverName"]', isTls);
            setVis('[data-visibility-key="httpPayload"]', isHttp);

            setVis('[data-visibility-key="enableCustomPath"]', isMasque);
            if (!isMasque && !el('enableCustomPath').checked) {
                el('enableCustomPath').checked = true;
            }
            const showCustomPath = (isMasque && el('enableCustomPath').checked) || isCustomPathSupported;
            setVis('[data-visibility-key="customPath"]', showCustomPath);

            const proxyAuth = el('proxyAuthRequired').checked;
            const supportsProxyAuth = ['h2', 'h2c', 'grpc', 'grpcc', 'h3', 'wt', 'masque', 'xhttp', 'xhttpc', 'ws', 'wss', 'http'].includes(tunnelType);
            setVis('[data-visibility-key="proxyAuthToken"]', proxyAuth && supportsProxyAuth && !isWss && !isHttp);
            setVis('[data-visibility-key="proxyAuthUserPass"]', proxyAuth && supportsProxyAuth && (isWss || isHttp));

            setVis('[data-visibility-key="dnsOverrideFields"]', el('dnsOverride').checked);
            setVis('[data-visibility-key="routingOverrideFields"]', el('routingOverride').checked);
            
            setVis('[data-visibility-key="serverFingerprint"]', el('verifyFingerprint').checked);
            
            const supportsCertFingerprint = ['tls', 'wss', 'h2', 'quic', 'grpc', 'h3', 'wt', 'masque', 'xhttp'].includes(tunnelType);
            setVis('[data-visibility-key="verifyCertFingerprint"]', supportsCertFingerprint);
            setVis('[data-visibility-key="serverCertFingerprint"]', supportsCertFingerprint && el('verifyCertFingerprint').checked);

            const isXhttp = tunnelType === 'xhttp';
            const isXhttpc = tunnelType === 'xhttpc';
            setVis('[data-visibility-key="alpn"]', isXhttp || isXhttpc);
        }
    };

    // --- Event Handlers ---
    const handlers = {
        loginSubmit: async (e) => {
            e.preventDefault();
            const res = await fetch('/api/v1/login', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username: el('login-user').value, password: el('login-pass').value })
            });
            if (res.ok) {
                const data = await res.json();
                localStorage.setItem('jwt_token', data.token);
                await actions.start();
                el('login-overlay').style.display = 'none';
                el('main-ui').style.display = 'block';
                showToast(i18n.t('alert_login_success'), 'success');
            } else {
                showToast(i18n.t('alert_login_failed'), 'error');
            }
        },
        navigate: (e) => {
            if (e.target.matches('.nav-tab')) {
                document.querySelectorAll('.panel-section, .nav-tab').forEach(el => el.classList.remove('active'));
                el(e.target.dataset.panel + '-panel').classList.add('active');
                e.target.classList.add('active');
            }
        },
        saveSettings: async (e) => {
            e.preventDefault();
            const form = el('settings-form');
            const formData = new FormData(form);
            const newSettings = {};
            for (const [key, value] of formData.entries()) {
                newSettings[key] = (key === 'direct_site_tags' || key === 'direct_ip_tags') ? value.split(',').map(s => s.trim()).filter(Boolean) : value;
            }
            const res = await api.post('/settings', newSettings);
            if (res.message) {
                showToast(i18n.t('alert_settings_saved'), 'success');
                state.settings = newSettings;
            } else {
                showToast(`${i18n.t('alert_save_failed')}: ${res.error}`, 'error');
            }
        },
        nodeListClick: async (e) => {
            if (state.controlsLocked) return;
            const button = e.target.closest('button');
            if (!button) {
                const nodeItem = e.target.closest('.node-item');
                if (nodeItem) {
                    state.selectedNodeId = nodeItem.dataset.id;
                    document.querySelectorAll('.node-item').forEach(el => el.classList.remove('selected'));
                    nodeItem.classList.add('selected');
                }
                return;
            }
            const { action, id } = button.dataset;
            if (action === 'edit') {
                modal.open(state.nodes.find(n => n.id === id));
            } else if (action === 'delete') {
                if (confirm(i18n.t('alert_confirm_delete'))) {
                    const res = await api.delete(`/nodes/${id}`);
                    if (res.message) {
                        showToast(i18n.t('alert_delete_success'), 'success');
                        if (state.selectedNodeId === id) {
                            state.selectedNodeId = null;
                        }
                        await actions.fetchNodes();
                    } else {
                        showToast(`${i18n.t('alert_delete_failed')}: ${res.error}`, 'error');
                    }
                }
            } else if (action === 'start') {
                 setControlsLocked(true);
                 const res = await api.post('/start', { node_id: id });
                 if (res.message) {
                     showToast(i18n.t('alert_starting_proxy'), 'info');
                     await actions.fetchStatus();
                 } else {
                     showToast(`${i18n.t('alert_start_failed')}: ${res.error}`, 'error');
                 }
                 setControlsLocked(false);
            }
        },
        saveNode: async (e) => {
            e.preventDefault();
            const form = el('node-form');
            const formData = new FormData(form);
            const nodeData = Object.fromEntries(formData.entries());
            form.querySelectorAll('input[type="checkbox"]').forEach(cb => nodeData[cb.name] = cb.checked);
            if (nodeData.filterMode) nodeData.filterMode = parseInt(nodeData.filterMode, 10);
            
            const res = state.currentNodeId ? await api.put(`/nodes/${state.currentNodeId}`, nodeData) : await api.post('/nodes', nodeData);
            if (res.error) {
                showToast(`${i18n.t('alert_save_failed')}: ${res.error}`, 'error');
            } else {
                showToast(i18n.t('alert_save_success'), 'success');
                modal.close();
                await actions.fetchNodes();
            }
        },
        clearLogs: async () => {
            if (confirm(i18n.t('alert_confirm_clear_log'))) {
                const res = await api.post('/log-clear');
                if (res.message) {
                    state.logs.content = '';
                    render.logs(false);
                    showToast(i18n.t('alert_log_cleared'), 'success');
                }
            }
        },
        exportNodes: async () => {
            const res = await fetch('/api/v1/nodes/export', { headers: getHeaders() });
            if (!res.ok) return handleAuthError(res);
            const blob = await res.blob();
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = 'myssh_profiles.json';
            document.body.appendChild(a);
            a.click();
            a.remove();
            window.URL.revokeObjectURL(url);
        },
        handleImport: async (e) => {
            const file = e.target.files[0];
            if (!file) return;
            const formData = new FormData();
            formData.append('file', file);
            const res = await fetch('/api/v1/nodes/import', { method: 'POST', headers: getHeaders(true), body: formData });
            const data = await res.json();
            if (res.ok) {
                showToast(data.message, 'success');
                await actions.fetchNodes();
            } else {
                showToast(`${i18n.t('alert_import_failed')}: ${data.error}`, 'error');
            }
            e.target.value = '';
        },
        stopProxy: async () => {
            const res = await api.post('/stop');
            if (res.message) {
                showToast(i18n.t('alert_stopped'), 'success');
                await actions.fetchStatus();
            } else {
                showToast(`${i18n.t('alert_stop_failed')}: ${res.error}`, 'error');
            }
        },
        startProxy: async () => {
            showToast(i18n.t('alert_select_node_to_start'), 'error');
        },
    };

    // --- Main Actions ---
    const actions = {
        fetchStatus: async () => { state.status = await api.get('/dashboard-stats'); render.status(); },
        fetchNodes: async () => { 
            const data = await api.get('/nodes');
            state.nodes = Array.isArray(data) ? data : []; 
            render.nodes(); 
            render.status(); 
        },
        fetchSettings: async () => {
            state.settings = await api.get('/settings');
            const form = el('settings-form');
            for (const key in state.settings) {
                const input = form.elements[key];
                if (input) input.value = Array.isArray(state.settings[key]) ? state.settings[key].join(',') : state.settings[key];
            }
        },
        fetchLogs: async () => {
            const mode = state.logs.lastFetchFull ? 'full' : 'incremental';
            const res = await fetch(`/api/v1/log-raw?mode=${mode}`, { headers: getHeaders() });
            if (!res.ok) return handleAuthError(res);
            const logText = await res.text();
            if (logText) {
                state.logs.content = logText;
                render.logs(mode === 'incremental');
            }
            state.logs.lastFetchFull = false;
        },
        init: async () => {
            try {
                const res = await fetch('/static/locales.json');
                translations = await res.json();
                
                // 动态生成语言选择器
                const langSelector = el('lang-selector');
                if (langSelector) {
                    langSelector.innerHTML = '';
                    for (const langCode in translations) {
                        const option = document.createElement('option');
                        option.value = langCode;
                        option.textContent = translations[langCode]['_lang_display_name_'] || langCode;
                        langSelector.appendChild(option);
                    }
                    langSelector.value = currentLang;
                    langSelector.addEventListener('change', (e) => i18n.setLang(e.target.value));
                }
            } catch (e) { console.error("Failed to load translations", e); }

            const bind = (id, event, handler) => el(id)?.addEventListener(event, handler);
            
            bind('login-form', 'submit', handlers.loginSubmit);
            document.querySelector('.nav-buttons')?.addEventListener('click', handlers.navigate);
            bind('add-node-btn', 'click', () => modal.open());
            bind('close-modal-btn', 'click', modal.close);
            el('node-modal')?.addEventListener('click', (e) => { if(e.target === el('node-modal')) modal.close(); });
            
            el('node-form')?.addEventListener('change', (e) => {
                if (e.target.matches('#authType, #tunnelType, #proxyAuthRequired, #dnsOverride, #routingOverride, #verifyFingerprint, #verifyCertFingerprint, #enableCustomPath')) {
                    modal.updateVisibility();
                }
            });

            bind('node-form', 'submit', handlers.saveNode);
            bind('settings-form', 'submit', handlers.saveSettings);
            bind('node-list', 'click', handlers.nodeListClick);
            bind('clear-log-btn', 'click', handlers.clearLogs);
            bind('start-btn', 'click', handlers.startProxy);
            bind('stop-btn', 'click', handlers.stopProxy);
            bind('export-btn', 'click', handlers.exportNodes);
            bind('import-btn', 'click', () => el('import-file-input').click());
            bind('import-file-input', 'change', handlers.handleImport);

            if (localStorage.getItem('jwt_token')) {
                await actions.start();
                el('login-overlay').style.display = 'none';
                el('main-ui').style.display = 'block';
            } else {
                el('login-overlay').style.display = 'flex';
                el('main-ui').style.display = 'none';
            }
            i18n.updateUI();
            document.body.classList.add('loaded');
        },
        start: async () => {
            setControlsLocked(true);
            await Promise.all([
                actions.fetchNodes(),
                actions.fetchSettings(),
                actions.fetchStatus(),
            ]);
            await actions.fetchLogs();
            setControlsLocked(false);
            
            setInterval(actions.fetchStatus, 5000);
            setInterval(actions.fetchLogs, 2000);
        }
    };

    actions.init();
});