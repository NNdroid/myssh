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

    // --- Theme Management (Auto / Light / Dark) ---
    const theme = {
        get: () => localStorage.getItem('theme') || 'auto',
        set: (mode) => {
            localStorage.setItem('theme', mode);
            theme.apply(mode);
        },
        apply: (mode) => {
            if (mode === 'light' || mode === 'dark') {
                document.documentElement.setAttribute('data-theme', mode);
            } else {
                // Auto mode: remove data-theme attribute so CSS @media (prefers-color-scheme) kicks in naturally
                document.documentElement.removeAttribute('data-theme');
            }
            const selector = el('theme-selector');
            if (selector && selector.value !== mode) {
                selector.value = mode;
            }
        },
        init: () => {
            const saved = theme.get();
            theme.apply(saved);

            const selector = el('theme-selector');
            if (selector) {
                selector.value = saved;
                selector.addEventListener('change', (e) => theme.set(e.target.value));
            }

            // 监听系统深浅色偏好动态变化
            if (window.matchMedia) {
                window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', () => {
                    if (theme.get() === 'auto') {
                        theme.apply('auto');
                    }
                });
            }
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
        document.querySelectorAll(selector).forEach(element => {
            element.style.display = isVisible ? '' : 'none';
        });
    };

    // 智能字节格式化：自动在 B/KB/MB/GB/TB 间换算
    const formatBytesSmart = (bytes, perSec = false) => {
        const units = ['B', 'KB', 'MB', 'GB', 'TB'];
        let v = Math.abs(Number(bytes) || 0);
        let i = 0;
        while (v >= 1024 && i < units.length - 1) { v /= 1024; i++; }
        const num = i === 0 ? String(Math.round(v)) : v.toFixed(2);
        return `${num} ${units[i]}${perSec ? '/s' : ''}`;
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
            const loginEl = el('login-overlay');
            loginEl.style.display = 'flex';
            loginEl.classList.add('active');
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
            const ind = el('status-indicator');
            const txt = el('status-text');
            const nodeTxt = el('status-node');
            const startBtn = el('start-btn');
            const stopBtn = el('stop-btn');

            if (state.status.running) {
                ind?.classList.add('connected');
                if (txt) txt.textContent = i18n.t('status_connected');
                const runningNode = state.nodes.find(n => n.id === state.status.running_node);
                if (nodeTxt) nodeTxt.textContent = runningNode ? `${i18n.t('status_node_prefix')}: ${runningNode.name}` : '-';
                if (startBtn) startBtn.style.display = 'none';
                if (stopBtn) stopBtn.style.display = 'inline-flex';
            } else {
                ind?.classList.remove('connected');
                if (txt) txt.textContent = i18n.t('status_disconnected');
                if (nodeTxt) nodeTxt.textContent = '-';
                if (startBtn) startBtn.style.display = 'inline-flex';
                if (stopBtn) stopBtn.style.display = 'none';
            }
        },
        nodes: () => {
            const list = el('node-list');
            if (!list) return;
            list.innerHTML = '';
            if (!state.nodes || state.nodes.length === 0) {
                const emptyDiv = document.createElement('div');
                emptyDiv.style.gridColumn = '1/-1';
                emptyDiv.style.textAlign = 'center';
                emptyDiv.style.padding = '40px 0';
                emptyDiv.style.color = 'var(--text-muted)';
                emptyDiv.textContent = i18n.t('text_no_nodes');
                list.appendChild(emptyDiv);
                return;
            }

            state.nodes.forEach(node => {
                const isRunning = state.status.running && state.status.running_node === node.id;
                const isSelected = state.selectedNodeId === node.id;

                const nodeCard = document.createElement('div');
                nodeCard.className = `card node-item ${isRunning ? 'running' : ''} ${isSelected ? 'selected' : ''}`;
                nodeCard.dataset.id = node.id;

                const nodeHeader = document.createElement('div');
                nodeHeader.className = 'node-header';

                const nodeTitle = document.createElement('h3');
                nodeTitle.className = 'node-title';
                nodeTitle.textContent = node.name;

                const badgesWrapper = document.createElement('div');
                badgesWrapper.style.display = 'flex';
                badgesWrapper.style.gap = '6px';

                if (isRunning) {
                    const runBadge = document.createElement('span');
                    runBadge.className = 'badge running';
                    runBadge.textContent = i18n.t('badge_running') || 'Running';
                    badgesWrapper.appendChild(runBadge);
                }

                const typeBadge = document.createElement('span');
                typeBadge.className = 'badge';
                typeBadge.textContent = (node.tunnelType || 'BASE').toUpperCase();
                badgesWrapper.appendChild(typeBadge);

                nodeHeader.appendChild(nodeTitle);
                nodeHeader.appendChild(badgesWrapper);

                const infoAddr = document.createElement('div');
                infoAddr.className = 'node-info-row';
                const addrLabel = document.createElement('span');
                addrLabel.textContent = i18n.t('label_ssh_addr');
                const addrVal = document.createElement('span');
                addrVal.textContent = node.sshAddr;
                infoAddr.appendChild(addrLabel);
                infoAddr.appendChild(addrVal);

                const infoUser = document.createElement('div');
                infoUser.className = 'node-info-row';
                const userLabel = document.createElement('span');
                userLabel.textContent = i18n.t('label_ssh_user');
                const userVal = document.createElement('span');
                userVal.textContent = node.user;
                infoUser.appendChild(userLabel);
                infoUser.appendChild(userVal);

                const infoTraffic = document.createElement('div');
                infoTraffic.className = 'node-info-row';
                const trafLabel = document.createElement('span');
                trafLabel.textContent = `${i18n.t('stat.total_tx')} / ${i18n.t('stat.total_rx')}`;
                const trafVal = document.createElement('span');
                trafVal.textContent = `↑${formatBytesSmart(node.totalTx || 0)} ↓${formatBytesSmart(node.totalRx || 0)}`;
                infoTraffic.appendChild(trafLabel);
                infoTraffic.appendChild(trafVal);

                const actions = document.createElement('div');
                actions.className = 'node-actions';

                if (!isRunning) {
                    const startBtn = document.createElement('button');
                    startBtn.className = 'btn btn-sm accent';
                    startBtn.dataset.action = 'start';
                    startBtn.dataset.id = node.id;
                    startBtn.textContent = i18n.t('btn_start') || 'Start';
                    actions.appendChild(startBtn);
                }

                const editBtn = document.createElement('button');
                editBtn.className = 'btn btn-sm';
                editBtn.dataset.action = 'edit';
                editBtn.dataset.id = node.id;
                editBtn.textContent = i18n.t('title_edit_node');

                const delBtn = document.createElement('button');
                delBtn.className = 'btn btn-sm danger';
                delBtn.dataset.action = 'delete';
                delBtn.dataset.id = node.id;
                delBtn.textContent = i18n.t('btn_delete');

                actions.appendChild(editBtn);
                actions.appendChild(delBtn);

                nodeCard.appendChild(nodeHeader);
                nodeCard.appendChild(infoAddr);
                nodeCard.appendChild(infoUser);
                nodeCard.appendChild(infoTraffic);
                nodeCard.appendChild(actions);

                list.appendChild(nodeCard);
            });
        },
        settings: () => {
            const form = el('settings-form');
            if (!form) return;
            for (const key in state.settings) {
                const input = form.elements[key];
                if (input) {
                    if (Array.isArray(state.settings[key])) {
                        input.value = state.settings[key].join(', ');
                    } else {
                        input.value = state.settings[key];
                    }
                }
            }
        },
        logs: (isIncremental = false) => {
            const logPre = el('logs');
            if (!logPre) return;
            if (isIncremental) {
                logPre.textContent += state.logs.content;
            } else {
                logPre.textContent = state.logs.content;
            }
            logPre.scrollTop = logPre.scrollHeight;
        }
    };

    // --- Modal Management ---
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
                        if (input.type === 'checkbox') input.checked = !!node[key];
                        else input.value = node[key] ?? '';
                    }
                }
            }
            modal.updateVisibility();
            const nodeModal = el('node-modal');
            nodeModal.style.display = 'flex';
            nodeModal.classList.add('active');
        },
        close: () => {
            const nodeModal = el('node-modal');
            nodeModal.classList.remove('active');
            setTimeout(() => { nodeModal.style.display = 'none'; }, 250);
        },
        updateVisibility: () => {
            const authType = el('authType').value;
            setVis('[data-auth="password"]', authType === 'password');
            setVis('[data-auth="key"]', authType === 'key');

            const tunnelType = el('tunnelType').value;
            const isHttp = tunnelType === 'http';
            const isBase = tunnelType === 'base';
            const isMasque = tunnelType === 'masque';
            const isDns = tunnelType === 'dns' || tunnelType === 'vaydns';
            const isWss = ['ws', 'wss'].includes(tunnelType);
            const isTls = ['tls', 'wss', 'h2', 'quic', 'xhttp', 'grpc', 'h3', 'wt', 'masque'].includes(tunnelType);
            const isCustomPathSupported = ['ws', 'wss', 'h2', 'h2c', 'grpc', 'grpcc', 'h3', 'wt', 'xhttp', 'xhttpc'].includes(tunnelType);
            
            setVis('[data-visibility-key="proxyAddr"]', !isBase && !isDns);
            setVis('[data-visibility-key="dnsTunnelFields"]', isDns);
            setVis('[data-visibility-key="customHost"]', !isBase && !isDns && tunnelType !== 'tls' && tunnelType !== 'quic');
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

    // --- iOS Confirm Helper ---
    const asyncConfirm = (message) => {
        return new Promise((resolve) => {
            const overlay = el('ios-confirm-overlay');
            const msgEl = el('ios-confirm-message');
            const cancelBtn = el('ios-confirm-cancel');
            const okBtn = el('ios-confirm-ok');

            if (!overlay || !msgEl) {
                resolve(confirm(message));
                return;
            }

            msgEl.textContent = message;
            overlay.classList.add('active');

            const cleanup = (result) => {
                overlay.classList.remove('active');
                cancelBtn.removeEventListener('click', onCancel);
                okBtn.removeEventListener('click', onOk);
                resolve(result);
            };

            const onCancel = () => cleanup(false);
            const onOk = () => cleanup(true);

            cancelBtn.addEventListener('click', onCancel);
            okBtn.addEventListener('click', onOk);
        });
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
                const loginEl = el('login-overlay');
                loginEl.style.display = 'none';
                loginEl.classList.remove('active');
                el('main-ui').style.display = 'block';
                showToast(i18n.t('alert_login_success'), 'success');
            } else {
                showToast(i18n.t('alert_login_failed'), 'error');
            }
        },
        navigate: (e) => {
            const tab = e.target.closest('.nav-tab');
            if (tab) {
                document.querySelectorAll('.panel-section, .nav-tab').forEach(item => item.classList.remove('active'));
                const targetPanel = el(tab.dataset.panel + '-panel');
                if (targetPanel) targetPanel.classList.add('active');
                tab.classList.add('active');
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
                    document.querySelectorAll('.node-item').forEach(item => item.classList.remove('selected'));
                    nodeItem.classList.add('selected');
                }
                return;
            }
            const { action, id } = button.dataset;
            if (action === 'start') {
                state.selectedNodeId = id;
                document.querySelectorAll('.node-item').forEach(item => item.classList.remove('selected'));
                e.target.closest('.node-item')?.classList.add('selected');
                await handlers.startProxy();
            } else if (action === 'edit') {
                modal.open(state.nodes.find(n => n.id === id));
            } else if (action === 'delete') {
                if (await asyncConfirm(i18n.t('alert_confirm_delete'))) {
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
            }
        },
        saveNode: async (e) => {
            e.preventDefault();
            const form = el('node-form');
            const formData = new FormData(form);
            const nodeData = Object.fromEntries(formData.entries());
            form.querySelectorAll('input[type="checkbox"]').forEach(cb => nodeData[cb.name] = cb.checked);
            
            let res;
            if (state.currentNodeId) {
                res = await api.put(`/nodes/${state.currentNodeId}`, nodeData);
            } else {
                res = await api.post('/nodes', nodeData);
            }

            if (res.message) {
                showToast(i18n.t('alert_save_success'), 'success');
                modal.close();
                await actions.fetchNodes();
            } else {
                showToast(`${i18n.t('alert_save_failed')}: ${res.error}`, 'error');
            }
        },
        startProxy: async () => {
            if (!state.selectedNodeId) {
                showToast(i18n.t('alert_select_node_to_start'), 'info');
                return;
            }
            if (state.status.running) {
                showToast(i18n.t('alert_already_running') || 'Proxy is already running', 'info');
                return;
            }
            setControlsLocked(true);
            showToast(i18n.t('alert_starting_proxy'), 'info');
            const res = await api.post('/start', { node_id: state.selectedNodeId });
            if (res.message) {
                showToast(i18n.t('status_connected'), 'success');
                await actions.fetchStatus();
                state.logs.lastFetchFull = true;
                await actions.fetchLogs();
            } else {
                showToast(`${i18n.t('alert_start_failed')}: ${res.error}`, 'error');
            }
            setControlsLocked(false);
        },
        stopProxy: async () => {
            setControlsLocked(true);
            const res = await api.post('/stop', {});
            if (res.message) {
                showToast(i18n.t('alert_stopped'), 'info');
                await actions.fetchStatus();
            } else {
                showToast(`${i18n.t('alert_stop_failed')}: ${res.error}`, 'error');
            }
            setControlsLocked(false);
        },
        clearLogs: async () => {
            if (await asyncConfirm(i18n.t('alert_confirm_clear_log'))) {
                const res = await api.post('/clear-log', {});
                if (res.message) {
                    showToast(i18n.t('alert_log_cleared'), 'info');
                    state.logs.content = '';
                    render.logs(false);
                } else {
                    showToast(res.error, 'error');
                }
            }
        },
        exportNodes: async () => {
            const res = await api.get('/nodes');
            if (Array.isArray(res)) {
                const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(res, null, 2));
                const downloadAnchor = document.createElement('a');
                downloadAnchor.setAttribute("href", dataStr);
                downloadAnchor.setAttribute("download", `myssh_nodes_${new Date().toISOString().slice(0, 10)}.json`);
                document.body.appendChild(downloadAnchor);
                downloadAnchor.click();
                downloadAnchor.remove();
            } else {
                showToast(i18n.t('alert_export_failed') || 'Export failed', 'error');
            }
        },
        handleImport: (e) => {
            const file = e.target.files[0];
            if (!file) return;
            const reader = new FileReader();
            reader.onload = async (event) => {
                try {
                    const importedNodes = JSON.parse(event.target.result);
                    if (!Array.isArray(importedNodes)) {
                        showToast(i18n.t('alert_import_invalid_json'), 'error');
                        return;
                    }
                    const res = await api.post('/nodes/import', importedNodes);
                    if (res.message) {
                        showToast(i18n.t('alert_import_success'), 'success');
                        await actions.fetchNodes();
                    } else {
                        showToast(`${i18n.t('alert_import_failed')}: ${res.error}`, 'error');
                    }
                } catch (err) {
                    showToast(`${i18n.t('alert_import_error')}: ${err.message}`, 'error');
                }
                e.target.value = '';
            };
            reader.readAsText(file);
        }
    };

    // --- Actions ---
    const actions = {
        fetchNodes: async () => {
            const res = await api.get('/nodes');
            if (Array.isArray(res)) {
                state.nodes = res;
                render.nodes();
            }
        },
        fetchSettings: async () => {
            const res = await api.get('/settings');
            if (res && !res.error) {
                state.settings = res;
                render.settings();
            }
        },
        fetchStatus: async () => {
            const res = await api.get('/status');
            if (res && !res.error) {
                state.status = res;
                render.status();
                if (res.metrics) {
                    if (el('sysCpu')) el('sysCpu').textContent = `${(res.metrics.cpu_usage || 0).toFixed(1)}%`;
                    if (el('sysMem')) el('sysMem').textContent = `${(res.metrics.memory_alloc || 0).toFixed(1)} / ${(res.metrics.memory_sys || 0).toFixed(1)} MB`;
                    if (el('sysGoroutine')) el('sysGoroutine').textContent = res.metrics.goroutines || 0;
                    if (el('trafRateTx')) el('trafRateTx').textContent = formatBytesSmart(res.metrics.bytes_sent_per_sec || 0, true);
                    if (el('trafRateRx')) el('trafRateRx').textContent = formatBytesSmart(res.metrics.bytes_recv_per_sec || 0, true);
                    if (el('trafTotalTx')) el('trafTotalTx').textContent = formatBytesSmart(res.metrics.total_bytes_sent || 0);
                    if (el('trafTotalRx')) el('trafTotalRx').textContent = formatBytesSmart(res.metrics.total_bytes_recv || 0);
                    if (el('trafConnsActive')) el('trafConnsActive').textContent = `${res.metrics.active_conns || 0} / ${res.metrics.total_conns || 0}`;

                    const domainList = el('domainList');
                    if (domainList) {
                        domainList.innerHTML = '';
                        if (res.metrics.top_domains && res.metrics.top_domains.length > 0) {
                            res.metrics.top_domains.forEach(d => {
                                const li = document.createElement('li');
                                li.className = 'domain-item';
                                const dSpan = document.createElement('span');
                                dSpan.textContent = d.domain;
                                const cSpan = document.createElement('span');
                                cSpan.textContent = d.count;
                                li.appendChild(dSpan);
                                li.appendChild(cSpan);
                                domainList.appendChild(li);
                            });
                        } else {
                            const li = document.createElement('li');
                            li.className = 'domain-item';
                            li.textContent = i18n.t('text_no_domains') || 'No active domains';
                            domainList.appendChild(li);
                        }
                    }
                }
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
            // 初始化主题
            theme.init();

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
            bind('log-level-select', 'change', async (e) => {
                const level = e.target.value;
                try {
                    await api.post('/loglevel', { level });
                    showToast(`Log level updated to ${level.toUpperCase()}`);
                } catch (err) {
                    showToast(`Failed to update log level: ${err.message}`, 'error');
                }
            });
            bind('start-btn', 'click', handlers.startProxy);
            bind('stop-btn', 'click', handlers.stopProxy);
            bind('export-btn', 'click', handlers.exportNodes);
            bind('import-btn', 'click', () => el('import-file-input').click());
            bind('import-file-input', 'change', handlers.handleImport);

            if (localStorage.getItem('jwt_token')) {
                await actions.start();
                const loginEl = el('login-overlay');
                loginEl.style.display = 'none';
                loginEl.classList.remove('active');
                el('main-ui').style.display = 'block';
            } else {
                const loginEl = el('login-overlay');
                loginEl.style.display = 'flex';
                loginEl.classList.add('active');
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