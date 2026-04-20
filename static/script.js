// グローバル変数
let scanInterval = null;
let hostsData = {};

// ローカルホストかどうかを判定
function isLocalHost(host) {
    // localhostまたは127.x.x.x
    if (host === 'localhost' || host.startsWith('127.')) {
        return true;
    }
    // プライベートIPアドレス範囲をチェック
    const parts = host.split('.');
    if (parts.length === 4) {
        const first = parseInt(parts[0]);
        const second = parseInt(parts[1]);
        // 192.168.x.x
        if (first === 192 && second === 168) {
            return true;
        }
        // 10.x.x.x
        if (first === 10) {
            return true;
        }
        // 172.16.x.x ~ 172.31.x.x
        if (first === 172 && second >= 16 && second <= 31) {
            return true;
        }
    }
    return false;
}

// ページ読み込み時の初期化
document.addEventListener('DOMContentLoaded', function() {
    console.log('LocalNetScan initialized');

    // イベントリスナーの設定
    document.getElementById('rescanBtn').addEventListener('click', startScan);

    // サンプルクリックで入力フィールドに設定
    document.querySelectorAll('.example-item').forEach(item => {
        item.addEventListener('click', function() {
            document.getElementById('targetRange').value = this.textContent;
        });
    });

    // Enterキーでスキャン開始
    document.getElementById('targetRange').addEventListener('keypress', function(e) {
        if (e.key === 'Enter') {
            startScan();
        }
    });

    // 初回データ取得
    loadResults();
    checkScanStatus();
});

// スキャンを開始
async function startScan() {
    const btn = document.getElementById('rescanBtn');
    const targetRangeInput = document.getElementById('targetRange');
    const targetRange = targetRangeInput.value.trim();

    btn.disabled = true;

    try {
        const requestBody = {};
        if (targetRange) {
            requestBody.target_range = targetRange;
        }

        const response = await fetch('/api/scan', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(requestBody)
        });

        const data = await response.json();

        if (data.status === 'success') {
            const message = targetRange
                ? `スキャンを開始しました: ${targetRange}`
                : 'スキャンを開始しました（自動検出）';
            showNotification(message, 'success');
            monitorScanProgress();
        } else {
            showNotification(data.message, 'error');
            btn.disabled = false;
        }
    } catch (error) {
        console.error('スキャン開始エラー:', error);
        showNotification('スキャン開始に失敗しました', 'error');
        btn.disabled = false;
    }
}

// スキャン進捗を監視
function monitorScanProgress() {
    const scanStatus = document.getElementById('scanStatus');
    scanStatus.classList.remove('hidden');

    // 既存のインターバルをクリア
    if (scanInterval) {
        clearInterval(scanInterval);
    }

    // 定期的にステータスをチェック
    scanInterval = setInterval(checkScanStatus, 1000);
}

// スキャンステータスをチェック
async function checkScanStatus() {
    try {
        const response = await fetch('/api/scan-status');
        const status = await response.json();

        const scanStatus = document.getElementById('scanStatus');
        const progressBar = document.getElementById('progressBar');
        const progressText = document.getElementById('progressText');
        const rescanBtn = document.getElementById('rescanBtn');

        // nmapが利用できない場合は警告を表示
        if (status.nmap_available === false) {
            showNmapWarning(status.nmap_error);
            rescanBtn.disabled = true;
            return;
        }

        if (status.is_scanning) {
            scanStatus.classList.remove('hidden');
            progressBar.style.width = status.scan_progress + '%';

            // 見つかったホスト数を表示
            const hostsInfo = status.found_hosts > 0 ? ` - ${status.found_hosts}台検出` : '';
            progressText.textContent = `スキャン中... ${status.scan_progress}%${hostsInfo} (${status.current_subnet})`;
            rescanBtn.disabled = true;
        } else {
            scanStatus.classList.add('hidden');
            progressBar.style.width = '0%';
            rescanBtn.disabled = false;

            // スキャン完了時に結果を読み込み
            if (scanInterval) {
                clearInterval(scanInterval);
                scanInterval = null;
                loadResults();
            }

            // 最終スキャン時刻を更新
            if (status.last_scan_time) {
                document.getElementById('lastScanTime').textContent =
                    '最終スキャン: ' + status.last_scan_time;
            }
        }
    } catch (error) {
        console.error('ステータス取得エラー:', error);
    }
}

// nmapの警告を表示
function showNmapWarning(error) {
    const tbody = document.getElementById('hostsTableBody');
    tbody.innerHTML = `
        <tr class="no-data">
            <td colspan="5" style="padding: 40px; text-align: left;">
                <div style="background: #fff3cd; border: 2px solid #ffc107; border-radius: 8px; padding: 20px;">
                    <h3 style="color: #856404; margin-bottom: 15px;">⚠️ nmapがインストールされていません</h3>
                    <p style="color: #856404; margin-bottom: 10px;">
                        LocalNetScanを使用するには、システムにnmapをインストールする必要があります。
                    </p>
                    <div style="background: white; padding: 15px; border-radius: 4px; margin-top: 15px;">
                        <h4 style="color: #333; margin-bottom: 10px;">インストール方法:</h4>
                        <p style="color: #333; margin-bottom: 5px;"><strong>macOS:</strong></p>
                        <code style="background: #f5f5f5; padding: 5px 10px; border-radius: 3px; display: block; margin-bottom: 10px;">brew install nmap</code>

                        <p style="color: #333; margin-bottom: 5px;"><strong>Ubuntu/Debian:</strong></p>
                        <code style="background: #f5f5f5; padding: 5px 10px; border-radius: 3px; display: block; margin-bottom: 10px;">sudo apt-get update && sudo apt-get install nmap</code>

                        <p style="color: #333; margin-bottom: 5px;"><strong>Windows:</strong></p>
                        <p style="color: #666;">https://nmap.org/download.html からダウンロード</p>
                    </div>
                    <p style="color: #856404; margin-top: 15px; font-size: 0.9em;">
                        インストール後、アプリケーションを再起動してください。
                    </p>
                </div>
            </td>
        </tr>
    `;
}

// スキャン結果を読み込み
async function loadResults() {
    try {
        const response = await fetch('/api/results');
        const data = await response.json();

        hostsData = data.hosts;
        displayHosts(hostsData);

        // ホスト数を更新
        document.getElementById('hostCount').textContent =
            '検出ホスト数: ' + data.total;
    } catch (error) {
        console.error('結果取得エラー:', error);
    }
}

// ホスト一覧を表示（カード形式）
function displayHosts(hosts) {
    const container = document.getElementById('hostsContainer');
    container.innerHTML = '';

    if (Object.keys(hosts).length === 0) {
        container.innerHTML = '<div style="text-align: center; padding: 40px; color: #999;">ホストが見つかりませんでした</div>';
        return;
    }

    for (const [ip, info] of Object.entries(hosts)) {
        const card = createHostCard(ip, info);
        container.appendChild(card);
    }
}

// ホストカードを作成
function createHostCard(ip, info) {
    const card = document.createElement('div');
    card.className = 'host-card';
    card.id = `host-${ip.replace(/\./g, '-')}`;

    card.innerHTML = `
        <div class="card-header" onclick="toggleCard('${ip}')">
            <div class="card-title">
                <h3>${ip}</h3>
                <span class="status-badge up">Online</span>
            </div>
            <span class="card-toggle" id="toggle-${ip.replace(/\./g, '-')}">▼</span>
        </div>
        <div class="card-body" id="body-${ip.replace(/\./g, '-')}">
            <!-- セクション1: PING/物理アクセス -->
            <div class="section">
                <div class="section-header">
                    <div class="section-title">
                        <span class="section-icon">📡</span>
                        物理アクセス
                    </div>
                </div>
                <div class="info-grid">
                    <span class="info-label">状態:</span>
                    <span class="info-value">✓ PING応答あり</span>
                    <span class="info-label">サブネット:</span>
                    <span class="info-value">${info.subnet || '-'}</span>
                </div>
            </div>

            <!-- セクション2: マシン情報 -->
            <div class="section">
                <div class="section-header">
                    <div class="section-title">
                        <span class="section-icon">💻</span>
                        マシン情報
                    </div>
                </div>
                <div class="info-grid">
                    <span class="info-label">ホスト名:</span>
                    <span class="info-value">${info.hostname || 'Unknown'}</span>
                    <span class="info-label">ベンダー:</span>
                    <span class="info-value">${info.vendor || '-'}</span>
                </div>
            </div>

            <!-- セクション3: ポートスキャン -->
            <div class="section">
                <div class="section-header">
                    <div class="section-title">
                        <span class="section-icon">🔌</span>
                        ポート情報
                    </div>
                </div>
                <div class="card-actions">
                    <button class="btn btn-primary btn-small" onclick="openPortScanConfig('${ip}')">
                        ポートスキャン実行
                    </button>
                </div>
                <div id="ports-${ip.replace(/\./g, '-')}" class="ports-list" style="margin-top: 15px;">
                    <p style="color: #999; font-size: 0.9rem;">ポートスキャンを実行してください</p>
                </div>
            </div>
        </div>
    `;

    return card;
}

// カードの開閉（排他制御）
function toggleCard(ip) {
    const bodyId = `body-${ip.replace(/\./g, '-')}`;
    const toggleId = `toggle-${ip.replace(/\./g, '-')}`;
    const body = document.getElementById(bodyId);
    const toggle = document.getElementById(toggleId);

    const isCurrentlyExpanded = body.classList.contains('expanded');

    // 全てのカードを閉じる
    document.querySelectorAll('.card-body').forEach(b => {
        b.classList.remove('expanded');
    });
    document.querySelectorAll('.card-toggle').forEach(t => {
        t.classList.remove('expanded');
    });

    // クリックされたカードが閉じていた場合は開く
    if (!isCurrentlyExpanded) {
        body.classList.add('expanded');
        toggle.classList.add('expanded');
    }
}

// ポートスキャン設定モーダルを開く
let currentScanHost = null;

function openPortScanConfig(ip) {
    currentScanHost = ip;
    const modal = document.getElementById('portScanConfigModal');
    modal.classList.remove('hidden');

    // デフォルトのコマンドを設定
    document.getElementById('scanCommand').value = '-sT -sV';
}

// ポートスキャン設定モーダルを閉じる
function closePortScanConfig() {
    const modal = document.getElementById('portScanConfigModal');
    modal.classList.add('hidden');
    currentScanHost = null;
}

// ポートスキャンを実行
async function executePortScan() {
    if (!currentScanHost) {
        showNotification('スキャン対象ホストが指定されていません', 'error');
        return;
    }

    const scanCommand = document.getElementById('scanCommand').value.trim();
    if (!scanCommand) {
        showNotification('スキャンコマンドを入力してください', 'error');
        return;
    }

    // スキャンモードを取得
    const scanMode = document.querySelector('input[name="scanMode"]:checked').value;

    // ホストを一時変数に保存（モーダルを閉じる前に）
    const targetHost = currentScanHost;

    // モーダルを閉じる
    closePortScanConfig();

    // タブUIを作成（初期表示から優先ポート・全ポートのタブを表示、スキャンモードを渡す）
    createPortScanTabs(targetHost, scanMode);

    try {
        const response = await fetch(`/api/port-scan/${targetHost}`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                arguments: scanCommand,
                scan_mode: scanMode  // priority or full
            })
        });

        const data = await response.json();

        if (data.status === 'success') {
            showNotification(data.message, 'success');
            // タブ内の進捗を更新（モードに応じて）
            if (scanMode === 'priority') {
                updateTabProgress(targetHost, 'priority', 'started');
            } else if (scanMode === 'full') {
                updateTabProgress(targetHost, 'full', 'started');
            }
            // ポーリングを開始して結果を取得（スキャンモードを渡す）
            pollPortScanResults(targetHost, scanMode);
        } else {
            showNotification('ポートスキャンに失敗しました: ' + data.message, 'error');
            if (scanMode === 'priority') {
                updateTabProgress(targetHost, 'priority', 'error');
            } else if (scanMode === 'full') {
                updateTabProgress(targetHost, 'full', 'error');
            }
        }
    } catch (error) {
        console.error('ポートスキャンエラー:', error);
        showNotification('ポートスキャンに失敗しました', 'error');
        if (scanMode === 'priority') {
            updateTabProgress(targetHost, 'priority', 'error');
        } else if (scanMode === 'full') {
            updateTabProgress(targetHost, 'full', 'error');
        }
    }
}

// スキャン進捗を更新
function updateScanProgress(host, stage, command = '') {
    const progressDiv = document.getElementById(`scan-progress-${host.replace(/\./g, '-')}`);
    if (!progressDiv) return;

    let html = '';

    if (stage === 'started') {
        html = `
            <div><input type="checkbox" checked disabled> スキャン開始</div>
            <div><input type="checkbox" disabled> コマンド実行: nmap ${command}</div>
            <div><input type="checkbox" disabled> ポート検出中...</div>
        `;
    } else if (stage === 'detecting') {
        html = `
            <div><input type="checkbox" checked disabled> スキャン開始</div>
            <div><input type="checkbox" checked disabled> コマンド実行: nmap ${command}</div>
            <div><input type="checkbox" disabled> ポート検出中...</div>
        `;
    } else if (stage === 'analyzing') {
        html = `
            <div><input type="checkbox" checked disabled> スキャン開始</div>
            <div><input type="checkbox" checked disabled> コマンド実行完了</div>
            <div><input type="checkbox" checked disabled> ポート検出完了</div>
            <div><input type="checkbox" disabled> サービス情報取得中...</div>
        `;
    } else if (stage === 'complete') {
        html = `
            <div><input type="checkbox" checked disabled> スキャン開始</div>
            <div><input type="checkbox" checked disabled> コマンド実行完了</div>
            <div><input type="checkbox" checked disabled> ポート検出完了</div>
            <div><input type="checkbox" checked disabled> サービス情報取得完了</div>
            <div><input type="checkbox" checked disabled> 結果の解析完了</div>
        `;
    }

    progressDiv.innerHTML = html;
}

// タブUIを作成（優先ポート・全ポートのタブを初期表示）
function createPortScanTabs(host, scanMode) {
    const portsDiv = document.getElementById(`ports-${host.replace(/\./g, '-')}`);
    const hostKey = host.replace(/\./g, '-');

    // スキャンモードに応じた初期メッセージ
    const priorityInitialMessage = (scanMode === 'priority')
        ? '<div><input type="checkbox" disabled> 優先ポートスキャン待機中...</div>'
        : '<div style="color: #999;">このスキャンは実行されていません。<br>再度ポートスキャンを実行してモード選択してください。</div>';

    const fullInitialMessage = (scanMode === 'full')
        ? '<div><input type="checkbox" disabled> 並列スキャン待機中（6スレッド）...</div>'
        : '<div style="color: #999;">このスキャンは実行されていません。<br>再度ポートスキャンを実行してモード選択してください。</div>';

    portsDiv.innerHTML = `
        <div class="port-scan-tabs" style="margin-top: 15px;">
            <!-- タブヘッダー -->
            <div class="tab-headers" style="display: flex; border-bottom: 2px solid #e2e8f0; margin-bottom: 10px;">
                <button class="tab-btn"
                        data-tab="priority"
                        onclick="switchTab('${host}', 'priority')"
                        style="flex: 1; padding: 8px 12px; background: #667eea; color: white; border: none; border-radius: 6px 6px 0 0; cursor: pointer; font-weight: 600; font-size: 0.85rem; transition: all 0.3s; margin-right: 4px;">
                    📌 優先ポート
                </button>
                <button class="tab-btn"
                        data-tab="full"
                        onclick="switchTab('${host}', 'full')"
                        style="flex: 1; padding: 8px 12px; background: #cbd5e0; color: #4a5568; border: none; border-radius: 6px 6px 0 0; cursor: pointer; font-weight: 600; font-size: 0.85rem; transition: all 0.3s;">
                    🔍 全ポート (1-65535)
                </button>
            </div>

            <!-- タブコンテンツ -->
            <div class="tab-contents">
                <!-- 優先ポートタブ -->
                <div id="priority-tab-${hostKey}" class="tab-content" style="display: block;">
                    <div style="background: #f7fafc; padding: 12px; border-radius: 6px;">
                        <h4 style="margin: 0 0 8px 0; color: #4a5568; font-size: 0.95rem;">📌 優先ポートスキャン進捗</h4>
                        <div id="priority-progress-${hostKey}" style="font-size: 0.85rem;">
                            ${priorityInitialMessage}
                        </div>
                    </div>
                    <div id="priority-results-${hostKey}" style="margin-top: 12px;"></div>
                </div>

                <!-- 全ポートタブ -->
                <div id="full-tab-${hostKey}" class="tab-content" style="display: none;">
                    <div style="background: #f7fafc; padding: 12px; border-radius: 6px;">
                        <h4 style="margin: 0 0 8px 0; color: #4a5568; font-size: 0.95rem;">🔍 全ポートスキャン進捗</h4>
                        <div id="full-progress-${hostKey}" style="font-size: 0.85rem;">
                            ${fullInitialMessage}
                        </div>
                        <div id="full-scan-progress-bar-container-${hostKey}" style="display: none; margin-top: 15px;">
                            <div style="width: 100%; background: #e2e8f0; border-radius: 4px; height: 8px; overflow: hidden;">
                                <div id="full-scan-progress-bar-${hostKey}"
                                     style="width: 0%; background: linear-gradient(90deg, #667eea, #764ba2); height: 100%; transition: width 0.3s;"></div>
                            </div>
                            <div id="full-scan-progress-text-${hostKey}" style="margin-top: 8px; color: #718096; font-size: 0.85rem;">
                                🚀 高速並列スキャン実行中（6スレッド）...
                            </div>
                        </div>
                    </div>
                    <div id="full-results-${hostKey}" style="margin-top: 15px;"></div>
                </div>
            </div>
        </div>
    `;
}

// タブを切り替え
function switchTab(host, tabName) {
    const hostKey = host.replace(/\./g, '-');

    // 全てのタブボタンのスタイルをリセット
    const tabButtons = document.querySelectorAll(`#ports-${hostKey} .tab-btn`);
    tabButtons.forEach(btn => {
        if (btn.dataset.tab === tabName) {
            btn.style.background = '#667eea';
            btn.style.color = 'white';
        } else {
            btn.style.background = '#cbd5e0';
            btn.style.color = '#4a5568';
        }
    });

    // タブコンテンツの表示切り替え
    document.getElementById(`priority-tab-${hostKey}`).style.display =
        tabName === 'priority' ? 'block' : 'none';
    document.getElementById(`full-tab-${hostKey}`).style.display =
        tabName === 'full' ? 'block' : 'none';
}

// タブ内の進捗を更新
function updateTabProgress(host, tabName, stage, progressData = null) {
    const hostKey = host.replace(/\./g, '-');
    const progressDiv = document.getElementById(`${tabName}-progress-${hostKey}`);
    if (!progressDiv) return;

    const isLocal = isLocalHost(host);
    let html = '';

    if (stage === 'started') {
        html = `
            <div style="margin-bottom: 5px;"><input type="checkbox" checked disabled> スキャン開始</div>
            <div style="margin-bottom: 5px;"><input type="checkbox" disabled> コマンド実行中...</div>
        `;
    } else if (stage === 'detecting') {
        html = `
            <div style="margin-bottom: 5px;"><input type="checkbox" checked disabled> スキャン開始</div>
            <div style="margin-bottom: 5px;"><input type="checkbox" checked disabled> コマンド実行完了</div>
            <div style="margin-bottom: 5px;"><input type="checkbox" disabled> ポート検出中...</div>
        `;
    } else if (stage === 'analyzing') {
        if (isLocal) {
            html = `
                <div style="margin-bottom: 5px;"><input type="checkbox" checked disabled> スキャン開始</div>
                <div style="margin-bottom: 5px;"><input type="checkbox" checked disabled> コマンド実行完了</div>
                <div style="margin-bottom: 5px;"><input type="checkbox" checked disabled> ポート検出完了</div>
                <div style="margin-bottom: 5px;"><input type="checkbox" disabled> サービス情報取得中...</div>
            `;
        } else {
            // リモートスキャンの場合はサービス情報取得をスキップ
            html = `
                <div style="margin-bottom: 5px;"><input type="checkbox" checked disabled> スキャン開始</div>
                <div style="margin-bottom: 5px;"><input type="checkbox" checked disabled> コマンド実行完了</div>
                <div style="margin-bottom: 5px;"><input type="checkbox" checked disabled> ポート検出完了</div>
                <div style="margin-bottom: 5px; color: #718096;"><input type="checkbox" disabled> リモートスキャンの為、サービス情報取得できません</div>
            `;
        }
    } else if (stage === 'complete') {
        if (isLocal) {
            html = `
                <div style="margin-bottom: 5px;"><input type="checkbox" checked disabled> スキャン開始</div>
                <div style="margin-bottom: 5px;"><input type="checkbox" checked disabled> コマンド実行完了</div>
                <div style="margin-bottom: 5px;"><input type="checkbox" checked disabled> ポート検出完了</div>
                <div style="margin-bottom: 5px;"><input type="checkbox" checked disabled> サービス情報取得完了</div>
                <div style="margin-bottom: 5px;"><input type="checkbox" checked disabled> 結果の解析完了</div>
            `;
        } else {
            // リモートスキャンの場合はサービス情報取得をスキップ
            html = `
                <div style="margin-bottom: 5px;"><input type="checkbox" checked disabled> スキャン開始</div>
                <div style="margin-bottom: 5px;"><input type="checkbox" checked disabled> コマンド実行完了</div>
                <div style="margin-bottom: 5px;"><input type="checkbox" checked disabled> ポート検出完了</div>
                <div style="margin-bottom: 5px;"><input type="checkbox" checked disabled> 結果の解析完了</div>
            `;
        }

        // 完了時にプログレスバーを非表示にする
        const progressBarContainer = document.getElementById(`${tabName}-scan-progress-bar-container-${hostKey}`);
        if (progressBarContainer) {
            progressBarContainer.style.display = 'none';
        }
    } else if (stage === 'error') {
        html = `
            <div style="margin-bottom: 5px;"><input type="checkbox" checked disabled> スキャン開始</div>
            <div style="margin-bottom: 5px; color: #f56565;"><input type="checkbox" disabled> ❌ スキャン失敗</div>
        `;

        // エラー時にもプログレスバーを非表示にする
        const progressBarContainer = document.getElementById(`${tabName}-scan-progress-bar-container-${hostKey}`);
        if (progressBarContainer) {
            progressBarContainer.style.display = 'none';
        }
    } else if (stage === 'scanning') {
        // 全ポートスキャン実行中（進捗％付き）- 6スレッド、2段階スキャン
        // progressDataから実際のスキャン数に基づく進捗を取得
        let estimatedProgress = 0;
        let scanPhase = '';
        let detailsText = '';

        if (progressData && progressData.progress) {
            const progress = progressData.progress;
            estimatedProgress = progress.overall_progress || 0;

            // 進捗率に基づいてフェーズを判定
            if (estimatedProgress < 50) {
                scanPhase = 'ポートスキャン';
                detailsText = `${progress.scanned_ports.toLocaleString()}/${progress.total_ports.toLocaleString()}ポート`;
            } else {
                scanPhase = 'サービス情報取得';
                detailsText = `${progress.service_scanned}/${progress.found_ports}ポート`;
            }
        } else {
            // フォールバック: progressDataがない場合は初期状態
            estimatedProgress = 0;
            scanPhase = 'ポートスキャン';
            detailsText = '0/65,535ポート';
        }

        // 進捗表示を2段階に分離（ローカル/リモートで表示を変更）
        if (estimatedProgress < 50) {
            html = `
                <div style="margin-bottom: 5px;"><input type="checkbox" checked disabled> スキャン開始</div>
                <div style="margin-bottom: 5px;"><input type="checkbox" checked disabled> コマンド実行完了</div>
                <div style="margin-bottom: 5px;"><input type="checkbox" disabled> 🚀 ポートスキャン実行中 (6スレッド並列)... ${estimatedProgress}%<br><span style="font-size: 0.85em; color: #718096;">${detailsText}</span></div>
                <div style="margin-bottom: 5px;"><input type="checkbox" disabled> ${isLocal ? 'サービス情報取得待機中 (6スレッド並列)...' : 'リモートスキャンの為、サービス情報取得できません'}</div>
            `;
        } else {
            if (isLocal) {
                html = `
                    <div style="margin-bottom: 5px;"><input type="checkbox" checked disabled> スキャン開始</div>
                    <div style="margin-bottom: 5px;"><input type="checkbox" checked disabled> コマンド実行完了</div>
                    <div style="margin-bottom: 5px;"><input type="checkbox" checked disabled> ✅ ポートスキャン完了 (6スレッド並列)</div>
                    <div style="margin-bottom: 5px;"><input type="checkbox" disabled> 🔍 サービス情報取得中 (6スレッド並列)... ${estimatedProgress}%<br><span style="font-size: 0.85em; color: #718096;">${detailsText}</span></div>
                `;
            } else {
                // リモートスキャンの場合
                html = `
                    <div style="margin-bottom: 5px;"><input type="checkbox" checked disabled> スキャン開始</div>
                    <div style="margin-bottom: 5px;"><input type="checkbox" checked disabled> コマンド実行完了</div>
                    <div style="margin-bottom: 5px;"><input type="checkbox" checked disabled> ✅ ポートスキャン完了 (6スレッド並列)</div>
                    <div style="margin-bottom: 5px; color: #718096;"><input type="checkbox" disabled> リモートスキャンの為、サービス情報取得できません</div>
                `;
            }
        }

        // プログレスバーを表示
        const progressBarContainer = document.getElementById(`${tabName}-scan-progress-bar-container-${hostKey}`);
        if (progressBarContainer) {
            progressBarContainer.style.display = 'block';
            const progressBar = document.getElementById(`${tabName}-scan-progress-bar-${hostKey}`);
            const progressText = document.getElementById(`${tabName}-scan-progress-text-${hostKey}`);
            if (progressBar) {
                progressBar.style.width = `${estimatedProgress}%`;
            }
            if (progressText) {
                progressText.textContent = `🚀 高速並列スキャン実行中（6スレッド）| ${scanPhase}: ${estimatedProgress}% | ${detailsText}`;
            }
        }
    }

    progressDiv.innerHTML = html;
}

// ポートスキャン結果をポーリング（並列スキャン対応・タブUI版）
async function pollPortScanResults(host, scanMode) {
    const maxAttempts = 300; // 最大5分間ポーリング
    let attempts = 0;
    let priorityDisplayed = false;
    let fullDisplayed = false;
    let fullScanStartTime = null;

    // スキャンモードに応じて待機するステージを決定
    const waitForPriority = (scanMode === 'priority');
    const waitForFull = (scanMode === 'full');

    const pollInterval = setInterval(async () => {
        attempts++;

        // 進捗ステージを更新（時間経過に基づく、スキャンモードに応じて）
        if (attempts === 2) {
            if (waitForPriority) {
                updateTabProgress(host, 'priority', 'detecting');
            }
            if (waitForFull) {
                updateTabProgress(host, 'full', 'detecting');
            }
        } else if (attempts === 5) {
            if (waitForPriority) {
                updateTabProgress(host, 'priority', 'analyzing');
            }
        }

        try {
            const response = await fetch(`/api/port-scan/${host}`);
            const data = await response.json();

            if (data.status === 'success' && data.data) {
                const currentStage = data.data.scan_stage;
                const currentPorts = data.data.ports || [];

                // 優先ポートスキャン結果が来た場合（優先ポートを待機している場合のみ処理）
                if (currentStage === 'priority' && !priorityDisplayed && waitForPriority) {
                    priorityDisplayed = true;
                    fullScanStartTime = attempts;
                    updateTabProgress(host, 'priority', 'complete');
                    displayPortResults(host, data.data, 'priority');

                    // 優先ポートのみの場合はここで完了
                    if (scanMode === 'priority') {
                        clearInterval(pollInterval);
                    }
                }

                // 全ポートスキャン実行中の進捗％を更新（全ポートを待機している場合のみ処理）
                if (currentStage === 'full_scanning' && !fullDisplayed && waitForFull) {
                    if (!fullScanStartTime) fullScanStartTime = attempts;
                    // 実際の進捗データを渡す
                    updateTabProgress(host, 'full', 'scanning', data.data);
                }

                // 全ポートスキャン結果が来た場合（全ポートを待機している場合のみ処理）
                if (currentStage === 'full' && !fullDisplayed && waitForFull) {
                    fullDisplayed = true;
                    updateTabProgress(host, 'full', 'complete');
                    displayPortResults(host, data.data, 'full');
                    clearInterval(pollInterval);
                }
            } else if (attempts >= maxAttempts) {
                // タイムアウト（実行中のスキャンのみエラー表示）
                if (waitForPriority) {
                    updateTabProgress(host, 'priority', 'error');
                }
                if (waitForFull) {
                    updateTabProgress(host, 'full', 'error');
                }
                clearInterval(pollInterval);
            }
        } catch (error) {
            console.error('結果取得エラー:', error);
            if (attempts >= maxAttempts) {
                // タイムアウト（実行中のスキャンのみエラー表示）
                if (waitForPriority) {
                    updateTabProgress(host, 'priority', 'error');
                }
                if (waitForFull) {
                    updateTabProgress(host, 'full', 'error');
                }
                clearInterval(pollInterval);
            }
        }
    }, 1000); // 1秒ごとにチェック
}

// ポート結果を表示（タブUI版・優先ポートと全ポートを各タブ内に表示）
async function displayPortResults(host, data, stage = 'full') {
    const hostKey = host.replace(/\./g, '-');
    const resultsDiv = document.getElementById(`${stage}-results-${hostKey}`);

    if (!resultsDiv) {
        console.error(`結果表示エリアが見つかりません: ${stage}-results-${hostKey}`);
        return;
    }

    if (!data || !data.ports || data.ports.length === 0) {
        resultsDiv.innerHTML = '<p style="color: #999; font-size: 0.9rem; padding: 10px; background: #f7fafc; border-radius: 6px;">開いているポートが見つかりませんでした</p>';
        return;
    }

    // プロセス情報を取得
    let processInfo = {};
    let isLocalHost = false;
    let processInfoStatus = 'loading';
    try {
        const response = await fetch(`/api/process-info/${host}`);
        if (response.ok) {
            const processData = await response.json();
            if (processData.status === 'success') {
                processInfo = processData.data || {};
                isLocalHost = !processData.note; // noteがない場合はローカルホスト
                processInfoStatus = isLocalHost ? 'available' : 'remote';
            }
        }
    } catch (error) {
        console.error('プロセス情報取得エラー:', error);
        processInfoStatus = 'error';
    }

    let html = '';

    // OS情報（全ポートスキャン時のみ表示）
    if (stage === 'full' && data.os) {
        html += `<div style="background: #f7fafc; padding: 10px; border-radius: 6px; margin-bottom: 15px;">
            <strong>🖥️ OS:</strong> ${data.os}
        </div>`;
    }

    // 検出されたポート数を表示
    const openPorts = data.ports.filter(p => p.state === 'open').length;
    html += `<div style="background: #e6fffa; color: #234e52; padding: 10px; border-radius: 6px; margin-bottom: 15px; font-weight: 600;">
        ✅ ${openPorts}個の開いているポートを検出しました
    </div>`;

    // ポートリスト
    data.ports.forEach(port => {
        const stateClass = port.state === 'open' ? '' : 'closed';
        const version = port.version ? `${port.product} ${port.version}` : port.product || '';
        const portKey = `${port.port}/${port.protocol}`;
        const process = processInfo[portKey];

        // HTTP系のポートかどうかを判定
        const isHttpPort = port.state === 'open' &&
                          [80, 443, 8080, 8443, 3000, 3001, 5000, 5001, 5050, 8000, 8888].includes(port.port);

        html += `
            <div class="port-item ${stateClass}" data-port="${port.port}" data-host="${host}" style="background: white; padding: 12px; border-radius: 8px; margin-bottom: 10px; border-left: 3px solid ${port.state === 'open' ? '#48bb78' : '#cbd5e0'};">
                <div style="display: flex; justify-content: space-between; align-items: center;">
                    <div style="flex: 1;">
                        <div>
                            <span class="port-number" style="font-weight: 700; color: #2d3748; font-size: 1rem;">${port.port}/${port.protocol}</span>
                            <span class="port-service" style="color: #4a5568; margin-left: 10px; background: #edf2f7; padding: 3px 8px; border-radius: 4px; font-size: 0.85rem;">${port.service || 'unknown'}</span>
                            ${port.state !== 'open' ? `<span style="color: #f56565; font-size: 0.85rem; margin-left: 8px;">(${port.state})</span>` : ''}
                            ${isHttpPort ? `
                                <button id="http-info-btn-${host}-${port.port}" class="btn-http-info" onclick="fetchHttpInfo('${host}', ${port.port})">
                                    HTTP詳細
                                </button>
                            ` : ''}
                        </div>
                        ${version ? `<div style="color: #666; font-size: 0.85rem; margin-top: 5px;">📦 ${version}</div>` : ''}
                        ${process ? `
                            <div style="margin-top: 8px; font-size: 0.85rem; color: #4a5568; background: #f7fafc; padding: 6px 10px; border-radius: 4px; display: inline-block;">
                                <strong>PID:</strong> ${process.pid} |
                                <strong>プロセス:</strong> ${process.name || 'unknown'}
                            </div>
                        ` : ''}
                    </div>
                    ${process && process.pid ? `
                        <button class="btn-kill" onclick="killProcess(${process.pid}, '${host}', ${port.port})"
                                style="padding: 8px 16px; background: #f56565; color: white; border: none; border-radius: 6px; cursor: pointer; font-size: 0.85rem; font-weight: 600; transition: all 0.2s; margin-left: 15px; box-shadow: 0 2px 4px rgba(245, 101, 101, 0.3);"
                                onmouseover="this.style.background='#e53e3e'; this.style.transform='translateY(-1px)'; this.style.boxShadow='0 4px 6px rgba(245, 101, 101, 0.4)';"
                                onmouseout="this.style.background='#f56565'; this.style.transform=''; this.style.boxShadow='0 2px 4px rgba(245, 101, 101, 0.3)';">
                            ⚠️ KILL
                        </button>
                    ` : ''}
                </div>
            </div>
        `;
    });

    resultsDiv.innerHTML = html;

    // プロセス情報取得完了のチェックボックスを更新（ローカルホストの場合のみ）
    if (isLocalHost && processInfoStatus === 'available') {
        const progressDiv = document.getElementById(`${stage}-progress-${hostKey}`);
        if (progressDiv) {
            progressDiv.innerHTML += `
                <div style="margin-bottom: 5px;"><input type="checkbox" checked disabled> プロセス情報取得完了</div>
            `;
        }
    }
}

// プロセスをKILL
async function killProcess(pid, host, port) {
    if (!confirm(`警告: PID ${pid} (ポート ${port}) のプロセスを終了しますか？\n\nこの操作は元に戻せません。`)) {
        return;
    }

    try {
        const response = await fetch(`/api/kill-process/${pid}`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            }
        });

        const data = await response.json();

        if (data.status === 'success') {
            showNotification(`プロセス ${pid} を終了しました`, 'success');

            // 該当のポートアイテムを見つけてグレーアウト
            greyOutKilledPort(host, port, pid);
        } else {
            showNotification('プロセスの終了に失敗しました: ' + data.message, 'error');
        }
    } catch (error) {
        console.error('プロセス終了エラー:', error);
        showNotification('プロセスの終了に失敗しました', 'error');
    }
}

// KILLしたポートをグレーアウト表示
function greyOutKilledPort(host, port, pid) {
    // 全てのport-itemを検索して該当のポートを見つける
    const portsContainers = document.querySelectorAll(`#ports-${host.replace(/\./g, '-')} .port-item`);

    portsContainers.forEach(portItem => {
        const portNumberElement = portItem.querySelector('.port-number');
        if (portNumberElement && portNumberElement.textContent.startsWith(`${port}/`)) {
            // グレーアウトスタイルを適用
            portItem.style.opacity = '0.5';
            portItem.style.background = '#f5f5f5';
            portItem.style.borderLeft = '3px solid #cbd5e0';
            portItem.style.paddingLeft = '12px';
            portItem.style.transition = 'all 0.3s ease';

            // KILLボタンを「終了済み」バッジに置き換え
            const killButton = portItem.querySelector('.btn-kill');
            if (killButton) {
                killButton.outerHTML = `
                    <span style="padding: 6px 14px; background: #a0aec0; color: white; border-radius: 4px; font-size: 0.85rem; font-weight: 600;">
                        ✓ 終了済み
                    </span>
                `;
            }

            // プロセス情報の部分に取り消し線を追加
            const processInfoDiv = portItem.querySelector('div[style*="background: #f7fafc"]');
            if (processInfoDiv) {
                processInfoDiv.style.textDecoration = 'line-through';
                processInfoDiv.style.opacity = '0.6';
            }
        }
    });
}

// モーダルを閉じる（互換性のため残す）
function closeModal() {
    closePortScanConfig();
}

// sudoパスワードモーダルを開く
function openSudoPasswordModal() {
    const modal = document.getElementById('sudoPasswordModal');
    modal.classList.remove('hidden');
}

// sudoパスワードモーダルを閉じる
function closeSudoPasswordModal() {
    const modal = document.getElementById('sudoPasswordModal');
    modal.classList.add('hidden');
    document.getElementById('sudoPassword').value = '';
}

// sudoパスワードを保存
async function saveSudoPassword() {
    const password = document.getElementById('sudoPassword').value;

    if (!password) {
        showNotification('パスワードを入力してください', 'error');
        return;
    }

    try {
        const response = await fetch('/api/sudo-password', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                password: password
            })
        });

        const data = await response.json();

        if (data.status === 'success') {
            showNotification('sudoパスワードを設定しました', 'success');
            closeSudoPasswordModal();
        } else {
            showNotification('設定に失敗しました: ' + data.message, 'error');
        }
    } catch (error) {
        console.error('sudo設定エラー:', error);
        showNotification('設定に失敗しました', 'error');
    }
}

// 通知を表示
function showNotification(message, type = 'info') {
    // シンプルな通知実装
    const notification = document.createElement('div');
    notification.style.cssText = `
        position: fixed;
        top: 20px;
        right: 20px;
        padding: 15px 25px;
        background: ${type === 'success' ? '#48bb78' : type === 'error' ? '#f56565' : '#667eea'};
        color: white;
        border-radius: 8px;
        box-shadow: 0 4px 12px rgba(0,0,0,0.2);
        z-index: 10000;
        animation: slideIn 0.3s ease;
    `;
    notification.textContent = message;

    document.body.appendChild(notification);

    setTimeout(() => {
        notification.style.animation = 'slideOut 0.3s ease';
        setTimeout(() => {
            document.body.removeChild(notification);
        }, 300);
    }, 3000);
}

// アニメーション用のスタイルを追加
const style = document.createElement('style');
style.textContent = `
    @keyframes slideIn {
        from {
            transform: translateX(400px);
            opacity: 0;
        }
        to {
            transform: translateX(0);
            opacity: 1;
        }
    }

    @keyframes slideOut {
        from {
            transform: translateX(0);
            opacity: 1;
        }
        to {
            transform: translateX(400px);
            opacity: 0;
        }
    }
`;
document.head.appendChild(style);

// モーダルの外側クリックで閉じる
document.addEventListener('click', function(e) {
    const portScanModal = document.getElementById('portScanConfigModal');
    const sudoModal = document.getElementById('sudoPasswordModal');
    const networkMapModal = document.getElementById('networkMapModal');
    const httpInfoModal = document.getElementById('httpInfoModal');

    if (e.target === portScanModal) {
        closePortScanConfig();
    }
    if (e.target === sudoModal) {
        closeSudoPasswordModal();
    }
    if (e.target === networkMapModal) {
        closeNetworkMapModal();
    }
    if (e.target === httpInfoModal) {
        closeHttpInfoModal();
    }
});

// ネットワークマップモーダルを開く
async function openNetworkMapModal() {
    const modal = document.getElementById('networkMapModal');
    modal.classList.remove('hidden');

    try {
        const response = await fetch('/api/network-topology');
        const data = await response.json();

        if (data.status === 'error') {
            showNotification('ネットワークトポロジーの取得に失敗しました: ' + data.message, 'error');
            return;
        }

        // 統計情報を表示
        displayNetworkStats(data.stats);

        // ネットワークトポロジーを描画
        drawNetworkTopology(data.nodes, data.edges);

    } catch (error) {
        console.error('Network topology fetch error:', error);
        showNotification('ネットワークトポロジーの取得に失敗しました', 'error');
    }
}

// ネットワークマップモーダルを閉じる
function closeNetworkMapModal() {
    const modal = document.getElementById('networkMapModal');
    modal.classList.add('hidden');
}

// ネットワーク統計情報を表示
function displayNetworkStats(stats) {
    const statsContainer = document.getElementById('networkMapStats');
    statsContainer.innerHTML = `
        <div class="network-stat-item">
            <span class="stat-value">${stats.total_hosts}</span>
            <span class="stat-label">総ホスト数</span>
        </div>
        <div class="network-stat-item">
            <span class="stat-value">${stats.subnets}</span>
            <span class="stat-label">サブネット数</span>
        </div>
        <div class="network-stat-item">
            <span class="stat-value">${stats.gateways}</span>
            <span class="stat-label">ゲートウェイ</span>
        </div>
        <div class="network-stat-item">
            <span class="stat-value">${stats.servers}</span>
            <span class="stat-label">サーバー</span>
        </div>
        <div class="network-stat-item">
            <span class="stat-value">${stats.mobile_devices}</span>
            <span class="stat-label">モバイル機器</span>
        </div>
        <div class="network-stat-item">
            <span class="stat-value">${stats.total_connections}</span>
            <span class="stat-label">接続数</span>
        </div>
    `;
}

// ネットワークトポロジーを描画
function drawNetworkTopology(nodes, edges) {
    const canvas = document.getElementById('topologyCanvas');
    const ctx = canvas.getContext('2d');
    const width = canvas.width;
    const height = canvas.height;

    // キャンバスをクリア
    ctx.clearRect(0, 0, width, height);

    if (nodes.length === 0) {
        ctx.font = '16px Arial';
        ctx.fillStyle = '#718096';
        ctx.textAlign = 'center';
        ctx.fillText('スキャン結果がありません', width / 2, height / 2);
        return;
    }

    // ノードの色を定義
    const nodeColors = {
        gateway: '#f56565',
        server: '#4299e1',
        mobile: '#48bb78',
        host: '#a0aec0'
    };

    // 力指向グラフのシンプルな実装（円形配置）
    const centerX = width / 2;
    const centerY = height / 2;
    const radius = Math.min(width, height) * 0.35;

    // ノードの位置を計算（円形配置）
    const nodePositions = {};
    const angleStep = (2 * Math.PI) / nodes.length;

    // ゲートウェイを中心に配置
    const gateways = nodes.filter(n => n.type === 'gateway');
    const otherNodes = nodes.filter(n => n.type !== 'gateway');

    if (gateways.length > 0) {
        // ゲートウェイを中心に
        gateways.forEach((node, i) => {
            nodePositions[node.id] = {
                x: centerX + (gateways.length > 1 ? Math.cos(i * 2 * Math.PI / gateways.length) * 50 : 0),
                y: centerY + (gateways.length > 1 ? Math.sin(i * 2 * Math.PI / gateways.length) * 50 : 0),
                node: node
            };
        });

        // 他のノードを円周上に
        otherNodes.forEach((node, i) => {
            const angle = i * 2 * Math.PI / otherNodes.length;
            nodePositions[node.id] = {
                x: centerX + Math.cos(angle) * radius,
                y: centerY + Math.sin(angle) * radius,
                node: node
            };
        });
    } else {
        // ゲートウェイがない場合は全て円形配置
        nodes.forEach((node, i) => {
            const angle = i * angleStep;
            nodePositions[node.id] = {
                x: centerX + Math.cos(angle) * radius,
                y: centerY + Math.sin(angle) * radius,
                node: node
            };
        });
    }

    // エッジを描画
    ctx.strokeStyle = '#cbd5e0';
    ctx.lineWidth = 2;
    edges.forEach(edge => {
        const source = nodePositions[edge.source];
        const target = nodePositions[edge.target];
        if (source && target) {
            ctx.beginPath();
            ctx.moveTo(source.x, source.y);
            ctx.lineTo(target.x, target.y);
            ctx.stroke();
        }
    });

    // ノードを描画
    Object.values(nodePositions).forEach(pos => {
        const node = pos.node;
        const color = nodeColors[node.type] || nodeColors.host;
        const nodeRadius = node.type === 'gateway' ? 25 : (node.type === 'server' ? 20 : 15);

        // ノード本体
        ctx.beginPath();
        ctx.arc(pos.x, pos.y, nodeRadius, 0, 2 * Math.PI);
        ctx.fillStyle = color;
        ctx.fill();
        ctx.strokeStyle = '#2d3748';
        ctx.lineWidth = 2;
        ctx.stroke();

        // ラベル
        ctx.font = 'bold 11px Arial';
        ctx.fillStyle = '#2d3748';
        ctx.textAlign = 'center';
        ctx.fillText(node.label, pos.x, pos.y - nodeRadius - 8);

        // IPアドレス
        ctx.font = '9px Arial';
        ctx.fillStyle = '#718096';
        ctx.fillText(node.id, pos.x, pos.y - nodeRadius - 22);

        // ポート数（サーバーの場合）
        if (node.ports > 0) {
            ctx.font = 'bold 10px Arial';
            ctx.fillStyle = '#ffffff';
            ctx.fillText(node.ports, pos.x, pos.y + 4);
        }
    });
}

// HTTP詳細情報を取得して表示
async function fetchHttpInfo(host, port) {
    const modal = document.getElementById('httpInfoModal');
    const modalTitle = document.getElementById('httpInfoModalTitle');
    const modalBody = document.getElementById('httpInfoModalBody');

    // モーダルを開いて読み込み中を表示
    modal.classList.remove('hidden');
    modalTitle.textContent = `🌐 HTTP/HTTPS詳細情報 - ${host}:${port}`;
    modalBody.innerHTML = '<p style="text-align: center; padding: 40px; color: #718096;">読込中...</p>';

    try {
        const response = await fetch(`/api/http-info/${host}/${port}`);
        const data = await response.json();

        if (data.status === 'error') {
            showNotification('HTTP情報の取得に失敗しました: ' + data.message, 'error');
            closeHttpInfoModal();
            return;
        }

        // HTTP詳細情報を表示
        displayHttpInfo(host, port, data);

    } catch (error) {
        console.error('HTTP info fetch error:', error);
        showNotification('HTTP情報の取得に失敗しました', 'error');
        closeHttpInfoModal();
    }
}

// HTTP詳細情報モーダルを閉じる
function closeHttpInfoModal() {
    const modal = document.getElementById('httpInfoModal');
    modal.classList.add('hidden');
}

// HTTP詳細情報を表示
function displayHttpInfo(host, port, data) {
    const modalBody = document.getElementById('httpInfoModalBody');

    let htmlContent = '';

    if (!data.accessible) {
        htmlContent = `
            <div style="padding: 20px; text-align: center;">
                <div style="font-size: 48px; margin-bottom: 20px;">⚠️</div>
                <h3 style="color: #f56565; margin-bottom: 10px;">接続できませんでした</h3>
                <p style="color: #718096;">${data.error || '不明なエラー'}</p>
            </div>
        `;
    } else {
        htmlContent = `
            <div style="padding: 20px;">
                <div style="background: #e6fffa; color: #234e52; padding: 15px; border-radius: 8px; margin-bottom: 20px; border-left: 4px solid #38b2ac;">
                    <h3 style="margin: 0 0 10px 0; font-size: 1.1rem;">📊 基本情報</h3>
                    <table class="http-info-table">
                        <tbody>
                            <tr><td>ステータスコード</td><td><strong>${data.status_code}</strong></td></tr>
                            <tr><td>プロトコル</td><td><strong>${data.protocol.toUpperCase()}</strong></td></tr>
                            ${data.title ? `<tr><td>ページタイトル</td><td>${escapeHtml(data.title)}</td></tr>` : ''}
                            ${data.server ? `<tr><td>サーバー</td><td>${escapeHtml(data.server)}</td></tr>` : ''}
                            ${data.redirect_url ? `<tr><td>リダイレクト先</td><td style="word-break: break-all;">${escapeHtml(data.redirect_url)}</td></tr>` : ''}
                            ${data.headers['X-Powered-By'] ? `<tr><td>X-Powered-By</td><td>${escapeHtml(data.headers['X-Powered-By'])}</td></tr>` : ''}
                        </tbody>
                    </table>
                </div>

                ${data.security_headers ? `
                    <div style="background: #f7fafc; padding: 15px; border-radius: 8px; border-left: 4px solid #805ad5;">
                        <h3 style="margin: 0 0 15px 0; font-size: 1.1rem;">🔒 セキュリティヘッダー</h3>
                        <div>
                            ${Object.entries(data.security_headers).map(([header, info]) => {
                                const statusClass = info.present ? 'present' : 'missing';
                                const statusIcon = info.present ? '✅' : '❌';
                                return `
                                    <div class="security-header-item">
                                        <div class="security-header-status ${statusClass}"></div>
                                        <div style="flex: 1;">
                                            <div class="security-header-name">${statusIcon} ${header}</div>
                                            <div class="security-header-description">${info.description}</div>
                                            ${info.present && info.value ? `<div style="font-size: 0.8rem; color: #4a5568; margin-top: 5px; font-family: monospace; background: #edf2f7; padding: 5px; border-radius: 4px;">${escapeHtml(info.value)}</div>` : ''}
                                        </div>
                                    </div>
                                `;
                            }).join('')}
                        </div>
                    </div>
                ` : ''}
            </div>
        `;
    }

    modalBody.innerHTML = htmlContent;
}

// HTMLエスケープ関数
function escapeHtml(text) {
    const map = {
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#039;'
    };
    return text.replace(/[&<>"']/g, m => map[m]);
}


// ========================================
// 履歴機能のJavaScript 追加
// ========================================

let currentHistoryScanId = null;

// ページ読み込み時に履歴を取得
document.addEventListener('DOMContentLoaded', function() {
    loadScanHistory();
    // 10秒ごとに履歴を更新
    setInterval(loadScanHistory, 10000);
});

/**
 * スキャン履歴を読み込んで表示
 */
async function loadScanHistory() {
    try {
        const response = await fetch('/api/history');
        if (!response.ok) return;

        const contentType = response.headers.get('content-type');
        if (!contentType || !contentType.includes('application/json')) {
            console.error('History API returned non-JSON response');
            return;
        }

        const history = await response.json();
        const container = document.getElementById('historyContainer');

        if (!container) return;

        if (history.length === 0) {
            container.innerHTML = `
                <div class="empty-history">
                    <div class="empty-history-icon">📋</div>
                    <div>スキャン履歴がありません</div>
                </div>
            `;
            return;
        }

        container.innerHTML = history.map(scan => {
            const date = new Date(scan.timestamp);
            const timeStr = date.toLocaleString('ja-JP', {
                month: '2-digit',
                day: '2-digit',
                hour: '2-digit',
                minute: '2-digit'
            });
            const isActive = scan.id === currentHistoryScanId ? 'active' : '';
            const name = scan.name && scan.name.trim() ? scan.name.trim() : '未設定';

            return `
                <div class="history-item ${isActive}" onclick="loadHistoryScan(${scan.id})">
                    <div class="history-name" style="font-weight:600;color:#2d3748;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:200px;">
                            ${escapeHtml(name)}
                    </div>
                    <div class="history-time">${timeStr}</div>
                    <div class="history-target">${scan.target}</div>
                    <div class="history-count">🖥️ ${scan.host_count}台のホスト</div>
                    <div class="history-actions" onclick="event.stopPropagation()">
                        <button class="history-edit-btn" onclick="editHistoryName(${scan.id}, ${JSON.stringify(name)})">
                            編集
                        </button>
                        <button class="history-btn" onclick="deleteHistoryScan(${scan.id})">削除</button>
                    </div>
                </div>
            `;
        }).join('');
    } catch (error) {
        console.error('履歴読み込みエラー:', error);
    }
}

/**
 * 履歴名を編集する
 * - 既存の `#historyEditModal` があればそれを使い、なければ prompt で実装
 * - サーバー側は `PATCH /api/history/{id}` を想定し、ボディに { name: '新しい名前' } を送る
 */
async function editHistoryName(scanId, currentName) {
    // 優先: モーダルがある場合はその実装を使う（簡易版）
    const modal = document.getElementById('historyEditModal');
    let newName = null;

    if (modal) {
        // モーダルの存在を想定: input#historyNameInput, button#historyNameSave, button#historyNameCancel
        const input = document.getElementById('historyNameInput');
        const saveBtn = document.getElementById('historyNameSave');
        const cancelBtn = document.getElementById('historyNameCancel');

        if (!input || !saveBtn || !cancelBtn) {
            // モーダルが不完全ならフォールバック
            newName = prompt('履歴名を入力してください', currentName);
        } else {
            input.value = currentName || '';
            modal.classList.remove('hidden');

            // 一度だけハンドラを登録
            const onSave = async () => {
                modal.classList.add('hidden');
                saveBtn.removeEventListener('click', onSave);
                cancelBtn.removeEventListener('click', onCancel);
                newName = input.value;
                await performHistoryRename(scanId, newName);
            };
            const onCancel = () => {
                modal.classList.add('hidden');
                saveBtn.removeEventListener('click', onSave);
                cancelBtn.removeEventListener('click', onCancel);
            };

            saveBtn.addEventListener('click', onSave);
            cancelBtn.addEventListener('click', onCancel);
            return;
        }
    } else {
        // モーダルがなければ prompt を使用
        newName = prompt('履歴名を入力してください', currentName);
    }

    if (newName === null) return; // ユーザーキャンセル
    await performHistoryRename(scanId, newName);
}

async function performHistoryRename(scanId, newName) {
    newName = (newName || '').trim();
    if (newName.length === 0) {
        showNotification('名前を入力してください', 'error');
        return;
    }

    try {
        const response = await fetch(`/api/history/${scanId}`, {
            method: 'PATCH',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ name: newName })
        });

        const data = await response.json().catch(() => null);

        if (response.ok && data && (data.status === 'success' || response.status === 200)) {
            showNotification('履歴名を更新しました', 'success');
            // 更新反映: 全部リロードしても良いし、部分更新でも可。ここでは再取得する。
            loadScanHistory();
        } else {
            const msg = (data && data.message) ? data.message : response.statusText || '更新に失敗しました';
            showNotification('履歴名の更新に失敗しました: ' + msg, 'error');
        }
    } catch (error) {
        console.error('履歴名更新エラー:', error);
        showNotification('通信エラーにより更新できませんでした', 'error');
    }
}

/**
 * 履歴からスキャン結果を読み込む
 */
async function loadHistoryScan(scanId) {
    try {
        const response = await fetch(`/api/history/${scanId}/load`, {
            method: 'POST'
        });

        if (!response.ok) {
            console.error('Failed to load scan:', response.status);
            return;
        }

        const contentType = response.headers.get('content-type');
        if (!contentType || !contentType.includes('application/json')) {
            console.error('Load API returned non-JSON response');
            return;
        }

        const data = await response.json();

        if (data.success) {
            currentHistoryScanId = scanId;

            // 既存のテーブル更新関数を呼び出し
            // updateHostsTable関数が存在する場合
            if (typeof updateHostsTable === 'function') {
                updateHostsTable(data.hosts);
            } else {
                // 別の更新方法があればここに記述
                console.log('Loaded scan data:', data);
                // 例: テーブルを手動で更新
                updateResultsFromHistory(data.hosts);
            }

            // 履歴のアクティブ状態を更新
            loadScanHistory();

            // 通知表示
            showNotification('履歴を読み込みました', 'success');
        } else {
            showNotification('履歴の読み込みに失敗しました', 'error');
        }
    } catch (error) {
        console.error('履歴読み込みエラー:', error);
        showNotification('履歴の読み込みに失敗しました', 'error');
    }
}

/**
 * スキャン履歴を削除
 */
async function deleteHistoryScan(scanId) {
    if (!confirm('この履歴を削除しますか？')) {
        return;
    }

    try {
        const response = await fetch(`/api/history/${scanId}`, {
            method: 'DELETE'
        });

        if (!response.ok) {
            console.error('Failed to delete scan:', response.status);
            return;
        }

        const contentType = response.headers.get('content-type');
        if (!contentType || !contentType.includes('application/json')) {
            console.error('Delete API returned non-JSON response');
            return;
        }

        const data = await response.json();

        if (data.success) {
            // 現在表示中のスキャンを削除した場合
            if (currentHistoryScanId === scanId) {
                currentHistoryScanId = null;
                // テーブルをクリア（既存の関数があれば使用）
                const tbody = document.querySelector('#hostsTable tbody');
                if (tbody) {
                    tbody.innerHTML = '<tr><td colspan="5" style="text-align: center;">スキャン結果がありません</td></tr>';
                }
            }

            // 履歴を再読み込み
            loadScanHistory();

            showNotification('履歴を削除しました', 'success');
        } else {
            showNotification('削除に失敗しました', 'error');
        }
    } catch (error) {
        console.error('削除エラー:', error);
        showNotification('削除に失敗しました', 'error');
    }
}

/**
 * 履歴データから結果を更新（updateHostsTableがない場合の代替）
 */
function updateResultsFromHistory(hosts) {
    const tbody = document.querySelector('#hostsTable tbody');
    if (!tbody) return;

    if (Object.keys(hosts).length === 0) {
        tbody.innerHTML = '<tr><td colspan="5" style="text-align: center;">ホストが見つかりませんでした</td></tr>';
        return;
    }

    tbody.innerHTML = '';
    for (const [ip, info] of Object.entries(hosts)) {
        const row = tbody.insertRow();
        row.innerHTML = `
            <td>${ip}</td>
            <td>${info.hostname || 'Unknown'}</td>
            <td><span class="status-badge status-up">${info.state}</span></td>
            <td>${info.vendor || '-'}</td>
            <td>
                <button class="btn-small" onclick="scanPorts('${ip}')">ポートスキャン</button>
            </td>
        `;
    }
}

/**
 * 通知を表示
 */
function showNotification(message, type = 'info') {
    // 既存の通知システムがあればそれを使用
    console.log(`[${type.toUpperCase()}] ${message}`);

    // 簡易的な通知表示
    const notification = document.createElement('div');
    notification.style.cssText = `
        position: fixed;
        top: 20px;
        right: 20px;
        padding: 15px 20px;
        background: ${type === 'success' ? '#28a745' : type === 'error' ? '#dc3545' : '#17a2b8'};
        color: white;
        border-radius: 5px;
        box-shadow: 0 2px 10px rgba(0,0,0,0.2);
        z-index: 10000;
        animation: slideIn 0.3s ease;
    `;
    notification.textContent = message;

    document.body.appendChild(notification);

    setTimeout(() => {
        notification.style.animation = 'slideOut 0.3s ease';
        setTimeout(() => notification.remove(), 300);
    }, 3000);
}

// 通知アニメーション用のスタイルを追加
if (!document.getElementById('notification-styles')) {
    const style = document.createElement('style');
    style.id = 'notification-styles';
    style.textContent = `
        @keyframes slideIn {
            from { transform: translateX(400px); opacity: 0; }
            to { transform: translateX(0); opacity: 1; }
        }
        @keyframes slideOut {
            from { transform: translateX(0); opacity: 1; }
            to { transform: translateX(400px); opacity: 0; }
        }
    `;
    document.head.appendChild(style);
}