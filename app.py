#!/usr/bin/env python3
"""
LocalNetScan - ローカルネットワークスキャンFlaskアプリケーション
"""

from flask import Flask, render_template, jsonify, request
from scanner import NetworkScanner
import threading
import time
from datetime import datetime
# 履歴サイドバーモジュール追加
from history_manager import HistoryManager

app = Flask(__name__)
app.config['SECRET_KEY'] = 'localnetscan-secret-key-change-in-production'

# グローバル変数
scanner = NetworkScanner()
scan_status = {
    'is_scanning': False,
    'last_scan_time': None,
    'scan_progress': 0,
    'current_subnet': ''
}
scan_results = {}
port_scan_results = {}

history_manager = HistoryManager()


def background_scan(target_range=None):
    """バックグラウンドでスキャンを実行

    Args:
        target_range: スキャン対象（例: "192.168.0.0/24"、"192.168.0.1-50"、または "192.168.0.0/24,172.17.0.0/16"）
    """
    global scan_status, scan_results

    scan_status['is_scanning'] = True
    scan_status['scan_progress'] = 0
    scan_status['current_subnet'] = 'スキャン準備中...'
    scan_status['found_hosts'] = 0

    try:
        print("\n" + "="*60)
        print("ネットワークスキャン開始")
        print("="*60)

        if target_range:
            print(f"\nスキャン対象: {target_range}")
            scan_status['scan_progress'] = 10  # スキャン開始

            # チャンクレベルの進捗を反映するコールバック
            def progress_callback(completed_chunks, total_chunks, found_hosts):
                # 進捗を10%から90%の範囲で更新
                chunk_progress = 10 + int((completed_chunks / total_chunks) * 80)
                scan_status['scan_progress'] = chunk_progress
                scan_status['found_hosts'] = found_hosts
                scan_status['current_subnet'] = f'{target_range} をスキャン中... (チャンク {completed_chunks}/{total_chunks})'

            results = scanner.scan_ip_range(target_range, progress_callback=progress_callback)
            scan_status['found_hosts'] = len(results)
        else:
            # サブネットを検出（デフォルト動作）
            print("\n[ステップ 1/2] サブネットを検出中...")
            scan_status['scan_progress'] = 5
            subnets = scanner.detect_subnets()
            total_subnets = len(subnets)
            print(f"✓ {total_subnets}個のサブネットを検出しました: {', '.join(subnets)}")

            # 各サブネットをスキャン
            print(f"\n[ステップ 2/2] 各サブネットをスキャン中...")
            scan_status['scan_progress'] = 10
            results = {}
            for idx, subnet in enumerate(subnets):
                scan_status['current_subnet'] = f'{subnet} をスキャン中... ({idx+1}/{total_subnets})'

                # チャンクレベルの進捗を反映するコールバック
                def progress_callback(completed_chunks, total_chunks, found_hosts):
                    # サブネット間の進捗: 10% + (idx/total_subnets) * 80%
                    # サブネット内の進捗: (completed_chunks/total_chunks) * (80/total_subnets)%
                    subnet_base_progress = 10 + int((idx / total_subnets) * 80)
                    subnet_progress_range = int(80 / total_subnets)
                    chunk_progress = int((completed_chunks / total_chunks) * subnet_progress_range)
                    scan_status['scan_progress'] = subnet_base_progress + chunk_progress
                    scan_status['found_hosts'] = len(results) + found_hosts
                    scan_status['current_subnet'] = f'{subnet} をスキャン中... ({idx+1}/{total_subnets}) - チャンク {completed_chunks}/{total_chunks}'

                print(f"\n進捗: {idx+1}/{total_subnets} サブネット")
                subnet_results = scanner.ping_scan(subnet, progress_callback=progress_callback)
                results.update(subnet_results)
                scan_status['found_hosts'] = len(results)

        scan_results = results
        scan_status['last_scan_time'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        scan_status['scan_progress'] = 100
        scan_status['current_subnet'] = f'完了 ({len(results)}台のホストを検出)'

        # スキャン結果を履歴に保存
        target_str = target_range if target_range else 'auto-detect'
        history_manager.add_scan_record(target_str, results)
        print(f"✓ スキャン結果を履歴に保存しました")

        print("\n" + "="*60)
        print(f"全スキャン完了!")
        print(f"検出されたホスト総数: {len(results)}台")
        print("="*60 + "\n")

    except Exception as e:
        print(f"\n✗ スキャンエラー: {e}\n")
        scan_status['error'] = str(e)
        scan_status['scan_progress'] = 0

    finally:
        scan_status['is_scanning'] = False


@app.route('/')
def index():
    """メインページ"""
    return render_template('index.html')


@app.route('/api/scan', methods=['POST'])
def start_scan():
    """
    ネットワークスキャンを開始

    Request Body:
        target_range (optional): スキャン対象（例: "192.168.0.0/24" または "192.168.0.1-50"）

    Returns:
        JSON: スキャン開始ステータス
    """
    global scan_status

    # nmapの利用可否をチェック
    if not scanner.check_nmap_available():
        return jsonify({
            'status': 'error',
            'message': 'nmapがインストールされていません。インストール後に再度お試しください。',
            'nmap_error': scanner.nmap_error
        }), 503

    if scan_status['is_scanning']:
        return jsonify({
            'status': 'error',
            'message': 'スキャンは既に実行中です'
        }), 400

    # リクエストボディからIP範囲を取得
    target_range = None
    if request.json and 'target_range' in request.json:
        target_range = request.json['target_range']

    # バックグラウンドでスキャンを開始
    scan_thread = threading.Thread(target=background_scan, args=(target_range,))
    scan_thread.daemon = True
    scan_thread.start()

    return jsonify({
        'status': 'success',
        'message': 'スキャンを開始しました',
        'target_range': target_range
    })


@app.route('/api/scan-status', methods=['GET'])
def get_scan_status():
    """
    スキャンの状態を取得

    Returns:
        JSON: スキャンステータス
    """
    status = scan_status.copy()
    status['nmap_available'] = scanner.check_nmap_available()
    if not scanner.check_nmap_available():
        status['nmap_error'] = scanner.nmap_error
    return jsonify(status)


@app.route('/api/results', methods=['GET'])
def get_results():
    """
    スキャン結果を取得

    Returns:
        JSON: スキャン結果
    """
    return jsonify({
        'hosts': scan_results,
        'total': len(scan_results)
    })


@app.route('/api/port-scan/<host>', methods=['POST'])
def start_port_scan(host):
    """
    指定されたホストに対してポートスキャンを実行（2段階スキャン）

    Args:
        host: スキャン対象のIPアドレス

    Returns:
        JSON: ポートスキャン結果
    """
    global port_scan_results

    # ホストが存在するか確認
    if host not in scan_results:
        return jsonify({
            'status': 'error',
            'message': '指定されたホストが見つかりません'
        }), 404

    # スキャンオプションを取得（デフォルト: -sT -sV）
    scan_args = request.json.get('arguments', '-sT -sV') if request.json else '-sT -sV'
    # スキャンモードを取得（priority: 優先ポートのみ、full: 全ポートのみ）
    scan_mode = request.json.get('scan_mode', 'priority') if request.json else 'priority'

    def scan_priority_ports():
        """優先ポートスキャンを実行（高速化）"""
        try:
            print(f"\n[優先ポートスキャン] {host} の優先ポートをスキャン中...")
            # -T5 を追加して高速化
            fast_scan_args = scan_args.replace('-sV', '-sV -T5') if '-sV' in scan_args else scan_args + ' -T5'
            priority_result = scanner.port_scan(host, fast_scan_args, priority_only=True)
            port_scan_results[host] = priority_result
            print(f"[優先ポートスキャン完了] {len(priority_result.get('ports', []))}個のポートを検出")
        except Exception as e:
            print(f"\n優先ポートスキャンエラー ({host}): {e}\n")
            if host not in port_scan_results:
                port_scan_results[host] = {
                    'host': host,
                    'ports': [],
                    'os': '',
                    'scan_time': '',
                    'scan_stage': 'error',
                    'error': str(e)
                }

    def scan_full_ports():
        """全ポートスキャンを並列実行（2段階: ポート検出→サービス情報取得）"""
        try:
            print(f"\n{'='*60}")
            print(f"[2段階スキャン開始] {host}")
            print(f"第1段階: ポート検出（6スレッド並列）")
            print(f"第2段階: サービス情報取得（発見したポートのみ）")
            print(f"{'='*60}")

            # 進捗情報を初期化
            port_scan_results[host] = {
                'host': host,
                'ports': [],
                'os': '',
                'scan_time': '',
                'scan_stage': 'full_scanning',
                'progress': {
                    'total_ports': 65535,
                    'scanned_ports': 0,
                    'found_ports': 0,
                    'service_scanned': 0,
                    'overall_progress': 0
                }
            }

            # 全ポートを6つの範囲に分割して並列スキャン
            port_ranges = [
                (1, 10922),
                (10923, 21844),
                (21845, 32766),
                (32767, 43688),
                (43689, 54610),
                (54611, 65535)
            ]

            # ===== 第1段階: ポート検出（全範囲を並列スキャン） =====
            print(f"\n[第1段階] ポート検出開始...")
            port_results = []
            threads = []
            progress_lock = threading.Lock()

            def scan_ports_only(start, end):
                """指定範囲のポートを検出（サービス情報なし）"""
                try:
                    print(f"  [範囲 {start}-{end}] ポートスキャン中...")
                    # -sT: TCP接続スキャン
                    # -T4: 高速スキャン（T5より安定）
                    # --open: オープンポートのみ
                    # --host-timeout 30s: ホストごとのタイムアウト
                    range_args = f"-p {start}-{end} -sT -T4 --open --host-timeout 30s"
                    print(f"  [範囲 {start}-{end}] 実行コマンド: nmap {range_args} {host} (サービス情報なし)")
                    result = scanner.port_scan(host, range_args, priority_only=False, is_range_scan=True, verbose=False)

                    if result.get('ports') and len(result['ports']) > 0:
                        print(f"  [範囲 {start}-{end}] ✓ {len(result['ports'])}個のポートを発見")
                        port_results.append(result)
                    else:
                        print(f"  [範囲 {start}-{end}] ポートなし")

                    # 進捗を更新（このポート範囲をスキャン完了）
                    scanned_count = end - start + 1
                    with progress_lock:
                        port_scan_results[host]['progress']['scanned_ports'] += scanned_count
                        # 第1段階の進捗: 0-50%
                        stage1_progress = (port_scan_results[host]['progress']['scanned_ports'] / 65535) * 50
                        port_scan_results[host]['progress']['overall_progress'] = round(stage1_progress, 1)
                        print(f"  [進捗更新] {port_scan_results[host]['progress']['scanned_ports']}/{65535}ポート完了 ({port_scan_results[host]['progress']['overall_progress']}%)")

                except Exception as e:
                    print(f"  [範囲 {start}-{end}] エラー: {e}")

            # ポート検出を並列実行
            for start, end in port_ranges:
                thread = threading.Thread(target=scan_ports_only, args=(start, end))
                thread.daemon = True
                thread.start()
                threads.append(thread)

            # 全スレッドの完了を待つ
            for thread in threads:
                thread.join()

            print(f"\n[第1段階完了] ポート検出が完了しました")

            # 発見したポートを収集
            all_open_ports = []
            for result in port_results:
                if 'ports' in result:
                    all_open_ports.extend(result['ports'])

            # 発見ポート数を進捗に記録
            found_ports_count = len(all_open_ports)
            with progress_lock:
                port_scan_results[host]['progress']['found_ports'] = found_ports_count

            # ===== 第2段階: サービス情報取得（6スレッド並列） =====
            if len(all_open_ports) > 0:
                print(f"\n[第2段階] サービス情報取得開始（6スレッド並列）...")
                print(f"  発見したポート数: {len(all_open_ports)}個")

                # ポート番号のみ抽出してソート
                port_numbers = sorted([p['port'] for p in all_open_ports])
                print(f"  全ポート番号: {port_numbers}")

                # ポートを6グループに分割（できるだけ均等に）
                chunk_size = max(1, len(port_numbers) // 6)
                print(f"  chunk_size: {chunk_size} (total: {len(port_numbers)}, threads: 6)")
                port_chunks = []
                for i in range(0, len(port_numbers), chunk_size):
                    chunk = port_numbers[i:i + chunk_size]
                    if chunk:
                        port_chunks.append(chunk)
                        print(f"  追加chunk (i={i}): {chunk}")

                # 最後の小さなチャンクを前のチャンクに統合（6つを超えた場合）
                if len(port_chunks) > 6:
                    last_chunk = port_chunks.pop()
                    port_chunks[-1].extend(last_chunk)
                    print(f"  最後のchunkを統合: {port_chunks[-1]}")

                print(f"  ポートを{len(port_chunks)}グループに分割")
                for idx, chunk in enumerate(port_chunks, 1):
                    if len(chunk) > 0:
                        chunk_str = f"{chunk[0]}-{chunk[-1]}" if len(chunk) > 1 else str(chunk[0])
                        print(f"    グループ{idx}: {len(chunk)}ポート ({chunk_str}) - ポート番号: {chunk}")

                # サービス情報取得を並列実行
                service_results = []
                service_threads = []

                def scan_service_info(port_list, group_num, total_found_ports):
                    """指定ポートのサービス情報を取得"""
                    try:
                        ports_str = ','.join(map(str, port_list))
                        print(f"  [グループ{group_num}] サービス情報取得中... ({len(port_list)}ポート)")
                        print(f"  [グループ{group_num}] 対象ポート: {ports_str}")

                        # -sV: サービスバージョン検出
                        # -T4: 高速スキャン（T5より安定）
                        # --version-intensity 2: 軽量なバージョン検出（デフォルト7→2で大幅高速化）
                        # --host-timeout 20s: ホストごとのタイムアウト
                        service_args = f"-p {ports_str} -sV -T4 --version-intensity 2 --host-timeout 20s"
                        print(f"  [グループ{group_num}] 実行コマンド: nmap {service_args} {host}")
                        result = scanner.port_scan(host, service_args, priority_only=False, is_range_scan=True, verbose=False)

                        if result.get('ports'):
                            print(f"  [グループ{group_num}] ✓ {len(result['ports'])}ポートの情報取得完了")
                            service_results.append(result)

                            # 進捗を更新（サービス情報取得完了）
                            with progress_lock:
                                # progressキーの存在を確認
                                if 'progress' in port_scan_results.get(host, {}):
                                    port_scan_results[host]['progress']['service_scanned'] += len(result['ports'])
                                    # 第2段階の進捗: 50-100%
                                    if total_found_ports > 0:
                                        stage2_progress = (port_scan_results[host]['progress']['service_scanned'] / total_found_ports) * 50
                                        port_scan_results[host]['progress']['overall_progress'] = round(50 + stage2_progress, 1)
                                        print(f"  [進捗更新] サービス情報 {port_scan_results[host]['progress']['service_scanned']}/{total_found_ports}ポート完了 ({port_scan_results[host]['progress']['overall_progress']}%)")
                        else:
                            print(f"  [グループ{group_num}] 情報取得なし")
                    except Exception as e:
                        import traceback
                        print(f"  [グループ{group_num}] エラー: {e}")
                        print(f"  [グループ{group_num}] トレースバック: {traceback.format_exc()}")

                # サービス情報取得を並列実行
                for idx, chunk in enumerate(port_chunks, 1):
                    thread = threading.Thread(target=scan_service_info, args=(chunk, idx, found_ports_count))
                    thread.daemon = True
                    thread.start()
                    service_threads.append(thread)

                # 全スレッドの完了を待つ
                print(f"  [待機] {len(service_threads)}個のスレッドの完了を待機中...")
                for idx, thread in enumerate(service_threads, 1):
                    thread.join()
                    print(f"  [待機] スレッド{idx}/{len(service_threads)}完了")

                print(f"\n[第2段階完了] サービス情報取得が完了しました")
                print(f"  取得結果数: {len(service_results)}個")

                # 結果を統合
                print(f"\n[結果統合] service_results数: {len(service_results)}")
                final_ports = []
                for idx, result in enumerate(service_results, 1):
                    if 'ports' in result:
                        print(f"  結果{idx}: {len(result['ports'])}ポート")
                        final_ports.extend(result['ports'])
                    else:
                        print(f"  結果{idx}: ポート情報なし")

                print(f"  統合後の総ポート数: {len(final_ports)}")

                # ポート番号順にソート
                final_ports.sort(key=lambda x: x['port'])

                # 最終結果
                merged_result = {
                    'host': host,
                    'ports': final_ports if final_ports else all_open_ports,
                    'os': service_results[0].get('os', '') if service_results else '',
                    'scan_time': '',
                    'scan_stage': 'full'
                }
                print(f"\n[最終結果設定] scan_stage='full', ポート数: {len(merged_result['ports'])}")
            else:
                print(f"\n[第2段階スキップ] ポートが発見されませんでした")
                merged_result = {
                    'host': host,
                    'ports': [],
                    'os': '',
                    'scan_time': '',
                    'scan_stage': 'full'
                }

            # ポートを番号順にソート
            print(f"\n[ソート] {len(merged_result['ports'])}個のポートをソート中...")
            if merged_result['ports']:
                merged_result['ports'].sort(key=lambda x: x['port'])
                print(f"  ソート完了")

            print(f"\n[結果更新] port_scan_results[{host}]を更新中...")
            port_scan_results[host] = merged_result
            print(f"  更新完了: scan_stage={merged_result['scan_stage']}")

            print(f"\n{'='*60}")
            print(f"[2段階スキャン完了] {len(merged_result['ports'])}個のポートを検出")
            print(f"{'='*60}\n")

        except Exception as e:
            import traceback
            print(f"\n{'='*60}")
            print(f"全ポートスキャンエラー ({host}): {e}")
            print(f"トレースバック:")
            print(traceback.format_exc())
            print(f"{'='*60}\n")
            if host in port_scan_results:
                port_scan_results[host]['error'] = str(e)
                port_scan_results[host]['scan_stage'] = 'error'

    # スキャンモードに応じて実行
    def run_scan():
        """スキャンモードに応じて優先ポートまたは全ポートを実行"""
        if scan_mode == 'priority':
            # 優先ポートのみ
            print(f"[スキャンモード] 優先ポートのみ実行")
            scan_priority_ports()
        elif scan_mode == 'full':
            # 全ポートのみ
            print(f"[スキャンモード] 全ポートのみ実行")
            scan_full_ports()
        else:
            print(f"[エラー] 不明なスキャンモード: {scan_mode}")

    # スキャンをバックグラウンドスレッドで実行
    scan_thread = threading.Thread(target=run_scan)
    scan_thread.daemon = True
    scan_thread.start()

    # スキャンモードに応じたメッセージ
    messages = {
        'priority': '優先ポートスキャンを開始しました',
        'full': '全ポートスキャンを開始しました（6スレッド並列）'
    }

    return jsonify({
        'status': 'success',
        'message': messages.get(scan_mode, 'ポートスキャンを開始しました')
    })


@app.route('/api/port-scan/<host>', methods=['GET'])
def get_port_scan_result(host):
    """
    指定されたホストのポートスキャン結果を取得

    Args:
        host: IPアドレス

    Returns:
        JSON: ポートスキャン結果
    """
    if host in port_scan_results:
        return jsonify({
            'status': 'success',
            'data': port_scan_results[host]
        })
    else:
        # スキャン結果がない場合、404ではなくスキャン待機中として返す
        return jsonify({
            'status': 'pending',
            'message': 'スキャン実行中または未実行です'
        })


@app.route('/api/host/<host>', methods=['DELETE'])
def remove_host(host):
    """
    スキャン結果から指定されたホストを削除

    Args:
        host: IPアドレス

    Returns:
        JSON: 削除結果
    """
    global scan_results, port_scan_results

    if host in scan_results:
        del scan_results[host]
        if host in port_scan_results:
            del port_scan_results[host]

        return jsonify({
            'status': 'success',
            'message': f'ホスト {host} を削除しました'
        })
    else:
        return jsonify({
            'status': 'error',
            'message': 'ホストが見つかりません'
        }), 404


@app.route('/api/sudo-password', methods=['POST'])
def set_sudo_password():
    """
    sudoパスワードを設定

    Request Body:
        {
            "password": "sudo password"
        }

    Returns:
        JSON: 設定結果
    """
    if not request.json or 'password' not in request.json:
        return jsonify({
            'status': 'error',
            'message': 'パスワードが指定されていません'
        }), 400

    password = request.json['password']

    try:
        # パスワードをスキャナーに設定
        scanner.set_sudo_password(password)

        return jsonify({
            'status': 'success',
            'message': 'sudoパスワードを設定しました'
        })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': f'設定に失敗しました: {str(e)}'
        }), 500


@app.route('/api/process-info/<host>', methods=['GET'])
def get_process_info(host):
    """
    指定されたホストのポートで動作しているプロセス情報を取得
    注: リモートホストのプロセス情報は取得できません（ローカルマシンのみ）

    Args:
        host: IPアドレス（ローカルマシンかどうかのチェックに使用）

    Returns:
        JSON: プロセス情報 {port/protocol: {pid: xxx, name: xxx}}
    """
    import subprocess
    import re

    process_info = {}

    # ローカルIPアドレスのリスト
    local_ips = ['127.0.0.1', 'localhost', '::1']
    try:
        # 実際のローカルIPも追加
        local_ips.append(scanner.get_local_ip())
    except:
        pass

    # リモートホストの場合は空の結果を返す（エラーではない）
    if host not in local_ips and not host.startswith('127.') and not host.startswith('::'):
        # リモートホストのプロセス情報は取得できないため、空の結果を返す
        return jsonify({
            'status': 'success',
            'data': {},
            'note': 'リモートホストのプロセス情報は取得できません'
        })

    try:
        # lsof, ss, netstat を順に試す
        result = None
        command_type = None

        # 優先度1: lsof（最も詳細な情報）
        try:
            result = subprocess.run(
                ['lsof', '-i', '-n', '-P'],
                capture_output=True,
                text=True,
                timeout=10
            )
            if result.returncode == 0:
                command_type = 'lsof'
        except FileNotFoundError:
            pass

        # 優先度2: ss
        if result is None or result.returncode != 0:
            try:
                result = subprocess.run(
                    ['ss', '-tunlp'],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                if result.returncode == 0:
                    command_type = 'ss'
            except FileNotFoundError:
                pass

        # 優先度3: netstat
        if result is None or result.returncode != 0:
            try:
                result = subprocess.run(
                    ['netstat', '-tunlp'],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                if result.returncode == 0:
                    command_type = 'netstat'
            except FileNotFoundError:
                pass

        # いずれのコマンドも使えない場合
        if result is None or result.returncode != 0:
            return jsonify({
                'status': 'success',
                'data': {},
                'warning': 'lsof, ss, netstatコマンドが見つかりません'
            })

        output = result.stdout

        # 各行をパース（コマンドタイプに応じて）
        for line in output.split('\n'):
            if not line.strip():
                continue

            # lsofの出力をパース
            # 例: python3   12345  user   3u  IPv4  12345      0t0  TCP *:5000 (LISTEN)
            # 例: python3   12345  user   3u  IPv4  12345      0t0  TCP 127.0.0.1:5000 (LISTEN)
            if command_type == 'lsof':
                match = re.search(r'^(\S+)\s+(\d+)\s+\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+(TCP|UDP)\s+[^:]*:(\d+)\s+\(LISTEN\)', line, re.IGNORECASE)
                if match:
                    name = match.group(1)
                    pid = match.group(2)
                    protocol = match.group(3).lower()
                    port = match.group(4)

                    port_key = f"{port}/{protocol}"
                    if port_key not in process_info:
                        process_info[port_key] = {
                            'pid': int(pid),
                            'name': name
                        }
                    continue

            # ssの出力をパース
            # 例: tcp   LISTEN 0      128    0.0.0.0:22    0.0.0.0:*    users:(("sshd",pid=1234,fd=3))
            if command_type == 'ss':
                match = re.search(r':(\d+)\s.*users:\(\("([^"]+)",pid=(\d+)', line)
                if match:
                    port = match.group(1)
                    name = match.group(2)
                    pid = match.group(3)

                    # プロトコルを判定
                    protocol = 'tcp' if 'tcp' in line.lower() else 'udp'
                    port_key = f"{port}/{protocol}"

                    process_info[port_key] = {
                        'pid': int(pid),
                        'name': name
                    }
                    continue

            # netstatの出力をパース
            # 例: tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      1234/sshd
            if command_type == 'netstat':
                match = re.search(r'(tcp|udp)\s+\d+\s+\d+\s+[^:]*:(\d+)\s+.*?LISTEN\s+(\d+)/(\S+)', line, re.IGNORECASE)
                if match:
                    protocol = match.group(1).lower()
                    port = match.group(2)
                    pid = match.group(3)
                    name = match.group(4)

                    port_key = f"{port}/{protocol}"
                    if port_key not in process_info:
                        process_info[port_key] = {
                            'pid': int(pid),
                            'name': name
                        }
                    continue

        return jsonify({
            'status': 'success',
            'data': process_info
        })

    except subprocess.TimeoutExpired:
        # タイムアウトの場合も空の結果を返す（エラーにしない）
        return jsonify({
            'status': 'success',
            'data': {},
            'warning': 'プロセス情報の取得がタイムアウトしました'
        })
    except Exception as e:
        # エラーの場合も空の結果を返す（500エラーにしない）
        print(f"プロセス情報取得エラー: {e}")
        return jsonify({
            'status': 'success',
            'data': {},
            'warning': f'プロセス情報を取得できませんでした'
        })


@app.route('/api/kill-process/<int:pid>', methods=['POST'])
def kill_process(pid):
    """
    指定されたプロセスを安全に終了

    Args:
        pid: プロセスID

    Returns:
        JSON: 終了結果
    """
    import subprocess
    import signal
    import os

    # 安全性チェック: 重要なシステムプロセスを保護
    protected_pids = [0, 1]  # init/systemd など
    if pid in protected_pids or pid <= 0:
        return jsonify({
            'status': 'error',
            'message': f'PID {pid} は保護されたプロセスです'
        }), 403

    try:
        # PIDが存在するか確認
        try:
            os.kill(pid, 0)  # シグナル0で存在確認
        except OSError:
            return jsonify({
                'status': 'error',
                'message': f'PID {pid} のプロセスが見つかりません'
            }), 404

        # プロセス名を取得して確認用に表示
        try:
            proc_name_result = subprocess.run(
                ['ps', '-p', str(pid), '-o', 'comm='],
                capture_output=True,
                text=True,
                timeout=2
            )
            proc_name = proc_name_result.stdout.strip() if proc_name_result.returncode == 0 else 'unknown'
        except:
            proc_name = 'unknown'

        # プロセスを終了
        try:
            os.kill(pid, signal.SIGTERM)  # まずSIGTERMで穏やかに終了
            return jsonify({
                'status': 'success',
                'message': f'プロセス {pid} ({proc_name}) を終了しました'
            })
        except PermissionError:
            # 権限がない場合はsudoで試す
            if scanner.sudo_password:
                try:
                    result = subprocess.run(
                        ['sudo', '-S', 'kill', '-TERM', str(pid)],
                        input=f"{scanner.sudo_password}\n",
                        capture_output=True,
                        text=True,
                        timeout=10
                    )
                    if result.returncode == 0:
                        return jsonify({
                            'status': 'success',
                            'message': f'プロセス {pid} ({proc_name}) を終了しました（sudo使用）'
                        })
                    else:
                        # パスワードエラーのチェック
                        if 'incorrect password' in result.stderr.lower() or 'sorry' in result.stderr.lower():
                            return jsonify({
                                'status': 'error',
                                'message': 'sudoパスワードが正しくありません'
                            }), 403
                        return jsonify({
                            'status': 'error',
                            'message': f'プロセスの終了に失敗しました: {result.stderr}'
                        }), 500
                except subprocess.TimeoutExpired:
                    return jsonify({
                        'status': 'error',
                        'message': 'プロセスの終了がタイムアウトしました'
                    }), 500
            else:
                return jsonify({
                    'status': 'error',
                    'message': 'プロセスの終了に権限が必要です。sudo設定からパスワードを設定してください'
                }), 403

    except Exception as e:
        print(f"プロセス終了エラー (PID {pid}): {e}")
        return jsonify({
            'status': 'error',
            'message': f'プロセスの終了に失敗しました: {str(e)}'
        }), 500


@app.route('/api/http-info/<host>/<int:port>', methods=['GET'])
def get_http_info(host, port):
    """
    指定されたホストとポートのHTTP詳細情報を取得

    Args:
        host: ホストのIPアドレス
        port: ポート番号

    Returns:
        JSON: HTTP詳細情報
    """
    try:
        # HTTPSを試すかどうか（443, 8443などはHTTPS）
        use_https = port in [443, 8443]

        # HTTP情報を取得
        http_info = scanner.get_http_info(host, port, use_https)

        # HTTPSで失敗した場合、HTTPを試す
        if not http_info['accessible'] and use_https:
            http_info = scanner.get_http_info(host, port, use_https=False)

        return jsonify(http_info)

    except Exception as e:
        print(f"HTTP情報取得エラー ({host}:{port}): {e}")
        return jsonify({
            'status': 'error',
            'message': f'HTTP情報の取得に失敗しました: {str(e)}'
        }), 500


@app.route('/api/network-topology', methods=['GET'])
def get_network_topology():
    """
    ネットワークトポロジーのグラフデータを取得

    Returns:
        JSON: ネットワークトポロジー（nodes, edges, stats）
    """
    try:
        # 現在のスキャン結果からトポロジーを生成
        topology = scanner.generate_network_topology(scan_results, port_scan_results)

        return jsonify(topology)

    except Exception as e:
        print(f"ネットワークトポロジー生成エラー: {e}")
        return jsonify({
            'status': 'error',
            'message': f'ネットワークトポロジーの生成に失敗しました: {str(e)}'
        }), 500


@app.before_request
def limit_remote_addr():
    """
    セキュリティ: ローカルホストからのアクセスのみ許可
    """
    allowed_ips = ['127.0.0.1', 'localhost', '::1']
    client_ip = request.remote_addr

    # 開発環境では全てのアクセスを許可（本番環境では削除すること）
    # if client_ip not in allowed_ips:
    #     return jsonify({'error': 'アクセス拒否: ローカルホストのみアクセス可能です'}), 403

@app.route('/api/history', methods=['GET'])
def get_scan_history():
    """
    スキャン履歴一覧を取得

    Returns:
        JSON: スキャン履歴のリスト
    """
    try:
        history = history_manager.load_history()
        response = jsonify(history)
        response.headers['Content-Type'] = 'application/json'
        return response
    except Exception as e:
        print(f"履歴取得エラー: {e}")
        response = jsonify([])
        response.headers['Content-Type'] = 'application/json'
        return response, 200


@app.route('/api/history/<int:scan_id>', methods=['GET'])
def get_scan_detail(scan_id):
    """
    特定のスキャン記録の詳細を取得

    Args:
        scan_id: スキャンID

    Returns:
        JSON: スキャン記録の詳細
    """
    try:
        scan = history_manager.get_scan_by_id(scan_id)
        if scan:
            response = jsonify(scan)
            response.headers['Content-Type'] = 'application/json'
            return response
        else:
            response = jsonify({'error': 'Scan not found'})
            response.headers['Content-Type'] = 'application/json'
            return response, 404
    except Exception as e:
        print(f"スキャン詳細取得エラー: {e}")
        response = jsonify({'error': str(e)})
        response.headers['Content-Type'] = 'application/json'
        return response, 500


@app.route('/api/history/<int:scan_id>/load', methods=['POST'])
def load_scan_from_history(scan_id):
    """
    履歴からスキャン結果を読み込んで現在の結果として表示

    Args:
        scan_id: スキャンID

    Returns:
        JSON: 読み込み結果
    """
    global scan_results

    try:
        scan = history_manager.get_scan_by_id(scan_id)
        if scan:
            # 現在の結果として設定
            scan_results = scan['hosts']

            response = jsonify({
                'success': True,
                'hosts': scan_results,
                'target': scan['target'],
                'timestamp': scan['timestamp']
            })
            response.headers['Content-Type'] = 'application/json'
            return response
        else:
            response = jsonify({'success': False, 'error': 'Scan not found'})
            response.headers['Content-Type'] = 'application/json'
            return response, 404
    except Exception as e:
        print(f"履歴読み込みエラー: {e}")
        response = jsonify({'success': False, 'error': str(e)})
        response.headers['Content-Type'] = 'application/json'
        return response, 500


@app.route('/api/history/<int:scan_id>', methods=['DELETE'])
def delete_scan_history(scan_id):
    """
    特定のスキャン履歴を削除

    Args:
        scan_id: 削除するスキャンID

    Returns:
        JSON: 削除結果
    """
    try:
        success = history_manager.delete_scan(scan_id)

        response = jsonify({'success': success})
        response.headers['Content-Type'] = 'application/json'

        if success:
            return response
        else:
            return response, 404
    except Exception as e:
        print(f"履歴削除エラー: {e}")
        response = jsonify({'success': False, 'error': str(e)})
        response.headers['Content-Type'] = 'application/json'
        return response, 500


@app.route('/api/history/summary', methods=['GET'])
def get_history_summary():
    """
    履歴の統計情報を取得

    Returns:
        JSON: 統計情報
    """
    try:
        summary = history_manager.get_history_summary()
        response = jsonify(summary)
        response.headers['Content-Type'] = 'application/json'
        return response
    except Exception as e:
        print(f"統計情報取得エラー: {e}")
        response = jsonify({'error': str(e)})
        response.headers['Content-Type'] = 'application/json'
        return response, 500

if __name__ == '__main__':
    import socket

    print("\n" + "="*60)
    print("LocalNetScan - ローカルネットワークスキャナー")
    print("="*60)
    print("✓ アプリケーションを起動しています...")

    # nmapのチェック
    if not scanner.check_nmap_available():
        print("\n" + "!"*60)
        print("⚠ 警告: nmapが利用できません")
        print("!"*60)
        print("nmapをインストール後、Webインターフェースから")
        print("手動でスキャンを実行してください")
        print("!"*60)

    # ポートを試す（5000, 5001, 5002）
    host = '127.0.0.1'
    ports_to_try = [5000, 5001, 5002]
    port_found = None

    for port in ports_to_try:
        # ポートが使用可能かチェック
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((host, port))
        sock.close()

        if result != 0:  # ポートが空いている
            port_found = port
            print(f"✓ ポート {port} が利用可能です")
            print(f"✓ ブラウザで http://{host}:{port} にアクセスしてください")
            print("="*60)
            break
        else:
            print(f"⚠ ポート {port} は既に使用中です...")

    if port_found is None:
        print("\n" + "!"*60)
        print("✗ エラー: 利用可能なポートが見つかりませんでした")
        print("!"*60)
        print("ポート 5000, 5001, 5002 が全て使用中です。")
        print("いずれかのポートを解放してから再度お試しください。")
        print("\nヒント:")
        print("- macOSの場合: 'AirPlay Receiver'を無効化")
        print("  (システム設定 → 一般 → AirDropとHandoff)")
        print("- 使用中のプロセスを確認:")
        print("  lsof -i :5000")
        print("!"*60 + "\n")
        exit(1)

    # Flaskアプリケーションを起動
    # host='0.0.0.0' でローカルネットワークからアクセス可能
    # 本番環境ではセキュリティに注意
    app.run(host=host, port=port_found, debug=True, use_reloader=False)
