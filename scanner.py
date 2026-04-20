#!/usr/bin/env python3
"""
ネットワークスキャン機能を提供するモジュール
"""

import nmap
import socket
import subprocess
import re
import platform
import requests
import networkx as nx
from typing import List, Dict, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
# # 履歴サイドバーモジュール追加
# from history_manager import HistoryManager

# SSL警告を抑制（自己署名証明書のHTTPSアクセス時）
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class NetworkScanner:
    """ネットワークスキャンを実行するクラス"""

    def __init__(self):
        """スキャナーの初期化"""
        self.scan_results = {}
        self.nmap_available = False
        self.nmap_error = None
        self.sudo_password = None

        try:
            self.nm = nmap.PortScanner()
            self.nmap_available = True
        except Exception as e:
            self.nmap_error = str(e)
            print("=" * 80)
            print("エラー: nmapがシステムにインストールされていません")
            print("=" * 80)
            print("\nmacOSの場合、以下のコマンドでインストールしてください:")
            print("  brew install nmap")
            print("\nUbuntu/Debianの場合:")
            print("  sudo apt-get update")
            print("  sudo apt-get install nmap")
            print("\nWindowsの場合:")
            print("  https://nmap.org/download.html からダウンロードしてインストール")
            print("=" * 80)
            self.nm = None

    def set_sudo_password(self, password: str):
        """
        sudoパスワードを設定

        Args:
            password: sudoパスワード
        """
        self.sudo_password = password
        print("sudoパスワードが設定されました")

    def check_nmap_available(self) -> bool:
        """
        nmapが利用可能かチェック

        Returns:
            bool: nmapが利用可能な場合True
        """
        return self.nmap_available

    def get_local_ip(self) -> str:
        """
        ローカルIPアドレスを取得

        Returns:
            str: ローカルIPアドレス
        """
        try:
            # ダミーのUDP接続を作成してローカルIPを取得
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            return local_ip
        except Exception as e:
            print(f"ローカルIP取得エラー: {e}")
            return "127.0.0.1"

    def detect_subnets(self, include_docker: bool = True) -> List[str]:
        """
        ローカルネットワークのサブネットを検出

        Args:
            include_docker: Dockerネットワーク（172.x.x.x）も検出する場合True

        Returns:
            List[str]: 検出されたサブネットのリスト（例: ["192.168.0.0/24", "172.17.0.0/16"]）
        """
        subnets = []
        local_ip = self.get_local_ip()

        # ローカルIPから所属サブネットを判定
        ip_parts = local_ip.split('.')
        if ip_parts[0] == '192' and ip_parts[1] == '168':
            # 現在のサブネットを追加
            subnet = f"192.168.{ip_parts[2]}.0/24"
            subnets.append(subnet)

        # 複数のネットワークインターフェースから全てのサブネットを検出
        try:
            if platform.system() == 'Linux':
                result = subprocess.run(['ip', 'addr'], capture_output=True, text=True, timeout=5)
                output = result.stdout

                # 192.168.x.x のアドレスを抽出
                pattern = r'inet (192\.168\.\d+\.\d+)/(\d+)'
                matches = re.findall(pattern, output)
                for match in matches:
                    ip, netmask = match
                    ip_parts = ip.split('.')
                    subnet = f"192.168.{ip_parts[2]}.0/{netmask}"
                    if subnet not in subnets:
                        subnets.append(subnet)

                # Dockerネットワーク（172.x.x.x、10.x.x.x）を検出
                if include_docker:
                    # 172.x.x.x（Dockerデフォルト: 172.17.0.0/16など）
                    pattern_docker = r'inet (172\.\d+\.\d+\.\d+)/(\d+)'
                    matches_docker = re.findall(pattern_docker, output)
                    for match in matches_docker:
                        ip, netmask = match
                        ip_parts = ip.split('.')
                        # /16 または /24 の範囲に正規化
                        if int(netmask) >= 24:
                            subnet = f"172.{ip_parts[1]}.{ip_parts[2]}.0/24"
                        else:
                            subnet = f"172.{ip_parts[1]}.0.0/16"
                        if subnet not in subnets:
                            subnets.append(subnet)

                    # 10.x.x.x（プライベートネットワーク）
                    pattern_10 = r'inet (10\.\d+\.\d+\.\d+)/(\d+)'
                    matches_10 = re.findall(pattern_10, output)
                    for match in matches_10:
                        ip, netmask = match
                        ip_parts = ip.split('.')
                        if int(netmask) >= 24:
                            subnet = f"10.{ip_parts[1]}.{ip_parts[2]}.0/24"
                        else:
                            subnet = f"10.{ip_parts[1]}.0.0/16"
                        if subnet not in subnets:
                            subnets.append(subnet)

            elif platform.system() == 'Darwin':  # macOS
                result = subprocess.run(['ifconfig'], capture_output=True, text=True, timeout=5)
                output = result.stdout

                # 192.168.x.x のアドレスを抽出
                pattern = r'inet (192\.168\.\d+\.\d+)'
                matches = re.findall(pattern, output)
                for match in matches:
                    ip_parts = match.split('.')
                    subnet = f"192.168.{ip_parts[2]}.0/24"
                    if subnet not in subnets:
                        subnets.append(subnet)

                # Dockerネットワーク（172.x.x.x、10.x.x.x）を検出
                if include_docker:
                    # 172.x.x.x（Dockerデフォルト: 172.17.0.0/16など）
                    pattern_docker = r'inet (172\.\d+\.\d+\.\d+)'
                    matches_docker = re.findall(pattern_docker, output)
                    for match in matches_docker:
                        ip_parts = match.split('.')
                        # 一般的にDockerは/16
                        subnet = f"172.{ip_parts[1]}.0.0/16"
                        if subnet not in subnets:
                            subnets.append(subnet)

                    # 10.x.x.x（プライベートネットワーク）
                    pattern_10 = r'inet (10\.\d+\.\d+\.\d+)'
                    matches_10 = re.findall(pattern_10, output)
                    for match in matches_10:
                        ip_parts = match.split('.')
                        subnet = f"10.{ip_parts[1]}.0.0/16"
                        if subnet not in subnets:
                            subnets.append(subnet)

        except Exception as e:
            print(f"サブネット検出エラー: {e}")

        return subnets if subnets else ["192.168.0.0/24"]

    def _split_subnet_into_chunks(self, subnet: str, chunk_size: int = 24) -> List[str]:
        """
        サブネットを小さなチャンクに分割（並列スキャン用）

        Args:
            subnet: 分割対象のサブネット（例: "172.17.0.0/16"）
            chunk_size: チャンクのプレフィックスサイズ（デフォルト: 24）

        Returns:
            List[str]: 分割されたサブネットのリスト
        """
        chunks = []

        # IP範囲形式の場合はそのまま返す
        if '-' in subnet and '/' not in subnet:
            return [subnet]

        # サブネット形式の場合
        if '/' in subnet:
            ip_part, prefix = subnet.split('/')
            prefix = int(prefix)

            # /24以下（小さい範囲）の場合はそのまま返す
            if prefix >= chunk_size:
                return [subnet]

            # /16など大きな範囲の場合は/24に分割
            ip_octets = ip_part.split('.')
            base_ip = '.'.join(ip_octets[:2])  # 最初の2オクテット（例: 172.17）

            # /16の場合、256個の/24サブネットに分割
            if prefix == 16:
                for third_octet in range(256):
                    chunks.append(f"{base_ip}.{third_octet}.0/24")
            # /8の場合はさらに細かく分割（実際にはあまり使われない）
            elif prefix == 8:
                for second_octet in range(256):
                    for third_octet in range(256):
                        chunks.append(f"{ip_octets[0]}.{second_octet}.{third_octet}.0/24")
            # その他の場合は適切に分割
            else:
                # 簡易実装：とりあえずそのまま返す
                chunks.append(subnet)

        return chunks if chunks else [subnet]

    def _scan_single_chunk(self, chunk: str, original_subnet: str) -> Dict[str, Dict]:
        """
        単一チャンクをスキャン（スレッドセーフ、並列実行用）

        Args:
            chunk: スキャン対象のチャンク（例: "192.168.0.0/24"）
            original_subnet: 元のサブネット（結果に記録用）

        Returns:
            Dict: スキャン結果
        """
        results = {}

        try:
            # スレッドごとに独立したnmapインスタンスを作成
            nm = nmap.PortScanner()
            # 高速化オプション:
            # -sn: PINGスキャン（ポートスキャンなし）
            # -T4: 高速タイミング（aggressive）
            # --min-rate 300: 1秒あたり最低300パケット送信
            # --host-timeout 10s: ホストごとのタイムアウト10秒
            # --max-retries 1: 再試行回数を1回に制限
            nm.scan(hosts=chunk, arguments='-sn -T4 --min-rate 300 --host-timeout 10s --max-retries 1')

            for host in nm.all_hosts():
                if nm[host].state() == 'up':
                    hostname = nm[host].hostname() if nm[host].hostname() else 'Unknown'
                    vendor = ''
                    if 'mac' in nm[host]['addresses']:
                        mac = nm[host]['addresses']['mac']
                        vendor = nm[host]['vendor'].get(mac, '') if 'vendor' in nm[host] else ''

                    results[host] = {
                        'hostname': hostname,
                        'state': 'up',
                        'vendor': vendor,
                        'subnet': original_subnet
                    }

                    # 見つかったホストをリアルタイムで表示
                    print(f"  ✓ {host:15s} - {hostname}")

        except Exception as e:
            print(f"チャンク {chunk} のスキャンエラー: {e}")

        return results

    def ping_scan(self, subnet: str, progress_callback=None, max_threads: int = 10) -> Dict[str, Dict]:
        """
        指定されたサブネットに対してPingスキャン（nmap -sn）を並列実行

        Args:
            subnet: スキャン対象のサブネット（例: "192.168.0.0/24"）
            progress_callback: 進捗コールバック関数 callback(current, total, found_hosts)
            max_threads: 最大スレッド数（デフォルト: 10）

        Returns:
            Dict: スキャン結果（キー: IPアドレス、値: ホスト情報）
        """
        results = {}
        results_lock = threading.Lock()  # スレッドセーフな結果格納用

        if not self.nmap_available:
            print(f"エラー: nmapが利用できません - {self.nmap_error}")
            return results

        try:
            import time
            start_time = time.time()

            print(f"\n{'='*60}")
            print(f"Pingスキャン開始: {subnet}")
            print(f"{'='*60}")

            # サブネットを小さなチャンクに分割
            chunks = self._split_subnet_into_chunks(subnet)
            total_chunks = len(chunks)

            # サブネットから想定ホスト数を計算
            if '/' in subnet:
                prefix = int(subnet.split('/')[1])
                total_hosts = 2 ** (32 - prefix) - 2
            else:
                if '-' in subnet:
                    parts = subnet.split('-')
                    if len(parts) == 2 and '.' in parts[0]:
                        start_ip = parts[0].split('.')[-1]
                        end_ip = parts[1]
                        total_hosts = int(end_ip) - int(start_ip) + 1
                    else:
                        total_hosts = 254
                else:
                    total_hosts = 1

            if total_chunks > 1:
                print(f"高速スキャンモード: {total_chunks}個のチャンクを{max_threads}スレッドで並列実行")
            print(f"スキャン中... (最大{total_hosts}台のホストをチェック)")
            print("見つかったホスト:")

            # チャンクを並列スキャン
            completed_chunks = 0
            with ThreadPoolExecutor(max_workers=max_threads) as executor:
                # 全チャンクのスキャンを並列実行
                future_to_chunk = {
                    executor.submit(self._scan_single_chunk, chunk, subnet): chunk
                    for chunk in chunks
                }

                # 完了したチャンクから結果を収集
                for future in as_completed(future_to_chunk):
                    chunk = future_to_chunk[future]
                    try:
                        chunk_results = future.result()

                        # スレッドセーフに結果をマージ
                        with results_lock:
                            results.update(chunk_results)

                        completed_chunks += 1

                        # 進捗表示
                        if total_chunks > 1:
                            progress_pct = int((completed_chunks / total_chunks) * 100)
                            print(f"[進捗] {completed_chunks}/{total_chunks} チャンク完了 ({progress_pct}%) - 検出: {len(results)}台")

                        # 進捗コールバック
                        if progress_callback:
                            progress_callback(completed_chunks, total_chunks, len(results))

                    except Exception as e:
                        print(f"チャンク {chunk} の処理エラー: {e}")

            elapsed_time = time.time() - start_time
            print(f"\n{'='*60}")
            print(f"スキャン完了: {len(results)}台のホストを検出")
            print(f"所要時間: {elapsed_time:.1f}秒")
            if total_chunks > 1:
                print(f"並列実行: {max_threads}スレッド × {total_chunks}チャンク")
            print(f"{'='*60}\n")

        except Exception as e:
            print(f"\nPingスキャンエラー: {e}\n")

        return results

    def scan_ip_range(self, target_range: str, progress_callback=None) -> Dict[str, Dict]:
        """
        指定されたIP範囲をスキャン（複数範囲対応）

        Args:
            target_range: スキャン対象
                - サブネット形式: "192.168.0.0/24"
                - IP範囲形式: "192.168.0.1-50"
                - 複数範囲（カンマ区切り）: "192.168.0.0/24,172.17.0.0/16"
            progress_callback: 進捗コールバック関数 callback(current, total, found_hosts)

        Returns:
            Dict: スキャン結果
        """
        if not self.nmap_available:
            print(f"エラー: nmapが利用できません - {self.nmap_error}")
            return {}

        # カンマ区切りで複数範囲が指定されている場合
        if ',' in target_range:
            ranges = [r.strip() for r in target_range.split(',')]
            print(f"\n複数範囲スキャンモード: {len(ranges)}個の範囲を検出")
            all_results = {}

            for idx, single_range in enumerate(ranges):
                print(f"\n[{idx+1}/{len(ranges)}] {single_range} をスキャン中...")

                # 複数範囲の場合、各範囲の進捗を反映
                def range_progress_callback(completed_chunks, total_chunks, found_hosts):
                    if progress_callback:
                        # 範囲全体の進捗を計算
                        overall_completed = idx * 100 + int((completed_chunks / total_chunks) * 100)
                        overall_total = len(ranges) * 100
                        progress_callback(overall_completed, overall_total, len(all_results) + found_hosts)

                results = self.scan_ip_range(single_range, progress_callback=range_progress_callback)  # 再帰呼び出し
                all_results.update(results)

            return all_results

        # IP範囲形式を変換（192.168.0.1-50 → 192.168.0.1-192.168.0.50）
        if '-' in target_range and '/' not in target_range and ',' not in target_range:
            parts = target_range.split('-')
            if len(parts) == 2:
                base_ip = parts[0].strip()
                end_num = parts[1].strip()
                # IPアドレスのベース部分を取得（例: 192.168.0）
                ip_parts = base_ip.split('.')
                if len(ip_parts) == 4:
                    base = '.'.join(ip_parts[:3])
                    start_num = ip_parts[3]
                    # nmap形式に変換
                    target_range = f"{base}.{start_num}-{end_num}"

        return self.ping_scan(target_range, progress_callback=progress_callback)

    def scan_all_subnets(self) -> Dict[str, Dict]:
        """
        すべての検出されたサブネットをスキャン

        Returns:
            Dict: 全スキャン結果
        """
        all_results = {}
        subnets = self.detect_subnets()

        for subnet in subnets:
            results = self.ping_scan(subnet)
            all_results.update(results)

        self.scan_results = all_results
        return all_results

    def _run_nmap_with_sudo(self, host: str, arguments: str) -> Dict:
        """
        sudoを使用してnmapコマンドを実行

        Args:
            host: スキャン対象のIPアドレス
            arguments: nmapの引数

        Returns:
            Dict: スキャン結果（XMLパース後）
        """
        import subprocess
        import tempfile
        import xml.etree.ElementTree as ET

        # 一時ファイルにXML出力を保存
        with tempfile.NamedTemporaryFile(mode='w', suffix='.xml', delete=False) as tmp:
            output_file = tmp.name

        try:
            # sudoでnmapを実行（パスワードを標準入力から渡す）
            cmd = ['sudo', '-S', 'nmap', '-oX', output_file] + arguments.split() + [host]

            process = subprocess.Popen(
                cmd,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )

            # sudoパスワードを渡す
            stdout, stderr = process.communicate(input=f"{self.sudo_password}\n", timeout=300)

            if process.returncode != 0:
                if 'incorrect password' in stderr.lower() or 'sorry' in stderr.lower():
                    raise Exception("sudoパスワードが正しくありません")
                print(f"nmap標準出力: {stdout}")
                print(f"nmapエラー出力: {stderr}")

            # XML結果を読み込んでパース
            tree = ET.parse(output_file)
            root = tree.getroot()

            # 結果を辞書形式に変換
            scan_result = {
                'host': host,
                'ports': [],
                'os': ''
            }

            # ホスト情報を取得
            for host_elem in root.findall('host'):
                # ポート情報を取得
                for port_elem in host_elem.findall('.//port'):
                    port_id = port_elem.get('portid')
                    protocol = port_elem.get('protocol')
                    state_elem = port_elem.find('state')
                    service_elem = port_elem.find('service')

                    if state_elem is not None:
                        state = state_elem.get('state')
                        service_name = service_elem.get('name', '') if service_elem is not None else ''
                        product = service_elem.get('product', '') if service_elem is not None else ''
                        version = service_elem.get('version', '') if service_elem is not None else ''

                        scan_result['ports'].append({
                            'port': int(port_id),
                            'protocol': protocol,
                            'state': state,
                            'service': service_name,
                            'product': product,
                            'version': version
                        })

                # OS情報を取得
                osmatch = host_elem.find('.//osmatch')
                if osmatch is not None:
                    scan_result['os'] = osmatch.get('name', '')

            return scan_result

        finally:
            # 一時ファイルを削除
            import os
            if os.path.exists(output_file):
                os.remove(output_file)

    def port_scan(self, host: str, arguments: str = '-sS -sV', priority_only: bool = False, is_range_scan: bool = False, verbose: bool = True) -> Dict:
        """
        指定されたホストに対して詳細ポートスキャンを実行

        Args:
            host: スキャン対象のIPアドレス
            arguments: nmapの引数（デフォルト: '-sS -sV'）
            priority_only: Trueの場合、優先ポートのみスキャン
            is_range_scan: 範囲スキャンの場合True
            verbose: 詳細なログ出力（デフォルト: True）

        Returns:
            Dict: ポートスキャン結果
        """
        result = {
            'host': host,
            'ports': [],
            'os': '',
            'scan_time': '',
            'scan_stage': 'priority' if priority_only else 'full'
        }

        if not self.nmap_available:
            result['error'] = f"nmapが利用できません: {self.nmap_error}"
            print(f"エラー: {result['error']}")
            return result

        # 優先ポートの定義
        priority_ports = [80, 8080, 5000, 5001, 5050, 3000, 3001]

        try:
            import time
            start_time = time.time()

            # verboseモードでのみ詳細を表示
            if verbose:
                print(f"\n{'='*60}")
                print(f"ポートスキャン開始: {host}")

            if priority_only:
                if verbose:
                    print(f"スキャンタイプ: 優先ポート ({','.join(map(str, priority_ports))})")
                # 優先ポートのみスキャン
                ports_str = ','.join(map(str, priority_ports))
                scan_args = f"-p {ports_str} {arguments}"
            elif is_range_scan:
                # 範囲スキャンの場合は引数にすでに-pとタイミングオプションが含まれている
                if verbose:
                    print(f"スキャンタイプ: {arguments}")
                scan_args = arguments
            else:
                if verbose:
                    print(f"スキャンタイプ: {arguments}")
                scan_args = arguments

            if verbose:
                print(f"{'='*60}")

            # root権限が必要なスキャンかチェック
            needs_root = '-sS' in scan_args or '-sU' in scan_args or '-O' in scan_args

            if needs_root and self.sudo_password:
                print(f"[nmap実行] sudo nmap {scan_args} {host}")
                print("sudo権限でnmapを実行中...")
                # sudoでnmapを実行
                sudo_result = self._run_nmap_with_sudo(host, scan_args)
                result['ports'] = sudo_result['ports']
                result['os'] = sudo_result['os']

                # 結果を表示（verboseモードのみ）
                if verbose and result['ports']:
                    print("\n検出されたポート:")
                    for port_info in result['ports']:
                        service = port_info.get('service', 'unknown')
                        version = port_info.get('version', '')
                        product = port_info.get('product', '')
                        version_str = f"{product} {version}".strip() if product or version else ""
                        print(f"  ✓ {port_info['port']}/{port_info['protocol']:3s} - {service:15s} {version_str}")

                if verbose and result['os']:
                    print(f"\nOS検出: {result['os']}")

            else:
                print(f"[nmap実行] nmap {scan_args} {host}")
                print("スキャン中... (ポートとサービスを検出しています)")
                # -sS はroot権限が必要なため、権限がない場合は -sT を使用
                try:
                    self.nm.scan(hosts=host, arguments=scan_args)
                except Exception as e:
                    # SYNスキャンが失敗した場合はTCPコネクトスキャンにフォールバック
                    if '-sS' in scan_args and not self.sudo_password:
                        print(f"⚠ SYNスキャンにはroot権限が必要です。TCPコネクトスキャンに切り替えます")
                        print(f"  ヒント: sudo設定からパスワードを設定すると-sSスキャンが使用できます")
                        scan_args = scan_args.replace('-sS', '-sT')
                        self.nm.scan(hosts=host, arguments=scan_args)
                    else:
                        raise

                if host in self.nm.all_hosts():
                    if verbose:
                        print("\n検出されたポート:")
                    # ポート情報を取得
                    for proto in self.nm[host].all_protocols():
                        ports = self.nm[host][proto].keys()
                        for port in ports:
                            port_info = self.nm[host][proto][port]
                            result['ports'].append({
                                'port': port,
                                'protocol': proto,
                                'state': port_info['state'],
                                'service': port_info.get('name', ''),
                                'version': port_info.get('version', ''),
                                'product': port_info.get('product', '')
                            })

                            # 見つかったポートを表示（verboseモードのみ）
                            if verbose:
                                service = port_info.get('name', 'unknown')
                                version = port_info.get('version', '')
                                product = port_info.get('product', '')
                                version_str = f"{product} {version}".strip() if product or version else ""
                                print(f"  ✓ {port}/{proto:3s} - {service:15s} {version_str}")

                    # OS情報（あれば）
                    if 'osmatch' in self.nm[host]:
                        if len(self.nm[host]['osmatch']) > 0:
                            result['os'] = self.nm[host]['osmatch'][0]['name']
                            print(f"\nOS検出: {result['os']}")

            elapsed_time = time.time() - start_time
            if verbose:
                print(f"\n{'='*60}")
                scan_type_str = "優先" if priority_only else "全"
                print(f"{scan_type_str}ポートスキャン完了: {len(result['ports'])}個のポートを検出")
                print(f"所要時間: {elapsed_time:.1f}秒")
                print(f"{'='*60}\n")

        except Exception as e:
            print(f"\nポートスキャンエラー ({host}): {e}\n")
            result['error'] = str(e)

        return result

    def get_scan_results(self) -> Dict[str, Dict]:
        """
        最後のスキャン結果を取得

        Returns:
            Dict: スキャン結果
        """
        return self.scan_results

    def get_http_info(self, host: str, port: int = 80, use_https: bool = False) -> Dict:
        """
        HTTPサービスの詳細情報を取得

        Args:
            host: 対象ホストのIPアドレス
            port: ポート番号（デフォルト: 80）
            use_https: HTTPSを使用する場合True

        Returns:
            Dict: HTTP詳細情報
        """
        result = {
            'host': host,
            'port': port,
            'protocol': 'https' if use_https else 'http',
            'accessible': False,
            'title': '',
            'server': '',
            'headers': {},
            'security_headers': {},
            'status_code': 0,
            'redirect_url': '',
            'error': ''
        }

        protocol = 'https' if use_https else 'http'
        url = f"{protocol}://{host}:{port}"

        try:
            # タイムアウト3秒でHTTPリクエスト、リダイレクト追従
            response = requests.get(
                url,
                timeout=3,
                allow_redirects=True,
                verify=False  # 自己署名証明書も許可
            )

            result['accessible'] = True
            result['status_code'] = response.status_code

            # リダイレクトされた場合の最終URL
            if response.url != url:
                result['redirect_url'] = response.url

            # HTMLタイトルを抽出
            if 'text/html' in response.headers.get('Content-Type', ''):
                import re
                title_match = re.search(r'<title[^>]*>(.*?)</title>', response.text, re.IGNORECASE | re.DOTALL)
                if title_match:
                    result['title'] = title_match.group(1).strip()[:200]  # 最大200文字

            # サーバー情報
            result['server'] = response.headers.get('Server', '')

            # 主要なヘッダー情報
            important_headers = [
                'Server', 'X-Powered-By', 'Content-Type',
                'Content-Length', 'Last-Modified', 'ETag'
            ]
            for header in important_headers:
                if header in response.headers:
                    result['headers'][header] = response.headers[header]

            # セキュリティヘッダーのチェック
            security_headers = {
                'Strict-Transport-Security': 'HSTS',
                'Content-Security-Policy': 'CSP',
                'X-Frame-Options': 'Clickjacking Protection',
                'X-Content-Type-Options': 'MIME Sniffing Protection',
                'X-XSS-Protection': 'XSS Protection',
                'Referrer-Policy': 'Referrer Policy',
                'Permissions-Policy': 'Permissions Policy'
            }

            for header, description in security_headers.items():
                if header in response.headers:
                    result['security_headers'][header] = {
                        'value': response.headers[header],
                        'description': description,
                        'present': True
                    }
                else:
                    result['security_headers'][header] = {
                        'value': '',
                        'description': description,
                        'present': False
                    }

        except requests.exceptions.SSLError as e:
            # HTTPSで失敗した場合、HTTPを試す
            if use_https:
                result['error'] = f'SSL/TLS error: {str(e)[:100]}'
            else:
                result['error'] = str(e)[:100]
        except requests.exceptions.ConnectionError:
            result['error'] = 'Connection refused or timeout'
        except requests.exceptions.Timeout:
            result['error'] = 'Request timeout (3s)'
        except Exception as e:
            result['error'] = str(e)[:100]

        return result

    def generate_network_topology(self, scan_results: Dict, port_results: Dict) -> Dict:
        """
        ネットワークトポロジーのグラフデータを生成

        Args:
            scan_results: Pingスキャン結果
            port_results: ポートスキャン結果

        Returns:
            Dict: ネットワークトポロジーのグラフデータ（nodes, edges, stats）
        """
        G = nx.Graph()

        # ゲートウェイ（ルーター）を推定 - 通常は .1 か .254
        gateway_candidates = []
        subnets_map = {}

        # サブネット毎にホストを分類
        for ip, info in scan_results.items():
            subnet = info.get('subnet', '192.168.0.0/24')
            if subnet not in subnets_map:
                subnets_map[subnet] = []
            subnets_map[subnet].append(ip)

            # ゲートウェイ候補を特定
            ip_parts = ip.split('.')
            if ip_parts[-1] in ['1', '254']:
                gateway_candidates.append(ip)

        # ノードを追加
        for ip, info in scan_results.items():
            hostname = info.get('hostname', 'Unknown')
            vendor = info.get('vendor', '')
            subnet = info.get('subnet', '')

            # ポート数を取得
            open_ports = []
            if ip in port_results:
                open_ports = [p['port'] for p in port_results[ip].get('ports', [])]

            # ノードタイプを判定
            node_type = 'host'
            if ip in gateway_candidates:
                node_type = 'gateway'
            elif len(open_ports) > 5:
                node_type = 'server'
            elif vendor and any(v in vendor.lower() for v in ['apple', 'samsung', 'huawei', 'xiaomi']):
                node_type = 'mobile'

            G.add_node(ip,
                      label=hostname if hostname != 'Unknown' else ip,
                      hostname=hostname,
                      vendor=vendor,
                      subnet=subnet,
                      type=node_type,
                      ports=len(open_ports),
                      port_list=open_ports[:10])  # 最大10ポートまで表示

        # エッジを追加（同じサブネット内のホストを接続）
        for subnet, hosts in subnets_map.items():
            # ゲートウェイがあれば、全ホストをゲートウェイに接続
            subnet_gateway = None
            for gw in gateway_candidates:
                if gw in hosts:
                    subnet_gateway = gw
                    break

            if subnet_gateway:
                # スター型トポロジー（ゲートウェイ中心）
                for host in hosts:
                    if host != subnet_gateway:
                        G.add_edge(subnet_gateway, host, subnet=subnet)
            else:
                # ゲートウェイがない場合は、メッシュ型で一部接続
                # （見やすさのため、全てを接続しない）
                if len(hosts) <= 5:
                    # ホストが少ない場合は全て接続
                    for i, host1 in enumerate(hosts):
                        for host2 in hosts[i+1:]:
                            G.add_edge(host1, host2, subnet=subnet)
                else:
                    # ホストが多い場合は最初のホストをハブとして使用
                    hub = hosts[0]
                    for host in hosts[1:]:
                        G.add_edge(hub, host, subnet=subnet)

        # グラフデータをJSON形式に変換
        nodes = []
        for node, attrs in G.nodes(data=True):
            nodes.append({
                'id': node,
                'label': attrs.get('label', node),
                'hostname': attrs.get('hostname', ''),
                'vendor': attrs.get('vendor', ''),
                'subnet': attrs.get('subnet', ''),
                'type': attrs.get('type', 'host'),
                'ports': attrs.get('ports', 0),
                'port_list': attrs.get('port_list', [])
            })

        edges = []
        for source, target, attrs in G.edges(data=True):
            edges.append({
                'source': source,
                'target': target,
                'subnet': attrs.get('subnet', '')
            })

        # 統計情報
        stats = {
            'total_hosts': len(G.nodes()),
            'total_connections': len(G.edges()),
            'subnets': len(subnets_map),
            'gateways': len(gateway_candidates),
            'servers': len([n for n, attrs in G.nodes(data=True) if attrs.get('type') == 'server']),
            'mobile_devices': len([n for n, attrs in G.nodes(data=True) if attrs.get('type') == 'mobile'])
        }

        return {
            'nodes': nodes,
            'edges': edges,
            'stats': stats
        }
