#!/usr/bin/env python3
"""
スキャン履歴管理モジュール
"""

import json
import os
from datetime import datetime
from typing import List, Dict, Optional


class HistoryManager:
    """スキャン履歴を管理するクラス"""

    def __init__(self, history_file: str = 'scan_history.json'):
        """
        履歴マネージャーの初期化

        Args:
            history_file: 履歴を保存するファイルパス
        """
        self.history_file = history_file
        self.max_history = 50  # 最大保存件数

    def load_history(self) -> List[Dict]:
        """
        スキャン履歴を読み込む

        Returns:
            List[Dict]: スキャン履歴のリスト
        """
        try:
            if os.path.exists(self.history_file):
                with open(self.history_file, 'r', encoding='utf-8') as f:
                    return json.load(f)
        except Exception as e:
            print(f"履歴読み込みエラー: {e}")
        return []

    def save_history(self, history: List[Dict]) -> bool:
        """
        スキャン履歴を保存する

        Args:
            history: 保存する履歴のリスト

        Returns:
            bool: 保存成功時True
        """
        try:
            with open(self.history_file, 'w', encoding='utf-8') as f:
                json.dump(history, f, ensure_ascii=False, indent=2)
            return True
        except Exception as e:
            print(f"履歴保存エラー: {e}")
            return False

    def add_scan_record(self, target: str, hosts: Dict) -> Dict:
        """
        新しいスキャン記録を追加

        Args:
            target: スキャン対象（例: "192.168.1.0/24" または "auto-detect"）
            hosts: スキャン結果のホスト情報

        Returns:
            Dict: 追加されたスキャン記録
        """
        history = self.load_history()

        # 新しいスキャン記録を作成
        scan_record = {
            'id': int(datetime.now().timestamp() * 1000),  # ユニークなID
            'timestamp': datetime.now().isoformat(),
            'target': target,
            'host_count': len(hosts),
            'hosts': hosts
        }

        # 履歴の先頭に追加（最新が最初）
        history.insert(0, scan_record)

        # 最大件数を超えた場合は古いものを削除
        if len(history) > self.max_history:
            history = history[:self.max_history]

        # 保存
        self.save_history(history)

        return scan_record

    def get_scan_by_id(self, scan_id: int) -> Optional[Dict]:
        """
        IDで特定のスキャン記録を取得

        Args:
            scan_id: スキャンID

        Returns:
            Optional[Dict]: スキャン記録、見つからない場合はNone
        """
        history = self.load_history()
        for scan in history:
            if scan['id'] == scan_id:
                return scan
        return None

    def delete_scan(self, scan_id: int) -> bool:
        """
        特定のスキャン記録を削除

        Args:
            scan_id: 削除するスキャンID

        Returns:
            bool: 削除成功時True
        """
        history = self.load_history()
        original_length = len(history)

        # 指定IDのスキャンを除外
        history = [scan for scan in history if scan['id'] != scan_id]

        # 削除されたかチェック
        if len(history) < original_length:
            self.save_history(history)
            return True

        return False

    def clear_all_history(self) -> bool:
        """
        全ての履歴を削除

        Returns:
            bool: 削除成功時True
        """
        try:
            self.save_history([])
            return True
        except Exception as e:
            print(f"履歴クリアエラー: {e}")
            return False

    def get_history_summary(self) -> Dict:
        """
        履歴の統計情報を取得

        Returns:
            Dict: 統計情報（件数、最新スキャン日時など）
        """
        history = self.load_history()

        if not history:
            return {
                'total_scans': 0,
                'total_hosts': 0,
                'latest_scan': None
            }

        total_hosts = sum(scan['host_count'] for scan in history)
        latest_scan = history[0] if history else None

        return {
            'total_scans': len(history),
            'total_hosts': total_hosts,
            'latest_scan': latest_scan['timestamp'] if latest_scan else None
        }