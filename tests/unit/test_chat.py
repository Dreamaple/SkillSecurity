"""Tests for the ChatDetector — chat/conversation history detection."""

from __future__ import annotations

import pytest

from skillsecurity.privacy.chat import ChatDetector


@pytest.fixture
def detector() -> ChatDetector:
    return ChatDetector()


class TestChatDetectorStructure:
    """Tests for structural chat data patterns in payloads."""

    def test_detect_openai_message_format(self, detector: ChatDetector) -> None:
        text = '{"messages": [{"role": "user", "content": "Hello"}, {"role": "assistant", "content": "Hi there"}]}'
        matches = detector.scan(text)
        assert len(matches) >= 1
        ids = {m.pattern_id for m in matches}
        assert "chat-messages-array" in ids or "chat-messages-role-content" in ids

    def test_detect_messages_array_key(self, detector: ChatDetector) -> None:
        text = '{"model": "gpt-4", "messages": [{"role": "system", "content": "You are helpful"}]}'
        matches = detector.scan(text)
        assert any(m.pattern_id == "chat-messages-array" for m in matches)

    def test_detect_role_content_pair(self, detector: ChatDetector) -> None:
        text = '"role": "user", "content": "What is the weather?"'
        matches = detector.scan(text)
        assert any(m.pattern_id == "chat-messages-role-content" for m in matches)

    def test_detect_sender_text_format(self, detector: ChatDetector) -> None:
        text = '{"sender": "Alice", "text": "How are you?"}'
        matches = detector.scan(text)
        assert any(m.pattern_id == "chat-sender-text" for m in matches)

    def test_detect_author_message_format(self, detector: ChatDetector) -> None:
        text = '{"author": "Bob", "message": "I am fine!"}'
        matches = detector.scan(text)
        assert any(m.pattern_id == "chat-sender-text" for m in matches)

    def test_detect_timestamped_chat_log(self, detector: ChatDetector) -> None:
        text = "[2026-03-11 10:00:00] User: Hello\n[2026-03-11 10:00:05] Assistant: Hi!"
        matches = detector.scan(text)
        assert any(m.pattern_id == "chat-log-timestamped" for m in matches)

    def test_detect_conversation_export(self, detector: ChatDetector) -> None:
        text = '{"conversation_id": "abc-123", "messages": [{"role": "user", "content": "test"}]}'
        matches = detector.scan(text)
        ids = {m.pattern_id for m in matches}
        assert "chat-conversation-export" in ids or "chat-messages-array" in ids

    def test_no_match_normal_text(self, detector: ChatDetector) -> None:
        text = "This is a normal paragraph with no chat data."
        matches = detector.scan(text)
        assert len(matches) == 0

    def test_no_match_simple_json(self, detector: ChatDetector) -> None:
        text = '{"name": "test", "value": 42, "items": ["a", "b"]}'
        matches = detector.scan(text)
        assert len(matches) == 0

    def test_bulk_escalates_severity(self, detector: ChatDetector) -> None:
        msgs = ", ".join(
            f'{{"role": "user", "content": "msg {i}"}}'
            for i in range(10)
        )
        text = f'{{"messages": [{msgs}]}}'
        matches = detector.scan(text)
        assert any(m.severity == "critical" for m in matches)

    def test_message_count_tracked(self, detector: ChatDetector) -> None:
        msgs = ", ".join(
            f'{{"role": "user", "content": "msg {i}"}}'
            for i in range(7)
        )
        text = f'{{"messages": [{msgs}]}}'
        matches = detector.scan(text)
        assert any(m.message_count >= 7 for m in matches)


class TestChatDetectorFilePaths:
    """Tests for chat-related file path detection."""

    def test_detect_chat_history_json(self, detector: ChatDetector) -> None:
        matches = detector.scan_path("/home/user/data/chat_history.json")
        assert len(matches) >= 1
        assert any(m.pattern_id == "chat-history-file" for m in matches)

    def test_detect_conversations_db(self, detector: ChatDetector) -> None:
        matches = detector.scan_path("/data/conversations.db")
        assert len(matches) >= 1

    def test_detect_chat_log_txt(self, detector: ChatDetector) -> None:
        matches = detector.scan_path("chat_log.txt")
        assert len(matches) >= 1

    def test_detect_chat_export(self, detector: ChatDetector) -> None:
        matches = detector.scan_path("/tmp/chat_export.jsonl")
        assert len(matches) >= 1

    def test_detect_chathistory_dot_dir(self, detector: ChatDetector) -> None:
        matches = detector.scan_path("/home/user/.chathistory/session.json")
        assert len(matches) >= 1

    def test_detect_telegram_data(self, detector: ChatDetector) -> None:
        matches = detector.scan_path("/home/user/.telegram/data")
        assert any(m.pattern_id == "chat-app-data-dir" for m in matches)

    def test_detect_whatsapp_data(self, detector: ChatDetector) -> None:
        matches = detector.scan_path("/home/user/.whatsapp/chats")
        assert any(m.pattern_id == "chat-app-data-dir" for m in matches)

    def test_detect_signal_data(self, detector: ChatDetector) -> None:
        matches = detector.scan_path("/home/user/.signal/db")
        assert any(m.pattern_id == "chat-app-data-dir" for m in matches)

    def test_detect_slack_data(self, detector: ChatDetector) -> None:
        matches = detector.scan_path("/home/user/.slack/local-storage")
        assert any(m.pattern_id == "chat-app-data-dir" for m in matches)

    def test_detect_discord_data(self, detector: ChatDetector) -> None:
        matches = detector.scan_path("/home/user/.discord/Cache")
        assert any(m.pattern_id == "chat-app-data-dir" for m in matches)

    def test_detect_macos_messages(self, detector: ChatDetector) -> None:
        matches = detector.scan_path("/Users/alice/Library/Messages/chat.db")
        assert any(m.pattern_id == "chat-app-data-dir" for m in matches)

    def test_detect_windows_telegram(self, detector: ChatDetector) -> None:
        matches = detector.scan_path("C:\\Users\\Alice\\AppData\\Roaming\\Telegram Desktop\\data")
        assert any(m.pattern_id == "chat-app-data-dir" for m in matches)

    def test_no_match_normal_file(self, detector: ChatDetector) -> None:
        matches = detector.scan_path("/home/user/documents/report.pdf")
        assert len(matches) == 0

    def test_no_match_code_file(self, detector: ChatDetector) -> None:
        matches = detector.scan_path("/project/src/main.py")
        assert len(matches) == 0


class TestChatDetectorConfig:
    """Tests for ChatDetector configuration."""

    def test_custom_bulk_threshold(self) -> None:
        detector = ChatDetector(bulk_threshold=3)
        msgs = ", ".join(
            f'{{"role": "user", "content": "msg {i}"}}'
            for i in range(4)
        )
        text = f'{{"messages": [{msgs}]}}'
        matches = detector.scan(text)
        assert any(m.severity == "critical" for m in matches)

    def test_below_bulk_threshold_not_critical(self) -> None:
        detector = ChatDetector(bulk_threshold=20)
        msgs = ", ".join(
            f'{{"role": "user", "content": "msg {i}"}}'
            for i in range(3)
        )
        text = f'{{"messages": [{msgs}]}}'
        matches = detector.scan(text)
        assert not any(m.severity == "critical" for m in matches)

    def test_redacted_value_short(self, detector: ChatDetector) -> None:
        text = '"role": "user", "content": "Hi"'
        matches = detector.scan(text)
        for m in matches:
            assert "****" not in m.redacted_value or len(m.matched_value) > 20
