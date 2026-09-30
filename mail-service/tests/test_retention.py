def test_parse_message_ttl_days_can_disable_cleanup():
    from app import _parse_message_ttl_days

    assert _parse_message_ttl_days("0") is None
    assert _parse_message_ttl_days("forever") is None
    assert _parse_message_ttl_days("7") == 7


def test_init_db_drops_ttl_index_when_cleanup_disabled(mock_mongo, monkeypatch):
    import app

    # Default is now "keep mail forever" (a real mailbox), so enable expiry first.
    monkeypatch.setattr(app, "MESSAGE_TTL_DAYS", 3)
    app.init_db()
    assert "ttl_cleanup" in mock_mongo.messages.index_information()

    monkeypatch.setattr(app, "MESSAGE_TTL_DAYS", None)
    app.init_db()

    assert "ttl_cleanup" not in mock_mongo.messages.index_information()


def test_init_db_recreates_ttl_index_when_retention_changes(mock_mongo, monkeypatch):
    import app

    monkeypatch.setattr(app, "MESSAGE_TTL_DAYS", 7)
    app.init_db()

    ttl_index = mock_mongo.messages.index_information()["ttl_cleanup"]
    assert ttl_index["expireAfterSeconds"] == 7 * 86400
