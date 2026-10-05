"""OpenAPI 3.0 description of the REST API.

Hand-written rather than generated: the API surface is small and the
spec doubles as human documentation at /docs. Kept in one dict so it
stays greppable and testable; served as JSON from /api/v1/openapi.json
and rendered at /docs.
"""

API_SPEC = {
    "openapi": "3.0.3",
    "info": {
        "title": "Watchtail REST API",
        "version": "1.0.0",
        "description": (
            "Machine access to Watchtail's detections: flagged IPs, "
            "alerts, statistics and review actions. Authenticate with a "
            "bearer token (created on the tokens page) or the dashboard "
            "session. Write endpoints need a token with can_write."
        ),
    },
    "servers": [{"url": "/api/v1"}],
    "components": {
        "securitySchemes": {
            "bearerAuth": {"type": "http", "scheme": "bearer"},
        },
        "schemas": {
            "IpStatus": {
                "type": "object",
                "properties": {
                    "ip": {"type": "string"},
                    "status": {"type": "string", "enum": ["flagged", "reviewed", "dismissed"]},
                    "alert_count": {"type": "integer"},
                    "reason": {"type": "string", "nullable": True},
                    "threat_score": {"type": "integer"},
                    "score_level": {"type": "string"},
                    "tags": {"type": "array", "items": {"type": "string"}},
                    "operator_note": {"type": "string", "nullable": True},
                    "geo": {"type": "object", "nullable": True},
                    "first_seen_at": {"type": "string", "nullable": True},
                    "last_alert_at": {"type": "string", "nullable": True},
                },
            },
            "Alert": {
                "type": "object",
                "properties": {
                    "id": {"type": "integer"},
                    "ts": {"type": "string", "format": "date-time"},
                    "detector": {"type": "string"},
                    "ip": {"type": "string"},
                    "severity": {"type": "string", "enum": ["low", "medium", "high", "critical"]},
                    "message": {"type": "string"},
                    "meta": {"type": "object"},
                    "mitre": {"type": "object", "nullable": True},
                },
            },
            "Stats": {
                "type": "object",
                "properties": {
                    "events_24h": {"type": "integer"},
                    "alerts_24h": {"type": "integer"},
                    "flagged_now": {"type": "integer"},
                },
            },
            "Error": {
                "type": "object",
                "properties": {"error": {"type": "string"}},
            },
        },
    },
    "paths": {
        "/ips": {
            "get": {
                "summary": "List currently flagged IPs",
                "security": [{"bearerAuth": []}],
                "responses": {
                    "200": {
                        "description": "Flagged IP rows in review order",
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "array",
                                    "items": {"$ref": "#/components/schemas/IpStatus"},
                                }
                            }
                        },
                    }
                },
            }
        },
        "/ips/risky": {
            "get": {
                "summary": "Highest-scoring IPs",
                "security": [{"bearerAuth": []}],
                "responses": {
                    "200": {
                        "description": "Top risky IPs by decayed score",
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "array",
                                    "items": {"$ref": "#/components/schemas/IpStatus"},
                                }
                            }
                        },
                    }
                },
            }
        },
        "/ips/{ip}": {
            "get": {
                "summary": "One IP with recent alerts and events",
                "security": [{"bearerAuth": []}],
                "parameters": [
                    {"name": "ip", "in": "path", "required": True, "schema": {"type": "string"}}
                ],
                "responses": {
                    "200": {
                        "description": "IP status with nested alert/event lists",
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/IpStatus"}
                            }
                        },
                    },
                    "404": {
                        "description": "Unknown IP",
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/Error"}
                            }
                        },
                    },
                },
            }
        },
        "/ips/{ip}/status": {
            "post": {
                "summary": "Review or dismiss an IP (write token required)",
                "security": [{"bearerAuth": []}],
                "parameters": [
                    {"name": "ip", "in": "path", "required": True, "schema": {"type": "string"}}
                ],
                "requestBody": {
                    "required": True,
                    "content": {
                        "application/json": {
                            "schema": {
                                "type": "object",
                                "required": ["action"],
                                "properties": {
                                    "action": {
                                        "type": "string",
                                        "enum": ["reviewed", "dismissed"],
                                    }
                                },
                            }
                        }
                    },
                },
                "responses": {
                    "200": {"description": "Updated status"},
                    "400": {"description": "Invalid action"},
                    "404": {"description": "Unknown IP"},
                },
            }
        },
        "/ips/{ip}/annotate": {
            "post": {
                "summary": "Set operator note and tags (write token required)",
                "security": [{"bearerAuth": []}],
                "parameters": [
                    {"name": "ip", "in": "path", "required": True, "schema": {"type": "string"}}
                ],
                "requestBody": {
                    "required": True,
                    "content": {
                        "application/json": {
                            "schema": {
                                "type": "object",
                                "properties": {
                                    "note": {"type": "string"},
                                    "tags": {
                                        "type": "array",
                                        "items": {"type": "string"},
                                    },
                                },
                            }
                        }
                    },
                },
                "responses": {
                    "200": {"description": "Saved annotation"},
                    "404": {"description": "Unknown IP"},
                },
            }
        },
        "/alerts": {
            "get": {
                "summary": "List recent alerts",
                "security": [{"bearerAuth": []}],
                "parameters": [
                    {
                        "name": "limit",
                        "in": "query",
                        "schema": {"type": "integer", "maximum": 500, "default": 50},
                    },
                    {
                        "name": "severity",
                        "in": "query",
                        "schema": {
                            "type": "string",
                            "enum": ["low", "medium", "high", "critical"],
                        },
                    },
                ],
                "responses": {
                    "200": {
                        "description": "Newest alerts first",
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "array",
                                    "items": {"$ref": "#/components/schemas/Alert"},
                                }
                            }
                        },
                    }
                },
            }
        },
        "/stats": {
            "get": {
                "summary": "24h counters",
                "security": [{"bearerAuth": []}],
                "responses": {
                    "200": {
                        "description": "Events/alerts in the last 24h and flagged count",
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/Stats"}
                            }
                        },
                    }
                },
            }
        },
        "/tokens": {
            "post": {
                "summary": "Mint an API token (write token required)",
                "security": [{"bearerAuth": []}],
                "requestBody": {
                    "required": True,
                    "content": {
                        "application/json": {
                            "schema": {
                                "type": "object",
                                "properties": {
                                    "name": {"type": "string"},
                                    "can_write": {"type": "boolean", "default": False},
                                },
                            }
                        }
                    },
                },
                "responses": {
                    "201": {
                        "description": "Token created; the plain value is shown once",
                    }
                },
            }
        },
    },
}
