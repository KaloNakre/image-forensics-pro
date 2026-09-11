import io
import pytest
from PIL import Image
from fastapi.testclient import TestClient

from main import (
    app, 
    is_in_bangladesh, 
    convert_to_degrees, 
    detect_c2pa_ai, 
    detect_copy_move, 
    inspect_timestamp_gps_anomalies, 
    scan_steganography_lsb
)

client = TestClient(app)

def create_test_image_bytes(width=150, height=150, color=(255, 0, 0)) -> bytes:
    """Helper to generate a PNG/JPEG image in memory for testing."""
    img = Image.new("RGB", (width, height), color=color)
    buf = io.BytesIO()
    img.save(buf, format="JPEG")
    return buf.getvalue()

def test_health_check():
    response = client.get("/api/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "online"
    assert "forensics_modules" in data
    assert len(data["forensics_modules"]) >= 6

def test_bangladesh_geofencing():
    # Dhaka coordinates (Inside BD)
    assert is_in_bangladesh(23.8103, 90.4125) is True
    # Chittagong coordinates (Inside BD)
    assert is_in_bangladesh(22.3569, 91.7832) is True
    # New York coordinates (Outside BD)
    assert is_in_bangladesh(40.7128, -74.0060) is False
    # Null Island (Outside BD)
    assert is_in_bangladesh(0.0, 0.0) is False

def test_convert_to_degrees():
    assert convert_to_degrees(None) is None
    assert convert_to_degrees("invalid") is None
    assert convert_to_degrees([]) is None
    assert round(convert_to_degrees(((23, 1), (48, 1), (37, 1))), 2) == 23.81
    assert round(convert_to_degrees((23, 48, 37.08)), 2) == 23.81

def test_detect_c2pa_ai():
    img_bytes = create_test_image_bytes()
    exif_data = {
        "summary": {"software": "Adobe Firefly DALL-E"},
        "raw_tags": {}
    }
    res = detect_c2pa_ai(img_bytes, exif_data)
    assert res["is_ai_generated"] is True
    assert res["confidence"] == "HIGH"
    assert "firefly" in res["ai_generator_name"].lower() or "dall-e" in res["ai_generator_name"].lower()

def test_detect_copy_move():
    img_bytes = create_test_image_bytes()
    res = detect_copy_move(img_bytes)
    assert res["status"] == "success"
    assert "forgery_detected" in res
    assert "forgery_score" in res

def test_inspect_timestamp_gps_anomalies():
    # Test Future Date Anomaly
    exif_data_future = {
        "summary": {
            "datetime": "2099:01:01 12:00:00",
            "gps_lat": 23.8103,
            "gps_lon": 90.4125
        }
    }
    res_future = inspect_timestamp_gps_anomalies(exif_data_future)
    assert res_future["anomalies_detected"] is True
    assert any(a["type"] == "FUTURE_TIMESTAMP" for a in res_future["flags"])

    # Test Null Island Anomaly
    exif_data_null = {
        "summary": {
            "datetime": "2023:05:10 10:00:00",
            "gps_lat": 0.0,
            "gps_lon": 0.0
        }
    }
    res_null = inspect_timestamp_gps_anomalies(exif_data_null)
    assert res_null["anomalies_detected"] is True
    assert any(a["type"] == "NULL_ISLAND_COORDINATE" for a in res_null["flags"])

def test_scan_steganography_lsb():
    img_bytes = create_test_image_bytes()
    res = scan_steganography_lsb(img_bytes)
    assert res["status"] == "success"
    assert "stego_suspected" in res
    assert "lsb_entropy" in res

def test_analyze_image_endpoint():
    img_bytes = create_test_image_bytes()
    response = client.post(
        "/api/analyze",
        files={"file": ("test.jpg", img_bytes, "image/jpeg")},
        data={"keywords": "test_target"}
    )
    assert response.status_code == 200
    data = response.json()
    assert data["filename"] == "test.jpg"
    assert data["size_bytes"] > 0
    assert "image_info" in data
    assert "exif" in data
    assert "ela" in data
    assert "c2pa_ai" in data
    assert "copy_move" in data
    assert "anomalies" in data
    assert "steganography" in data
    assert "location" in data

def test_ela_endpoint():
    img_bytes = create_test_image_bytes()
    response = client.post(
        "/api/ela?quality=90",
        files={"file": ("test.jpg", img_bytes, "image/jpeg")}
    )
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "success"
    assert "ela_image_b64" in data
    assert data["quality_level"] == 90

def test_agent_chat_endpoint():
    req_data = {
        "message": "Give me a forensic verdict for this image",
        "model": "claude-3-5-sonnet",
        "image_context": {
            "c2pa_ai": {"is_ai_generated": True, "ai_generator_name": "Midjourney v6"},
            "copy_move": {"forgery_detected": False},
            "anomalies": {"anomaly_count": 0, "flags": []},
            "steganography": {"stego_suspected": False, "lsb_entropy": 0.52}
        }
    }
    response = client.post("/api/agent/chat", json=req_data)
    assert response.status_code == 200
    data = response.json()
    assert data["model"] == "claude-3-5-sonnet"
    assert "Forensic" in data["reply"]
    assert "Midjourney" in data["reply"]

def test_dashboard_html_endpoint():
    response = client.get("/")
    assert response.status_code == 200
    assert "OSINT Vision Pro" in response.text
