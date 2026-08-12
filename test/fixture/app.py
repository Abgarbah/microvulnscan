import time

from flask import Flask, jsonify


app = Flask(__name__)


def _add_security_headers(response):
    response.headers.update({
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Content-Security-Policy": "default-src 'self'",
        "Strict-Transport-Security": "max-age=31536000",
        "Referrer-Policy": "no-referrer",
    })
    return response


@app.get("/ok")
def ok():
    """A valid endpoint with no deliberate vulnerability response."""
    return _add_security_headers(jsonify(endpoint="ok", message="success")), 200


@app.get("/not-found")
def not_found():
    return jsonify(error="endpoint not found"), 404


@app.get("/unauthorized")
def unauthorized():
    return jsonify(error="authentication required"), 401


@app.get("/forbidden")
def forbidden():
    return jsonify(error="access forbidden"), 403


@app.post("/method-not-allowed")
def method_not_allowed():
    """GET is intentionally unsupported, so Flask returns 405."""
    return jsonify(message="POST is supported"), 200


@app.get("/server-error")
def server_error():
    return jsonify(error="controlled internal server error"), 500


@app.get("/timeout")
def timeout():
    """Long enough to exceed the scanner's normal request timeout."""
    time.sleep(15)
    return jsonify(message="delayed response"), 200


@app.get("/missing-security-headers")
def missing_security_headers():
    """A valid 200 endpoint that deliberately omits security headers."""
    response = jsonify(endpoint="missing-security-headers", message="security headers omitted")
    response.headers.pop("Content-Security-Policy", None)
    response.headers.pop("Strict-Transport-Security", None)
    response.headers.pop("Referrer-Policy", None)
    response.headers.pop("X-Frame-Options", None)
    response.headers.pop("X-Content-Type-Options", None)
    return response, 200


if __name__ == "__main__":
    # Listen on the local network interface so VulnMicroScan's self-target
    # protection can distinguish this fixture from the scanner app itself.
    app.run(host="0.0.0.0", port=5055, debug=False)
