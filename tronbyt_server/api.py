import base64
import json
import time
from http import HTTPStatus
from pathlib import Path
from typing import Any, Dict, Optional

from flask import (
    Blueprint,
    Response,
    abort,
    current_app,
    request,
)
from flask.typing import ResponseReturnValue
from werkzeug.datastructures import Headers
from werkzeug.utils import secure_filename

import tronbyt_server.db as db
from tronbyt_server import call_handler
from tronbyt_server.manager import push_new_image, render_app
from tronbyt_server.models.app import App
from tronbyt_server.models.device import Device, validate_device_id

bp = Blueprint("api", __name__, url_prefix="/v0")


def get_api_key_from_headers(headers: Headers) -> Optional[str]:
    auth_header = headers.get("Authorization")
    if auth_header:
        if auth_header.startswith("Bearer "):
            return auth_header.split(" ")[1]
        else:
            return auth_header
    return None


def require_api_key() -> str:
    """
    Extract and validate API key from request headers.
    Returns the API key if valid, otherwise aborts with 400.
    """
    api_key = get_api_key_from_headers(request.headers)
    if not api_key:
        abort(
            HTTPStatus.BAD_REQUEST,
            description="Missing or invalid Authorization header",
        )
    return api_key


def get_authenticated_user(api_key: str) -> Dict[str, Any]:
    """
    Get user by API key.
    Returns the user if found, otherwise aborts with 401.
    """
    user = db.get_user_by_api_key(api_key)
    if not user:
        abort(HTTPStatus.UNAUTHORIZED, description="Invalid API key")
    return user


def validate_and_get_device(device_id: str) -> None:
    """
    Validate device ID format.
    Aborts with 400 if invalid.
    """
    if not validate_device_id(device_id):
        abort(HTTPStatus.BAD_REQUEST, description="Invalid device ID")


def get_device_and_user(device_id: str, api_key: str) -> tuple[Device, Dict[str, Any]]:
    """
    Authenticate and get device and user.
    Returns (device, user) tuple if successful, otherwise aborts.
    """
    device = authenticate_device_access(device_id, api_key)
    if not device:
        abort(HTTPStatus.NOT_FOUND, description="Device not found or unauthorized")
    
    user = db.get_user_by_device_id(device_id)
    if not user:
        abort(HTTPStatus.NOT_FOUND, description="User not found")
    
    return device, user


def get_user_device(user: Dict[str, Any], device_id: str) -> Device:
    """
    Get device from user's devices.
    Returns device if found, otherwise aborts with 404.
    """
    device = user.get("devices", {}).get(device_id)
    if not device:
        abort(HTTPStatus.NOT_FOUND, description="Device not found")
    return device


def get_app_installation(user: Dict[str, Any], device_id: str, installation_id: str) -> App:
    """
    Get app installation from device.
    Returns app if found, otherwise aborts with 404.
    """
    app = user["devices"][device_id].get("apps", {}).get(installation_id)
    if not app:
        abort(HTTPStatus.NOT_FOUND, description="App installation not found")
    return app


def get_app_by_id_or_name(username: str, app_id: str) -> Dict[str, Any]:
    """
    Get app details by ID or name.
    Returns app details if found, otherwise aborts with 404.
    """
    app_details = db.get_app_details_by_id(username, app_id)
    if not app_details:
        app_details = db.get_app_details_by_name(username, app_id)
    
    if not app_details:
        abort(HTTPStatus.NOT_FOUND, description="App not found")
    
    return app_details


def get_request_json_or_abort() -> Dict[str, Any]:
    """
    Get JSON data from request.
    Returns parsed JSON if valid, otherwise aborts with 400.
    """
    data = request.get_json()
    if not data:
        abort(HTTPStatus.BAD_REQUEST, description="Invalid JSON data")
    return data


def authenticate_device_access(device_id: str, api_key: str) -> Optional[Device]:
    """
    Authenticate access to a device using either device API key or user API key.
    Returns the device if authentication succeeds, None otherwise.
    """
    device = db.get_device_by_id(device_id)
    if not device:
        current_app.logger.debug(f"Device not found: {device_id}")
        return None
    
    # Check if it's the device's own API key
    if device.get("api_key") and device["api_key"] == api_key:
        current_app.logger.debug(f"Authenticated with device API key for device: {device_id}")
        return device
    
    # Check if it's the user's API key
    user = db.get_user_by_device_id(device_id)
    if user and user.get("api_key") and user["api_key"] == api_key:
        current_app.logger.debug(f"Authenticated with user API key for device: {device_id}")
        return device
    
    current_app.logger.debug(f"Authentication failed for device: {device_id}")
    return None


def get_device_payload(device: Device) -> dict[str, Any]:
    return {
        "id": device["id"],
        "displayName": device["name"],
        "brightness": db.get_device_brightness_8bit(device),
        "autoDim": device.get("night_mode_enabled", False),
    }


@bp.route("/devices", methods=["GET"])
def list_devices() -> ResponseReturnValue:
    api_key = require_api_key()
    user = get_authenticated_user(api_key)

    devices = user.get("devices", {})
    metadata = [get_device_payload(device) for device in devices.values()]
    return Response(
        json.dumps({"devices": metadata}),
        status=200,
        mimetype="application/json",
    )


@bp.route("/devices/<string:device_id>", methods=["GET", "PATCH"])
def get_device(device_id: str) -> ResponseReturnValue:
    validate_and_get_device(device_id)
    api_key = require_api_key()
    
    user = db.get_user_by_device_id(device_id)
    if not user:
        abort(HTTPStatus.NOT_FOUND)
    
    device = get_user_device(user, device_id)

    user_api_key_matches = user.get("api_key") and user["api_key"] == api_key
    device_api_key_matches = device.get("api_key") and device["api_key"] == api_key
    if not user_api_key_matches and not device_api_key_matches:
        abort(HTTPStatus.NOT_FOUND)

    if request.method == "PATCH":
        data = request.get_json()
        if "brightness" in data:
            brightness = int(data["brightness"])
            if brightness < 0 or brightness > 255:
                abort(
                    HTTPStatus.BAD_REQUEST,
                    description="Brightness must be between 0 and 255",
                )
            # Store only the percentage value
            device["brightness"] = brightness
        if "autoDim" in data:
            device["night_mode_enabled"] = bool(data["autoDim"])
        db.save_user(user)
    metadata = get_device_payload(device)
    return Response(json.dumps(metadata), status=200, mimetype="application/json")


@bp.route("/devices", methods=["POST"])
def create_device() -> ResponseReturnValue:
    """Create a new device"""
    api_key = require_api_key()
    user = get_authenticated_user(api_key)
    data = get_request_json_or_abort()

    name = data.get("name")
    if not name:
        abort(HTTPStatus.BAD_REQUEST, description="Device name is required")

    # Check if device with this name already exists for user
    if db.get_device_by_name(user, name):
        abort(HTTPStatus.CONFLICT, description="Device with this name already exists")

    # Generate unique device ID
    import uuid
    max_attempts = 10
    for _ in range(max_attempts):
        device_id = str(uuid.uuid4())[0:8]
        if device_id not in user.get("devices", {}):
            break
    else:
        abort(HTTPStatus.INTERNAL_SERVER_ERROR, description="Could not generate unique device ID")

    # Generate API key for device if not provided
    device_api_key = data.get("api_key")
    if not device_api_key:
        import secrets
        import string
        device_api_key = "".join(
            secrets.choice(string.ascii_letters + string.digits) for _ in range(32)
        )

    # Create device with provided data
    from tronbyt_server.models.device import Device, DEFAULT_DEVICE_TYPE, validate_device_type
    
    device_type = data.get("type", DEFAULT_DEVICE_TYPE)
    if not validate_device_type(device_type):
        abort(HTTPStatus.BAD_REQUEST, description="Invalid device type")

    device = Device(
        id=device_id,
        name=name,
        type=device_type,
        api_key=device_api_key,
        brightness=data.get("brightness", 50),  # Default 50%
        default_interval=data.get("default_interval", 10),
    )

    # Optional fields
    if data.get("notes"):
        device["notes"] = data["notes"]
    if data.get("img_url"):
        device["img_url"] = data["img_url"]
    else:
        from tronbyt_server.manager import server_root
        device["img_url"] = f"{server_root()}/{device_id}/next"

    # Save device
    user.setdefault("devices", {})[device_id] = device
    if db.save_user(user):
        # Create device directory
        device_dir = db.get_device_webp_dir(device_id)
        if not device_dir.is_dir():
            device_dir.mkdir(parents=True)
        
        metadata = get_device_payload(device)
        metadata["api_key"] = device_api_key  # Include API key in creation response
        return Response(
            json.dumps(metadata),
            status=201,
            mimetype="application/json"
        )
    else:
        abort(HTTPStatus.INTERNAL_SERVER_ERROR, description="Failed to save device")


@bp.route("/devices/<string:device_id>", methods=["PUT"])
def update_device(device_id: str) -> ResponseReturnValue:
    """Update an existing device"""
    validate_and_get_device(device_id)
    api_key = require_api_key()
    
    user = db.get_user_by_device_id(device_id)
    if not user:
        abort(HTTPStatus.NOT_FOUND, description="Device not found")
    
    device = get_user_device(user, device_id)

    # Check authorization (user API key or device API key)
    user_api_key_matches = user.get("api_key") and user["api_key"] == api_key
    device_api_key_matches = device.get("api_key") and device["api_key"] == api_key
    if not user_api_key_matches and not device_api_key_matches:
        abort(HTTPStatus.FORBIDDEN, description="Unauthorized")

    data = get_request_json_or_abort()

    # Update device fields
    from tronbyt_server.models.device import validate_device_type
    
    if "name" in data:
        # Check if another device has this name
        existing_device = db.get_device_by_name(user, data["name"])
        if existing_device and existing_device.get("id") != device_id:
            abort(HTTPStatus.CONFLICT, description="Device with this name already exists")
        device["name"] = data["name"]
    
    if "type" in data:
        if not validate_device_type(data["type"]):
            abort(HTTPStatus.BAD_REQUEST, description="Invalid device type")
        device["type"] = data["type"]
    
    if "brightness" in data:
        brightness = int(data["brightness"])
        if brightness < 0 or brightness > 100:
            abort(HTTPStatus.BAD_REQUEST, description="Brightness must be between 0 and 100")
        device["brightness"] = brightness
    
    if "default_interval" in data:
        interval = int(data["default_interval"])
        if interval < 1:
            abort(HTTPStatus.BAD_REQUEST, description="Default interval must be at least 1")
        device["default_interval"] = interval
    
    if "notes" in data:
        device["notes"] = data["notes"]
    
    if "img_url" in data:
        device["img_url"] = data["img_url"]
    
    if "night_mode_enabled" in data:
        device["night_mode_enabled"] = bool(data["night_mode_enabled"])
    
    if "night_brightness" in data:
        night_brightness = int(data["night_brightness"])
        if night_brightness < 0 or night_brightness > 100:
            abort(HTTPStatus.BAD_REQUEST, description="Night brightness must be between 0 and 100")
        device["night_brightness"] = night_brightness
    
    if "night_start" in data:
        device["night_start"] = int(data["night_start"])
    
    if "night_end" in data:
        device["night_end"] = int(data["night_end"])

    # Save updated device
    if db.save_user(user):
        metadata = get_device_payload(device)
        return Response(
            json.dumps(metadata),
            status=200,
            mimetype="application/json"
        )
    else:
        abort(HTTPStatus.INTERNAL_SERVER_ERROR, description="Failed to save device")


@bp.route("/devices/<string:device_id>", methods=["DELETE"])
def delete_device(device_id: str) -> ResponseReturnValue:
    """Delete a device"""
    if not validate_device_id(device_id):
        abort(HTTPStatus.BAD_REQUEST, description="Invalid device ID")

    api_key = get_api_key_from_headers(request.headers)
    if not api_key:
        abort(
            HTTPStatus.BAD_REQUEST,
            description="Missing or invalid Authorization header",
        )

    user = db.get_user_by_device_id(device_id)
    if not user:
        abort(HTTPStatus.NOT_FOUND, description="Device not found")
    
    device = user["devices"].get(device_id)
    if not device:
        abort(HTTPStatus.NOT_FOUND, description="Device not found")

    # Check authorization (user API key or device API key)
    user_api_key_matches = user.get("api_key") and user["api_key"] == api_key
    device_api_key_matches = device.get("api_key") and device["api_key"] == api_key
    if not user_api_key_matches and not device_api_key_matches:
        abort(HTTPStatus.FORBIDDEN, description="Unauthorized")

    # Remove device from user's devices
    user["devices"].pop(device_id, None)
    
    # Save user data and clean up device directories
    if db.save_user(user):
        db.delete_device_dirs(device_id)
        return Response("", status=204)
    else:
        abort(HTTPStatus.INTERNAL_SERVER_ERROR, description="Failed to delete device")


def push_image(
    device_id: str, installation_id: Optional[str], image_bytes: bytes
) -> None:
    device_webp_path = db.get_device_webp_dir(device_id)
    device_webp_path.mkdir(parents=True, exist_ok=True)
    pushed_path = device_webp_path / "pushed"
    pushed_path.mkdir(exist_ok=True)

    # Generate a unique filename using the sanitized installation_id or current timestamp
    if installation_id:
        filename = f"{secure_filename(installation_id)}.webp"
    else:
        filename = f"__{time.monotonic_ns()}.webp"
    file_path = pushed_path / filename

    # Save the decoded image data to a file
    file_path.write_bytes(image_bytes)

    if installation_id:
        # add the app so it'll stay in the rotation
        db.add_pushed_app(device_id, installation_id)

    push_new_image(device_id)


@bp.post("/devices/<string:device_id>/push")
def handle_push(device_id: str) -> ResponseReturnValue:
    try:
        if not validate_device_id(device_id):
            raise ValueError("Invalid device ID")

        # get api_key from Authorization header
        api_key = get_api_key_from_headers(request.headers)
        if not api_key:
            raise ValueError("Missing or invalid Authorization header")

        device = authenticate_device_access(device_id, api_key)
        if not device:
            raise FileNotFoundError("Device not found or invalid API key")

        # get parameters from JSON data
        # can't use request.get_json() because the media type might not be set to application/json
        try:
            data: Dict[str, Any] = json.loads(request.get_data(as_text=True))
        except json.JSONDecodeError:
            abort(HTTPStatus.BAD_REQUEST, description="Invalid JSON data")
        installation_id = data.get(
            "installationID", data.get("installationId")
        )  # get both cases ID and Id
        current_app.logger.debug(f"installation_id: {installation_id}")
        image_data = data.get("image")

        if not image_data:
            raise ValueError("Missing required image data")

        try:
            image_bytes = base64.b64decode(image_data)
        except Exception as e:
            current_app.logger.error(str(e))
            raise ValueError("Invalid image data")

        push_image(device_id, installation_id, image_bytes)

        return Response("WebP received.", status=200)

    except ValueError as e:
        abort(HTTPStatus.BAD_REQUEST, description=str(e))
    except FileNotFoundError as e:
        abort(HTTPStatus.NOT_FOUND, description=str(e))
    except Exception as e:
        current_app.logger.error(f"Unexpected error: {str(e)}")
        abort(
            HTTPStatus.INTERNAL_SERVER_ERROR, description="An unexpected error occurred"
        )


@bp.route("/devices/<string:device_id>/installations", methods=["GET", "POST"])
def handle_installations(device_id: str) -> ResponseReturnValue:
    validate_and_get_device(device_id)
    api_key = require_api_key()
    device, user = get_device_and_user(device_id, api_key)

    if request.method == "GET":
        # List installations
        apps = device.get("apps", {})
        installations = [
            {"id": installation_id, "appID": app_data.get("name", "")}
            for installation_id, app_data in apps.items()
        ]
        return Response(
            json.dumps({"installations": installations}),
            status=200,
            mimetype="application/json",
        )
    
    elif request.method == "POST":
        # Install new app
        data = get_request_json_or_abort()

        app_name = data.get("app_name")
        if not app_name:
            abort(HTTPStatus.BAD_REQUEST, description="App name is required")

        # Get app details
        app_details = db.get_app_details_by_name(user["username"], app_name)
        if not app_details:
            abort(HTTPStatus.NOT_FOUND, description="App not found")

        app_path = app_details.get("path")
        if not app_path:
            abort(HTTPStatus.NOT_FOUND, description="App path not found")

        # Generate unique installation ID
        from random import randint
        max_attempts = 10
        for _ in range(max_attempts):
            iname = str(randint(100, 999))
            if iname not in device.get("apps", {}):
                break
        else:
            abort(HTTPStatus.INTERNAL_SERVER_ERROR, description="Could not generate unique installation ID")

        # Create app installation
        app = App(
            name=app_name,
            iname=iname,
            enabled=data.get("enabled", False),
            last_render=0,
            path=app_path,
        )

        # Set optional fields
        if "uinterval" in data:
            app["uinterval"] = int(data["uinterval"])
        elif "recommended_interval" in app_details:
            app["uinterval"] = app_details["recommended_interval"]

        if "display_time" in data:
            app["display_time"] = int(data["display_time"])

        if "notes" in data:
            app["notes"] = data["notes"]

        if "config" in data:
            app["config"] = data["config"]

        app_id = app_details.get("id")
        if app_id:
            app["id"] = app_id

        # Add to device
        apps = user["devices"][device_id].setdefault("apps", {})
        app["order"] = len(apps)
        apps[iname] = app

        # Save user
        if db.save_user(user):
            # Return installation details
            installation_data = {
                "id": iname,
                "appID": app_name,
                "enabled": app.get("enabled", False),
                "uinterval": app.get("uinterval"),
                "display_time": app.get("display_time"),
                "notes": app.get("notes", ""),
                "order": app.get("order", 0)
            }
            return Response(
                json.dumps(installation_data),
                status=201,
                mimetype="application/json"
            )
        else:
            abort(HTTPStatus.INTERNAL_SERVER_ERROR, description="Failed to save app installation")


########################################################################################################
@bp.route(
    "/devices/<string:device_id>/installations/<string:installation_id>",
    methods=["PATCH", "PUT"],
)
def handle_patch_device_app(
    device_id: str, installation_id: str
) -> ResponseReturnValue:
    validate_and_get_device(device_id)
    api_key = require_api_key()
    device, user = get_device_and_user(device_id, api_key)

    # Handle the set_enabled json command
    if request.json is not None and "set_enabled" in request.json:
        set_enabled = request.json["set_enabled"]
        if not isinstance(set_enabled, bool):
            return Response(
                "Invalid value for set_enabled. Must be a boolean.", status=400
            )

        # Sanitize installation_id to prevent path traversal attacks
        installation_id = secure_filename(installation_id)
        apps = device.get("apps", {})

        # Get app_data and immediately return if it's not a valid dictionary
        app_data: Optional[App] = apps.get(installation_id)

        if app_data is None or "iname" not in app_data or "name" not in app_data:
            abort(HTTPStatus.NOT_FOUND)

        # Proceed with using app_data safely
        app: App = app_data
        if not app:
            abort(HTTPStatus.NOT_FOUND)

        # Enable it. Should probably render it right away too.
        if set_enabled:
            app["enabled"] = True
            app["last_render"] = 0  # this will trigger render on next fetch
            if db.save_app(device_id, app):
                return Response("App Enabled.", status=200)

        else:
            app["enabled"] = False
            webp_path = db.get_device_webp_dir(device["id"])
            if not webp_path.is_dir():
                abort(HTTPStatus.NOT_FOUND, description="Device directory not found")

            # Generate the filename using the installation_id eg. Acidwarp-220.webp
            file_path = webp_path / f"{app['name']}-{installation_id}.webp"
            current_app.logger.debug(file_path)
            if file_path.is_file():
                # Delete the file
                file_path.unlink()
            if db.save_app(device_id, app):
                return Response("App disabled.", status=200)
        return Response("Couldn't complete the operation", status=500)
    else:
        return Response("Unknown Operation", status=500)


########################################################################################################
@bp.delete("/devices/<string:device_id>/installations/<string:installation_id>")
def handle_delete(device_id: str, installation_id: str) -> ResponseReturnValue:
    validate_and_get_device(device_id)
    api_key = require_api_key()
    device, user = get_device_and_user(device_id, api_key)

    pushed_webp_path = db.get_device_webp_dir(device["id"]) / "pushed"
    if not pushed_webp_path.is_dir():
        abort(HTTPStatus.NOT_FOUND, description="Device directory not found")

    # Sanitize installation_id to prevent path traversal attacks
    installation_id = secure_filename(installation_id)

    # Generate the filename using the installation_id
    file_path = pushed_webp_path / f"{installation_id}.webp"
    current_app.logger.debug(file_path)
    if not file_path.is_file():
        abort(HTTPStatus.NOT_FOUND, description="File not found")

    # Delete the file
    file_path.unlink()

    return Response("Webp deleted.", status=200)


@bp.get("/apps")
def list_available_apps() -> ResponseReturnValue:
    """List all available apps (system and user apps)"""
    api_key = require_api_key()
    user = get_authenticated_user(api_key)
    
    # Get system apps
    system_apps_list = db.get_apps_list("system")
    
    # Get user's custom apps
    custom_apps_list = db.get_apps_list(user["username"])
    
    # Format the response
    apps = {
        "system_apps": [
            {
                "id": app["id"],
                "name": app.get("name", app["id"]),
                "description": app.get("description", ""),
                "path": app["path"]
            }
            for app in system_apps_list
        ],
        "custom_apps": [
            {
                "id": app["id"],
                "name": app.get("name", app["id"]),
                "description": app.get("description", ""),
                "path": app["path"]
            }
            for app in custom_apps_list
        ]
    }
    
    return Response(
        json.dumps(apps),
        status=200,
        mimetype="application/json"
    )


@bp.get("/apps/<string:app_id>/schema")
def get_app_schema(app_id: str) -> ResponseReturnValue:
    """Get the schema for an app by its ID"""
    api_key = require_api_key()
    user = get_authenticated_user(api_key)
    app_details = get_app_by_id_or_name(user["username"], app_id)
    
    app_path = app_details.get("path")
    if not app_path:
        abort(HTTPStatus.NOT_FOUND, description="App path not found")
    
    try:
        # Get the schema for the app
        from tronbyt_server import get_schema
        schema_json = get_schema(Path(app_path))
        if schema_json is None:
            return Response(
                json.dumps({"schema": None}),
                mimetype="application/json"
            )
        
        # Parse and return the schema
        schema = json.loads(schema_json) if schema_json else None
        return Response(
            json.dumps({"schema": schema}),
            mimetype="application/json"
        )
    except Exception as e:
        current_app.logger.error(f"Error getting app schema: {e}")
        abort(HTTPStatus.INTERNAL_SERVER_ERROR, description="Failed to get schema")


@bp.post("/apps/<string:app_id>/schema_handler/<string:handler>")
def app_schema_handler(app_id: str, handler: str) -> ResponseReturnValue:
    """
    Call a schema handler for an app.
    This allows testing schema handlers before installing the app.
    """
    api_key = require_api_key()
    user = get_authenticated_user(api_key)
    app_details = get_app_by_id_or_name(user["username"], app_id)
    
    app_path = app_details.get("path")
    if not app_path:
        abort(HTTPStatus.NOT_FOUND, description="App path not found")
    
    try:
        # Parse the JSON body
        data = get_request_json_or_abort()
        if "param" not in data:
            abort(HTTPStatus.BAD_REQUEST, description="Missing required parameter 'param'")
        
        # Call the handler with the provided parameter
        result = call_handler(Path(app_path), handler, data["param"])
        if result is None:
            abort(HTTPStatus.INTERNAL_SERVER_ERROR, description="Handler execution failed")
        
        # Return the result as JSON
        return Response(result, mimetype="application/json")
    except Exception as e:
        current_app.logger.error(f"Error in app_schema_handler: {e}")
        abort(HTTPStatus.INTERNAL_SERVER_ERROR, description="Handler execution failed")


@bp.get("/devices/<string:device_id>/apps")
def list_device_apps(device_id: str) -> ResponseReturnValue:
    """List all apps available for a specific device"""
    validate_and_get_device(device_id)
    api_key = require_api_key()
    device, user = get_device_and_user(device_id, api_key)
    
    # Get system apps
    system_apps_list = db.get_apps_list("system")
    
    # Get user's custom apps
    custom_apps_list = db.get_apps_list(user["username"])
    
    # Get currently installed apps on the device
    installed_apps = device.get("apps", {})
    installed_app_names = {app.get("name") for app in installed_apps.values() if app.get("name")}
    
    # Format the response
    apps = {
        "system_apps": [
            {
                "id": app["id"],
                "name": app.get("name", app["id"]),
                "description": app.get("description", ""),
                "path": app["path"],
                "installed": app.get("name", app["id"]) in installed_app_names
            }
            for app in system_apps_list
        ],
        "custom_apps": [
            {
                "id": app["id"],
                "name": app.get("name", app["id"]),
                "description": app.get("description", ""),
                "path": app["path"],
                "installed": app.get("name", app["id"]) in installed_app_names
            }
            for app in custom_apps_list
        ]
    }
    
    return Response(
        json.dumps(apps),
        status=200,
        mimetype="application/json"
    )


@bp.post("/devices/<string:device_id>/push_app")
def handle_app_push(device_id: str) -> ResponseReturnValue:
    try:
        validate_and_get_device(device_id)
        api_key = require_api_key()
        device, user = get_device_and_user(device_id, api_key)

        # Read the request body as a JSON object
        data = get_request_json_or_abort()

        config = data.get("config")
        app_id = data.get("app_id")
        if not app_id:
            raise ValueError("Missing app data")
        if config is None:
            raise ValueError("Missing config data")

        app_details = db.get_app_details_by_id(user["username"], app_id)
        app_path_name = app_details.get("path")
        if not app_path_name:
            raise FileNotFoundError("Missing app path")

        app_path = Path(app_path_name)
        if not app_path.exists():
            raise FileNotFoundError("App not found")

        installation_id = data.get(
            "installationID", data.get("installationId", "")
        )  # get both cases ID and Id
        current_app.logger.debug(f"installation_id: {installation_id}")

        app = db.get_pushed_app(user, device_id, installation_id)

        image_bytes = render_app(app_path, config, None, device, app)
        if image_bytes is None:
            raise RuntimeError("Rendering failed")
        if len(image_bytes) == 0:
            current_app.logger.debug("Empty image, not pushing")
            return Response("Empty image, not pushing", status=200)

        if installation_id:
            apps = user["devices"][device_id].setdefault("apps", {})
            apps[installation_id] = app
            db.save_user(user)

        push_image(device_id, installation_id, image_bytes)

        return Response("App pushed.", status=200)

    except ValueError as e:
        abort(HTTPStatus.BAD_REQUEST, description=str(e))
    except FileNotFoundError as e:
        abort(HTTPStatus.NOT_FOUND, description=str(e))
    except RuntimeError as e:
        abort(HTTPStatus.INTERNAL_SERVER_ERROR, description=str(e))


@bp.get("/devices/<string:device_id>/installations/<string:installation_id>/schema")
def get_installation_schema(device_id: str, installation_id: str) -> ResponseReturnValue:
    """
    Get the schema for an installed app on a device.
    Accepts both user API key and device API key.
    """
    validate_and_get_device(device_id)
    api_key = require_api_key()
    device, user = get_device_and_user(device_id, api_key)
    app = get_app_installation(user, device_id, installation_id)
    
    try:
        # Get the schema for the app
        from tronbyt_server import get_schema
        schema_json = get_schema(Path(app["path"]))
        if schema_json is None:
            return Response(
                json.dumps({"schema": None}),
                mimetype="application/json"
            )
        
        # Parse and return the schema
        schema = json.loads(schema_json) if schema_json else None
        return Response(
            json.dumps({"schema": schema}),
            mimetype="application/json"
        )
    except Exception as e:
        current_app.logger.error(f"Error getting schema: {e}")
        abort(HTTPStatus.INTERNAL_SERVER_ERROR, description="Failed to get schema")


@bp.post("/devices/<string:device_id>/installations/<string:installation_id>/schema_handler/<string:handler>")
def api_schema_handler(device_id: str, installation_id: str, handler: str) -> ResponseReturnValue:
    """
    Call a schema handler for an installed app on a device.
    Accepts both user API key and device API key.
    """
    validate_and_get_device(device_id)
    api_key = require_api_key()
    device, user = get_device_and_user(device_id, api_key)
    app = get_app_installation(user, device_id, installation_id)
    
    try:
        # Parse the JSON body
        data = get_request_json_or_abort()
        if "param" not in data:
            abort(HTTPStatus.BAD_REQUEST, description="Missing required parameter 'param'")
        
        # Call the handler with the provided parameter
        result = call_handler(Path(app["path"]), handler, data["param"])
        if result is None:
            abort(HTTPStatus.INTERNAL_SERVER_ERROR, description="Handler execution failed")
        
        # Return the result as JSON
        return Response(result, mimetype="application/json")
    except Exception as e:
        current_app.logger.error(f"Error in api_schema_handler: {e}")
        abort(HTTPStatus.INTERNAL_SERVER_ERROR, description="Handler execution failed")
