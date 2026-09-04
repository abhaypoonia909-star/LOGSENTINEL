import os
from werkzeug.utils import secure_filename
from config import Config


def save_upload(filename, raw_data):
    upload_dir = Config.UPLOAD_FOLDER
    os.makedirs(upload_dir, exist_ok=True)

    safe_name = secure_filename(filename)
    stored_name = safe_name

    path = os.path.join(upload_dir, stored_name)

    with open(path, "wb") as f:
        f.write(raw_data)

    return stored_name, path
