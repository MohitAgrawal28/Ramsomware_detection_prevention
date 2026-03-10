import shutil
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SOURCE_FOLDER = os.path.join(BASE_DIR, "test_folder")
BACKUP_FOLDER = os.path.join(BASE_DIR, "backup_folder")

def backup_files():
    if not os.path.exists(BACKUP_FOLDER):
        os.makedirs(BACKUP_FOLDER)

    for file in os.listdir(SOURCE_FOLDER):
        src = os.path.join(SOURCE_FOLDER, file)
        dst = os.path.join(BACKUP_FOLDER, file)
        if os.path.isfile(src):
            try:
                shutil.copy2(src, dst)
            except (PermissionError, OSError):
                pass  # Skip locked files

def restore_files():
    if not os.path.exists(BACKUP_FOLDER):
        print("  No backup found!")
        return

    print("  Restoring files from backup...")
    for file in os.listdir(BACKUP_FOLDER):
        src = os.path.join(BACKUP_FOLDER, file)
        dst = os.path.join(SOURCE_FOLDER, file)
        try:
            shutil.copy2(src, dst)
        except (PermissionError, OSError):
            pass
    print("  Files restored!")