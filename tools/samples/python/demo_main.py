# EZLARP sample: an inert script packed the way PyInstaller packs programs.
# It shows the Python module view and the threat scan. Nothing here runs or sends anything.
import os
import helper

WEBHOOK = "https://discord.com/api/webhooks/000000000000000000/EZLARP-DEMO-NOT-A-REAL-WEBHOOK"


def candidate_paths():
    base = os.getenv("APPDATA", "")
    return [os.path.join(base, "discord", "Local Storage", "leveldb")]


def main():
    print(helper.banner("EZLARP demo — this script does nothing"))


if __name__ == "__main__":
    main()
