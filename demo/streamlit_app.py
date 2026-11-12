"""Streamlit Community Cloud entry point: download the hashed demo bundle from Hugging Face once, then run the analyst dashboard on it."""
import os
import runpy
import sys
from pathlib import Path

import streamlit as st

REPO = Path(__file__).resolve().parent.parent
DATASET = os.environ.get("DERIDDLED_DEMO_DATASET", "TazerFlash/de-riddled-demo-data")
LOCAL = Path(os.environ.get("DERIDDLED_DEMO_DIR") or Path.home() / ".deriddled-demo")

st.set_page_config(page_title="De-Riddled", layout="wide")


@st.cache_resource(show_spinner="Loading the demo data (first start only, about a minute)…")
def bundle() -> str:
    from huggingface_hub import snapshot_download
    snapshot_download(DATASET, repo_type="dataset", local_dir=LOCAL)
    return str(LOCAL)


os.environ["DERIDDLED_ROOT"] = bundle()
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))
runpy.run_path(str(REPO / "dashboard" / "app.py"), run_name="__main__")
