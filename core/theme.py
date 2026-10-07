import base64
from pathlib import Path

import streamlit as st

IMAGE = Path(__file__).resolve().parent.parent / "bg.jpeg"   # change if your file differs


@st.cache_data
def _encoded(path):
    return base64.b64encode(Path(path).read_bytes()).decode()


def apply_theme():
    bg = "background-color: #0a1a3a;"
    if IMAGE.exists():
        ext = IMAGE.suffix.lstrip(".").lower().replace("jpg", "jpeg")
        bg = (
            "background-image: linear-gradient(rgba(10,26,58,0.6), rgba(10,26,58,0.6)), "
            f'url("data:image/{ext};base64,{_encoded(str(IMAGE))}"); '
            "background-size: cover; background-attachment: fixed;"
        )
    st.markdown(
        f"""
        <style>
        .stApp {{ {bg} }}
        [data-testid="stHeader"] {{ background: transparent; }}
        [data-testid="stSidebar"] {{ background-color: rgba(10,26,58,0.88); }}
        .stApp, .stApp p, .stApp label, .stApp span, .stApp li,
        h1, h2, h3, h4, h5, h6,
        [data-testid="stMetricLabel"], [data-testid="stMetricValue"],
        [data-testid="stMarkdownContainer"], [data-testid="stCaptionContainer"] {{
            color: #ffffff !important;
        }}
        input, textarea {{ color: #000000 !important; }}
        </style>
        """,
        unsafe_allow_html=True,
    )