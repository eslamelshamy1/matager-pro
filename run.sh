#!/bin/bash
# تشغيل سريع على جهازك المحلي
cd "$(dirname "$0")"
pip3 install -r requirements.txt
python3 app.py
echo "افتح المتصفح على: http://localhost:5000"
