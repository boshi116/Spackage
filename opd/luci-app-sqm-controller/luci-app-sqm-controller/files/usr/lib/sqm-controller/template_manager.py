#!/usr/bin/env python3
"""
场景模板管理器
"""

TEMPLATES = {
    "game": {
        "name": "游戏模式",
        "upload": 2000,
        "download": 8000,
        "algorithm": "fq_codel",
        "ecn": True
    },
    "meeting": {
        "name": "视频会议模式",
        "upload": 3000,
        "download": 10000,
        "algorithm": "fq_codel",
        "ecn": True
    },
    "normal": {
        "name": "普通上网模式",
        "upload": 5000,
        "download": 20000,
        "algorithm": "cake",
        "ecn": False
    },
    "download": {
        "name": "下载模式",
        "upload": 1000,
        "download": 50000,
        "algorithm": "cake",
        "ecn": False
    }
}

def get_templates():
    return TEMPLATES

def get_template(name):
    return TEMPLATES.get(name)