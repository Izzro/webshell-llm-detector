#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
困难良性样本：使用 subprocess 执行固定命令处理图片

业务场景：图片服务调用 ImageMagick convert 生成缩略图。
命令以列表形式传递，不使用 shell=True。

为什么安全：
  1. subprocess.run 命令以列表形式传递，shell=False，
     不经过 shell 解释器，不存在元字符注入。
  2. 可执行文件路径 "convert" 来自 shutil.which，非用户输入。
  3. 输出文件名由 UUID 生成，用户文件名仅用于读取（经校验）。
  4. 尺寸参数经整数校验和范围限制。
"""

import uuid
import shutil
import subprocess
from pathlib import Path


class ImageProcessor:
    """图片缩略图生成器"""

    UPLOAD_DIR = Path("/var/www/uploads/images")
    THUMB_DIR = Path("/var/www/uploads/thumbnails")
    MIN_SIZE = 16
    MAX_SIZE = 2048
    MIME = {b'\xff\xd8\xff':'jpg', b'\x89PNG':'png', b'GIF8':'gif'}

    def _safe_path(self, base_dir, filename):
        """构建安全路径，防路径穿越"""
        full = (base_dir / Path(filename).name).resolve()
        try:
            full.relative_to(base_dir.resolve())
        except ValueError:
            raise ValueError("文件路径非法")
        return full

    def generate_thumbnail(self, input_filename, width=300, height=300):
        """生成缩略图"""
        # 尺寸参数校验
        width, height = int(width), int(height)
        if not (self.MIN_SIZE <= width <= self.MAX_SIZE):
            raise ValueError("宽度超出范围")
        if not (self.MIN_SIZE <= height <= self.MAX_SIZE):
            raise ValueError("高度超出范围")
        # 安全输入路径 + 图片格式校验
        input_path = self._safe_path(self.UPLOAD_DIR, input_filename)
        if not input_path.exists():
            raise ValueError("输入文件不存在")
        with open(input_path, 'rb') as f:
            header = f.read(12)
        if not any(header.startswith(m) for m in self.MIME):
            raise ValueError("不支持的图片格式")
        # UUID 生成输出文件名（不含用户输入）
        output_path = self.THUMB_DIR / f"thumb_{uuid.uuid4().hex}.png"
        convert_bin = shutil.which("convert")
        if not convert_bin:
            raise RuntimeError("convert not found")
        # shell=False, list form, no injection
        cmd_array = [convert_bin, str(input_path), "-resize",
                     f"{width}x{height}", "-strip", "-quality", "85", str(output_path)]
        try:
            result = subprocess.run(cmd_array, capture_output=True, timeout=30)
        except subprocess.TimeoutExpired:
            raise RuntimeError("图片处理超时")
        if result.returncode != 0:
            raise RuntimeError("图片处理失败")
        return output_path.name

if __name__ == '__main__':
    p = ImageProcessor()
    try:
        name = p.generate_thumbnail("upload_abc.jpg", 300, 300)
        print(f"缩略图: {name}")
    except (ValueError, RuntimeError) as e:
        print(f"失败: {e}")
