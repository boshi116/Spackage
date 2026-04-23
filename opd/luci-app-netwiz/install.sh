#!/bin/sh

echo "🚀 开始极速安装/升级 NetWiz 网络设置向导 (含多语言包)..."

# 1. 判定包管理器并强制卸载旧版主程序与语言包
echo "🧹 正在清理旧版本与系统残留..."
if command -v apk >/dev/null 2>&1; then
    PKG_TYPE="apk"
    apk del luci-app-netwiz luci-i18n-netwiz-zh-cn luci-i18n-netwiz-zh-tw >/dev/null 2>&1
elif command -v opkg >/dev/null 2>&1; then
    PKG_TYPE="ipk"
    opkg remove luci-app-netwiz luci-i18n-netwiz-zh-cn luci-i18n-netwiz-zh-tw --force-remove >/dev/null 2>&1
else
    echo "❌ 找不到支持的软件包管理器 (未找到 apk 或 opkg)！"
    exit 1
fi

# 清理 /tmp 目录下可能存在的历史文件
rm -f /tmp/${PKG_TYPE}_luci-*.${PKG_TYPE} 2>/dev/null

# 2. 批量下载主程序与语言包
echo "⬇️ 正在从云端下载最新版本 (${PKG_TYPE} 格式)..."

# 定义需要下载的核心组件数组
FILES="luci-app-netwiz luci-i18n-netwiz-zh-cn luci-i18n-netwiz-zh-tw"
DOWNLOAD_SUCCESS=0

for FILE in $FILES; do
    # 拼接分类前缀文件名，例如: apk_luci-app-netwiz.apk
    TARGET_FILE="${PKG_TYPE}_${FILE}.${PKG_TYPE}"
    URL_DIRECT="https://github.com/huchd0/luci/releases/latest/download/${TARGET_FILE}"
    # ✅ 已替换为目前最稳定高效的代理节点
    URL_PROXY="https://mirror.ghproxy.com/${URL_DIRECT}"

    echo "正在拉取: ${FILE} ..."
    wget -qO "/tmp/${TARGET_FILE}" --no-check-certificate -T 15 "$URL_DIRECT"
    
    # 下载失败或文件大小为空时，自动切换代理
    if [ "$?" -ne 0 ] || [ ! -s "/tmp/${TARGET_FILE}" ]; then
        echo "⚠️ 官方节点连接超时，自动切换加速节点..."
        wget -qO "/tmp/${TARGET_FILE}" --no-check-certificate -T 15 "$URL_PROXY"
    fi

    # 校验是否最终下载成功
    if [ -s "/tmp/${TARGET_FILE}" ]; then
        DOWNLOAD_SUCCESS=$((DOWNLOAD_SUCCESS + 1))
    else
        echo "❌ 警告: ${FILE} 下载失败，可能会导致部分功能或翻译缺失！"
    fi
done

# 如果一个包都没下下来，直接终止
if [ "$DOWNLOAD_SUCCESS" -eq 0 ]; then
    echo "❌ 所有文件下载彻底失败！"
    echo "💡 提示: 请检查路由器的网络，或确认 GitHub Release 页面是否已生成对应文件。"
    exit 1
fi

# 3. 部署新版本
echo "⚙️ 正在执行批量覆盖安装..."
if [ "$PKG_TYPE" = "apk" ]; then
    # 批量安装 /tmp/ 下所有带有前缀的 apk
    apk add --allow-untrusted --force-overwrite /tmp/${PKG_TYPE}_luci-*.apk
else
    # 批量安装 /tmp/ 下所有带有前缀的 ipk
    opkg install /tmp/${PKG_TYPE}_luci-*.ipk --force-reinstall --force-overwrite
fi

# 4. 清理缓存
echo "♻️ 正在重建 LuCI 缓存并重载权限服务..."
rm -f /tmp/luci-indexcache /tmp/luci-modulecache/* /tmp/luci-app-netwiz.* /tmp/${PKG_TYPE}_luci-* 2>/dev/null
/etc/init.d/rpcd reload 2>/dev/null

echo -e "\n✅ NetWiz 核心程序及多语言包更新与部署完成！"
echo -e "👉 请返回浏览器，按下键盘的 【Ctrl + F5】 (或 Shift+F5) 强制刷新网页，即可享受最新界面！"
exit 0
