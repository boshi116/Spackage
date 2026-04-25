include $(TOPDIR)/rules.mk

PKG_NAME:=luci-app-sqm-controller
PKG_VERSION:=3.0.0
PKG_RELEASE:=11
PKG_LICENSE:=MIT
PKG_MAINTAINER:=vaidurya.zws@qq.com

LUCI_TITLE:=SQM Controller Web Interface
LUCI_DESCRIPTION:=Smart Queue Management (SQM) controller with LuCI web interface
LUCI_PKGARCH:=all

LUCI_DEPENDS:=+python3 +python3-light +curl +ca-bundle +kmod-ifb \
              +kmod-sched-core +kmod-sched-cake +kmod-sched-connmark +kmod-sched-ctinfo \
              +luci-base +luci-compat \
              +luci-lib-ip +luci-lib-nixio

include $(TOPDIR)/feeds/luci/luci.mk


define Package/$(PKG_NAME)/install
	$(INSTALL_DIR) $(1)/usr/lib/lua/luci/controller
	$(INSTALL_DIR) $(1)/usr/lib/lua/luci/model/cbi
	$(INSTALL_DIR) $(1)/usr/lib/lua/luci/view/sqm_controller
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_DIR) $(1)/usr/lib/sqm-controller
	$(INSTALL_DIR) $(1)/usr/share/rpcd/acl.d

	# LuCI controller/model
	$(INSTALL_DATA) ./luasrc/controller/sqm_controller.lua \
		$(1)/usr/lib/lua/luci/controller/

	$(INSTALL_DATA) ./luasrc/model/cbi/sqm_controller.lua \
		$(1)/usr/lib/lua/luci/model/cbi/

	# LuCI views
	$(INSTALL_DATA) ./luasrc/view/sqm_controller/help.htm \
		$(1)/usr/lib/lua/luci/view/sqm_controller/
	$(INSTALL_DATA) ./luasrc/view/sqm_controller/logs.htm \
		$(1)/usr/lib/lua/luci/view/sqm_controller/
	$(INSTALL_DATA) ./luasrc/view/sqm_controller/status.htm \
		$(1)/usr/lib/lua/luci/view/sqm_controller/
	$(INSTALL_DATA) ./luasrc/view/sqm_controller/monitor.htm \
		$(1)/usr/lib/lua/luci/view/sqm_controller/
	$(INSTALL_DATA) ./luasrc/view/sqm_controller/templates.htm \
		$(1)/usr/lib/lua/luci/view/sqm_controller/
	$(INSTALL_DATA) ./luasrc/view/sqm_controller/wizard.htm \
		$(1)/usr/lib/lua/luci/view/sqm_controller/
	$(INSTALL_DATA) ./luasrc/view/sqm_controller/traffic.htm \
		$(1)/usr/lib/lua/luci/view/sqm_controller/
	$(INSTALL_DATA) ./luasrc/view/sqm_controller/policy.htm \
		$(1)/usr/lib/lua/luci/view/sqm_controller/
	# config/init
	$(INSTALL_CONF) ./files/etc/config/sqm_controller \
		$(1)/etc/config/

	$(INSTALL_BIN) ./files/etc/init.d/sqm-controller \
		$(1)/etc/init.d/

	# shell helpers
	$(INSTALL_BIN) ./files/usr/bin/sqm-start.sh \
		$(1)/usr/bin/
	$(INSTALL_BIN) ./files/usr/bin/sqm-stop.sh \
		$(1)/usr/bin/
	$(INSTALL_BIN) ./files/usr/bin/sqm-status.sh \
		$(1)/usr/bin/

	# python backend
	$(INSTALL_BIN) ./files/usr/lib/sqm-controller/config_manager.py \
		$(1)/usr/lib/sqm-controller/
	$(INSTALL_BIN) ./files/usr/lib/sqm-controller/main.py \
		$(1)/usr/lib/sqm-controller/
	$(INSTALL_BIN) ./files/usr/lib/sqm-controller/tc_manager.py \
		$(1)/usr/lib/sqm-controller/
	$(INSTALL_BIN) ./files/usr/lib/sqm-controller/template_manager.py \
		$(1)/usr/lib/sqm-controller/
	$(INSTALL_BIN) ./files/usr/lib/sqm-controller/monitor.py \
		$(1)/usr/lib/sqm-controller/
	$(INSTALL_BIN) ./files/usr/lib/sqm-controller/self_check.py \
		$(1)/usr/lib/sqm-controller/
	$(INSTALL_BIN) ./files/usr/lib/sqm-controller/speedtest.py \
		$(1)/usr/lib/sqm-controller/
	$(INSTALL_BIN) ./files/usr/lib/sqm-controller/firewall_manager.py \
		$(1)/usr/lib/sqm-controller/
	$(INSTALL_BIN) ./files/usr/lib/sqm-controller/traffic_classifier.py \
		$(1)/usr/lib/sqm-controller/
	$(INSTALL_BIN) ./files/usr/lib/sqm-controller/traffic_stats.py \
		$(1)/usr/lib/sqm-controller/
	$(INSTALL_BIN) ./files/usr/lib/sqm-controller/policy_engine.py \
		$(1)/usr/lib/sqm-controller/
	$(INSTALL_BIN) ./check-deps.sh \
		$(1)/usr/lib/sqm-controller/

	# rpcd ACL
	$(INSTALL_DATA) ./files/share/rpcd/acl.d/luci-app-sqm-controller.json \
		$(1)/usr/share/rpcd/acl.d/
endef


define Package/$(PKG_NAME)/conffiles
/etc/config/sqm_controller
endef


define Package/$(PKG_NAME)/postinst
#!/bin/sh
[ -n "$$IPKG_INSTROOT" ] || {
	chmod 0755 /etc/init.d/sqm-controller 2>/dev/null
	chmod 0755 /usr/bin/sqm-*.sh 2>/dev/null
	chmod 0755 /usr/lib/sqm-controller/*.py 2>/dev/null
	chmod 0755 /usr/lib/sqm-controller/*.sh 2>/dev/null

	touch /var/log/sqm_controller.log 2>/dev/null
	touch /var/log/sqm_policy.jsonl 2>/dev/null

	/etc/init.d/sqm-controller enable 2>/dev/null
	uci -q get sqm_controller.basic_config.enabled | grep -q '^1$$' && /etc/init.d/sqm-controller restart
}
exit 0
endef


define Package/$(PKG_NAME)/prerm
#!/bin/sh
[ -n "$$IPKG_INSTROOT" ] || {
	/etc/init.d/sqm-controller stop 2>/dev/null || true
	/etc/init.d/sqm-controller disable 2>/dev/null || true
}
exit 0
endef


$(eval $(call BuildPackage,$(PKG_NAME)))
