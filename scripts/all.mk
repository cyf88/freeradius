install: $(R)$(sbindir)/rc.radiusd $(R)$(sbindir)/raddebug \
	$(R)$(bindir)/radsqlrelay $(R)$(bindir)/radcrypt $(R)$(bindir)/rlm_sqlippool_tool

$(R)$(sbindir)/rc.radiusd: scripts/rc.radiusd
	@mkdir -p $(dir $@)
	@$(INSTALL) -m 755 $< $@

$(R)$(sbindir)/raddebug: scripts/raddebug
	@mkdir -p $(dir $@)
	@$(INSTALL) -m 755 $< $@

$(R)$(bindir)/radsqlrelay: scripts/sql/radsqlrelay
	@mkdir -p $(dir $@)
	@$(INSTALL) -m 755 $< $@

$(R)$(bindir)/radcrypt: scripts/cryptpasswd
	@mkdir -p $(dir $@)
	@$(INSTALL) -m 755 $< $@

$(R)$(bindir)/rlm_sqlippool_tool: scripts/sql/rlm_sqlippool_tool
	@mkdir -p $(dir $@)
	@$(INSTALL) -m 755 $< $@
