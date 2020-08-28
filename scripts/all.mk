install: $(R)$(sbindir)/rc.radiusd $(R)$(sbindir)/raddebug \
	$(R)$(bindir)/radsqlrelay $(R)$(bindir)/radcrypt $(R)$(bindir)/rlm_sql_gen_ippool

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

$(R)$(bindir)/rlm_sql_gen_ippool: scripts/sql/rlm_sql_gen_ippool
	@mkdir -p $(dir $@)
	@$(INSTALL) -m 755 $< $@
