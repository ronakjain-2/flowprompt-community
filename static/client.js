(function () {
  if (!window.app || !app.user || !app.user.uid) {
    return;
  }

  console.log('[FlowPrompt SSO] Client loaded – letting NodeBB handle sockets');

  // ---- NEW LOGIC: FORCE REDIRECT FOR AJAX LOGIN / REGISTER ----
  $(document).ajaxError((event, jqxhr, settings) => {
    try {
      const response = jqxhr.responseJSON;

      if (response && response.redirect) {
        console.log(
          '[FlowPrompt SSO] Redirecting to FlowPrompt:',
          response.redirect,
        );

        // Force full browser navigation
        window.location.href = response.redirect;
      }
    } catch (err) {
      // silently ignore
    }
  });

  // ---- OPTIONAL HARDENING: BLOCK LOGIN / REGISTER PAGES ENTIRELY ----
  $(window).on('action:ajaxify.contentLoaded', (ev, data) => {
    if (data?.template === 'login' || data?.template === 'register') {
      console.log(
        '[FlowPrompt SSO] Blocking NodeBB auth UI, redirecting to FlowPrompt',
      );

      window.location.href = 'https://flowprompt.ai/login';
    }
  });
})();
