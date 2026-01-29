(function () {
  console.log('[FlowPrompt SSO] Client loaded');
  console.log('[FlowPrompt SSO] Window:', window);
  console.log('[FlowPrompt SSO] App:', window.app);
  console.log('[FlowPrompt SSO] User:', window.app.user);
  console.log('[FlowPrompt SSO] UID:', window.app.user.uid);

  if (!window.app || !window.app.user || !window.app.user.uid) {
    return;
  }

  console.log('[FlowPrompt SSO] Client loaded – letting NodeBB handle sockets');

  // 🔑 Intercept ALL ajax responses (success + failure)
  $(document).ajaxComplete((event, xhr, settings) => {
    try {
      const contentType = xhr.getResponseHeader('content-type') || '';

      if (!contentType.includes('application/json')) {
        return;
      }

      const response = JSON.parse(xhr.responseText);

      if (response && response.redirect) {
        console.log('[FlowPrompt SSO] Forcing redirect to:', response.redirect);
        window.location.href = response.redirect;
      }
    } catch (e) {
      // ignore parse errors
    }
  });

  // 🛡️ Extra safety: block auth pages entirely
  $(window).on('action:ajaxify.contentLoaded', (ev, data) => {
    if (data?.template === 'login' || data?.template === 'register') {
      console.log('[FlowPrompt SSO] Blocking NodeBB auth page');
      window.location.href = 'https://flowprompt.ai?forum=true';
    }
  });
})();
