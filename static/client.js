(function () {
  if (!window.app || !app.user || !app.user.uid) {
    return;
  }

  console.log('[FlowPrompt SSO] Client loaded – letting NodeBB handle sockets');
})();
