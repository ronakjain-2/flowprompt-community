<div class="row">
  <div class="col-lg-9">
    <form role="form" class="flowprompt-sso-settings">
      <div class="panel panel-default">
        <div class="panel-heading">
          <i class="fa fa-key"></i> FlowPrompt SSO Configuration
        </div>
        <div class="panel-body">
          <div class="form-group">
            <label for="flowpromptUrl">FlowPrompt API URL</label>
            <input type="text" class="form-control" id="flowpromptUrl" name="flowpromptUrl" placeholder="https://api.flowprompt.com" value="<!-- IF config.flowpromptUrl -->{config.flowpromptUrl}<!-- ENDIF config.flowpromptUrl -->">
            <p class="help-block">Base URL of your FlowPrompt API server</p>
          </div>

          <div class="form-group">
            <label for="publicKey">Public Key (PEM) - Optional</label>
            <textarea class="form-control" id="publicKey" name="publicKey" rows="5" placeholder="-----BEGIN PUBLIC KEY-----&#10;...&#10;-----END PUBLIC KEY-----"><!-- IF config.publicKey -->{config.publicKey}<!-- ENDIF config.publicKey --></textarea>
            <p class="help-block">If provided, this will be used instead of fetching from JWKS endpoint</p>
          </div>

          <div class="form-group">
            <label for="issuer">JWT Issuer</label>
            <input type="text" class="form-control" id="issuer" name="issuer" value="<!-- IF config.issuer -->{config.issuer}<!-- ELSE -->flowprompt<!-- ENDIF config.issuer -->">
            <p class="help-block">Expected issuer claim in JWT tokens</p>
          </div>

          <div class="form-group">
            <label for="audience">JWT Audience</label>
            <input type="text" class="form-control" id="audience" name="audience" value="<!-- IF config.audience -->{config.audience}<!-- ELSE -->nodebb<!-- ENDIF config.audience -->">
            <p class="help-block">Expected audience claim in JWT tokens</p>
          </div>

          <div class="form-group">
            <label for="nonceStore">Nonce Store Type</label>
            <select class="form-control" id="nonceStore" name="nonceStore">
              <option value="memory" <!-- IF config.nonceStore === "memory" -->selected<!-- ENDIF config.nonceStore -->>Memory (Development)</option>
              <option value="redis" <!-- IF config.nonceStore === "redis" -->selected<!-- ENDIF config.nonceStore -->>Redis (Production)</option>
            </select>
            <p class="help-block">Storage backend for nonce tracking (prevents replay attacks)</p>
          </div>

          <div class="form-group">
            <label for="redisUrl">Redis URL (if using Redis)</label>
            <input type="text" class="form-control" id="redisUrl" name="redisUrl" value="<!-- IF config.redisUrl -->{config.redisUrl}<!-- ELSE -->redis://localhost:6379<!-- ENDIF config.redisUrl -->">
            <p class="help-block">Redis connection URL (only used if Nonce Store Type is Redis)</p>
          </div>

          <div class="form-group">
            <div class="checkbox">
              <label>
                <input type="checkbox" id="autoCreateUsers" name="autoCreateUsers" <!-- IF config.autoCreateUsers -->checked<!-- ENDIF config.autoCreateUsers -->>
                Automatically create users if they don't exist
              </label>
            </div>
            <p class="help-block">If enabled, new users will be created automatically when they SSO in</p>
          </div>

          <div class="form-group">
            <label for="defaultGroup">Default Group for New Users</label>
            <input type="text" class="form-control" id="defaultGroup" name="defaultGroup" value="<!-- IF config.defaultGroup -->{config.defaultGroup}<!-- ELSE -->registered-users<!-- ENDIF config.defaultGroup -->">
            <p class="help-block">Group to add newly created users to</p>
          </div>

          <div class="form-group">
            <label for="allowedRedirectHosts">Allowed Redirect Hosts (comma-separated)</label>
            <input type="text" class="form-control" id="allowedRedirectHosts" name="allowedRedirectHosts" value="<!-- IF config.allowedRedirectHosts -->{config.allowedRedirectHosts}<!-- ENDIF config.allowedRedirectHosts -->" placeholder="forum.example.com,www.example.com">
            <p class="help-block">Comma-separated list of allowed hostnames for redirects (leave empty to allow all)</p>
          </div>
        </div>
      </div>

      <button type="submit" class="btn btn-primary">Save Settings</button>
    </form>
  </div>
</div>

<script>
  $(document).ready(function() {
    $('.flowprompt-sso-settings').on('submit', function(e) {
      e.preventDefault();
      const formData = $(this).serialize();
      
      $.ajax({
        url: '/api/admin/plugins/flowprompt-sso',
        method: 'POST',
        data: formData,
        success: function(data) {
          app.alertSuccess('Settings saved successfully!');
        },
        error: function(err) {
          app.alertError('Error saving settings: ' + (err.responseJSON?.error || 'Unknown error'));
        }
      });
    });
  });
</script>

