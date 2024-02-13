# bbt-sso-client-compat

Register your SSO login callback:
```
public function do_login_sso(){
  $sso = new BbtSsoClient($sso_url_endpoint, $sso_client_id);
  $emp = $this->sso->SsoCallbackHandler();

  $nip = $emp->nip;
  $fullname = $emp->name;

  ... (your login handle's code) ...
}
```

Authenticating User: Ideally you would intercept any incoming request with this code to check the login session:
```
$sso = new BbtSsoClient($sso_url_endpoint, $sso_client_id);
$sso->Auth(); //authenticate and automatically redirect to the SSO's login page if yet to be logged-in
```
