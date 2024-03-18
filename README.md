# bbt-sso-client-compat

- Cookies must be enabled in the browser

- Get or register your Client-ID and Client-Secret from Admin
```
// instantiate client's object using the given Client-ID and Client-Secret
$sso = new BbtSsoClient($sso_url, $sso_client_id, $sso_client_secret);
```

- Register your SSO login callback's url and call method SsoCallbackHandler() to perform 2nd step of Oauth2 flow (get token using Authorization Code)
```
public function do_login_sso(){
  $sso = new BbtSsoClient($sso_url, $sso_client_id, $sso_client_secret);
  $user = $this->sso->SsoCallbackHandler();

  $nip = $user->nip;
  $fullname = $user->name;

  ... (your login handle's code) ...
}
```

- Authenticating User: Ideally you would intercept any incoming request with this code to check the IDP's login session:
```
$sso = new BbtSsoClient($sso_url, $sso_client_id, $sso_client_secret);
$sso->AuthCheck(); //authenticate and automatically redirect to the SSO's login page if yet to be logged-in
```

- Login page redirections
```
$sso = new BbtSsoClient($sso_url, $sso_client_id, $sso_client_secret);

$sso->Logout(); //also revokes tokens saved in cookies

$sso->LoginPage(); //redirect to login page without revoking tokens

$sso->LoginPage(['some_url_param' => 'somevalue']); //redirect to login page without revoking tokens, and with url parameters

$url = $sso->LoginPage([], false); //set 2nd argument to false for only generate login url without automatically-redirecting to the login page
```
- if you want to use another "grant_type" other than "authorization_code", contact administrator (currently supported grant_type(s): authorization_code, password, and client_credentials)
