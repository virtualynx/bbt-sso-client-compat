<?php

namespace Bbt\Sso;

/**
 * For PHP >= 5.4.0
 */
class BbtSsoClient {
    private $sso_url;
    private $client_id;
    private $client_secret;
    private $sso_url_local;
    private $proxy;
    private $http_client;

    private const ACCESS_TOKEN_NAME = 'mwsat';
    private const REFRESH_TOKEN_NAME = 'mwsrt';
    private const ACCESS_TOKEN_AGE = (60*5);
    private const REFRESH_TOKEN_AGE = (60*60*2);

    function __construct(
        $sso_url, $client_id, $client_secret,
        $sso_url_local = '',
        $proxy = null
    ){
        $this->sso_url = $sso_url;
        $this->client_id = $client_id;
        $this->client_secret = $client_secret;
        $this->sso_url_local = $sso_url_local;
        $this->proxy = $proxy;
        $this->http_client = new HttpClient($proxy);
    }

    function LoginPage($params = [], $redirectLoginPage = true){
        $code_length = 64;
		$verifier = bin2hex(random_bytes(($code_length-($code_length%2))/2));
        setcookie('pkce_verifier', $verifier, time() + (60*60*24 * 3), '/', $this->GetDomain(), false, true);

        $challenge = base64_encode(hash('sha256', $verifier));
        
        $params['client_id'] = $this->client_id;
        $params['challenge'] = $challenge;
        $params['challenge_method'] = 's256';
        
        $strs = [];
        foreach($params as $key => $value){
            $encoded_value = urlencode($value);
            $strs []= "$key=$encoded_value";
        }
        $login_url = "$this->sso_url?".(implode('&', $strs));

        if($redirectLoginPage){
            header("Location: $login_url");
            exit();
        }

        return $login_url;
    }

    /**
     * Call this on your callback endpoint
     */
    function SsoCallbackHandler(){
        if(!isset($_GET['code'])){
            throw new \Exception('Invalid call, missing "code"');
        }

        if(!isset($_COOKIE['pkce_verifier'])){
            $this->LoginPage(['alert' => 'You left your login-page open for a long period of time. Please try logging in again !']);
        }

        try{
            $pkce_verifier = $_COOKIE['pkce_verifier'];
            setcookie('pkce_verifier', '', time() - 1, '/', $this->GetDomain(), false, true);

            $resp = $this->http_client->post($this->GetSsoUrl().'/get_token', [
                'code' => $_GET['code'],
                'verifier' => $pkce_verifier
            ]);
            if($resp){
                $json_resp = json_decode($resp);
                self::SaveTokens($json_resp);

                return $json_resp->user;
            }

            throw new \Exception('Empty response from Code-Exchange API');
        }catch(\Exception $e){
            if($e->getCode() == 401 && $e->getMessage() == 'PKCE challenge failed'){
                $this->LoginPage(['alert' => 'Login failed, make sure not to open multiple SSO-Login Page at once']);
            }

            throw $e;
        }
    }

    /**
     * Call this to check the validity of the SSO's shared-session
     */
    function Auth($autoRedirectLogin = true){
        if($this->IsThrottled()){
            return true;
        }

        try{
            $access_token = self::GetToken('access_token');
            $resp = $this->http_client->post($this->GetSsoUrl().'/authorize', ['type' => 'access'], $access_token);
            if($resp){
                $json_resp = json_decode($resp);
                if($json_resp->status != 'success'){
                    throw new \Exception("Authorization Failed: $resp");
                }
                $this->SetNextThrottlingTime();

                return true;
            }

            throw new \Exception('Empty response from Authentication API');
        }catch(\Exception $e){
            if($e->getCode() == 401){
                if($e->getMessage() == 'Expired token'){ //access token is expired
                    return $this->RefreshToken($autoRedirectLogin);
                }else{ //401 error, the cause is being logged in SSO server
                    if($autoRedirectLogin){
                        $this->Logout(['alert' => 'Your session is expired(401-access), please login again ! ('.$e->getMessage().')']);
                    }

                    return false;
                }
            }

            throw $e;
        }
    }
    
    private function RefreshToken($autoRedirectLogin){
        try{
            $refresh_token = self::GetToken('refresh_token');
            $resp = $this->http_client->post($this->GetSsoUrl().'/authorize', ['type' => 'refresh'], $refresh_token);
            if($resp){
                $json_resp = json_decode($resp);
                if($json_resp->status == 'success'){
                    self::SaveTokens($json_resp);
                    $this->SetNextThrottlingTime();

                    return true;
                }else{
                    throw new \Exception("Refresh Authorization Failed: $resp");
                }
            }

            throw new \Exception('Empty response from Authentication API');
        }catch(\Exception $e){
            if($e->getCode() == 401){
                $alert_msg = '';
                if($e->getMessage() == 'Expired token'){ //refresh token is expired
                    $alert_msg = 'Your session is expired, please login again !';
                }else{ //401 error, the cause is being logged in SSO server
                    $alert_msg = 'Your session is expired(401-refresh), please login again ! ('.$e->getMessage().')';
                }
                if($autoRedirectLogin){
                    $this->Logout(['alert' => $alert_msg]);
                }

                return false;
            }
            
            throw $e;
        }
    }

    function GetUserInfo(){
        $this->Auth();

        try{
            $resp = $this->http_client->post(
                $this->GetSsoUrl().'/userinfo', ['client_id' => $this->client_id], self::GetToken('access_token'));
            if($resp){
                $json_resp = json_decode($resp);
                if($json_resp->status != 'success'){
                    throw new \Exception("Get User Info failed: $resp");
                }
                
                return $json_resp->user;
            }

            throw new \Exception('Empty response from User-info API');
        }catch(\Exception $e){
            throw $e;
        }
    }

    public function Logout($loginPageParams = []){
        // session_destroy();

        try{
            $access_token = self::GetToken('access_token');
            $resp = $this->http_client->post($this->GetSsoUrl().'/logout', [], $access_token);
            if($resp){
                $json_resp = json_decode($resp);
                if($json_resp->status != 'success'){
                    throw new \Exception("SLO failed: $resp");
                }

                self::RevokeTokens();
            }

            throw new \Exception('Empty response from Logout API');
        }catch(\Exception $e){
            if($e->getCode() != 401){
                throw $e;
            }
        }

        $this->LoginPage($loginPageParams);
    }

    private function GetSsoUrl(){
        return !empty($this->sso_url_local)? $this->sso_url_local: $this->sso_url;
    }

    private static function GetToken($name){
        $token_keymap = [
            'access_token' => self::ACCESS_TOKEN_NAME,
            'refresh_token' => self::REFRESH_TOKEN_NAME
        ];
        
        if(empty($_COOKIE[$token_keymap['access_token']]) && empty($_COOKIE[$token_keymap['refresh_token']])) {
            throw new \Exception('Expired token', 401);
        }

        $tag = $token_keymap[$name];
        if(empty($_COOKIE[$tag])) {
            throw new \Exception('Expired token', 401);
        }

        return $_COOKIE[$tag];
    }

    private static function SaveTokens($tokens){
        $domain = self::GetDomain();
        setcookie(self::ACCESS_TOKEN_NAME, $tokens->access_token, time() + self::ACCESS_TOKEN_AGE, '/', $domain, false, true);
        setcookie(self::REFRESH_TOKEN_NAME, $tokens->refresh_token, time() + self::REFRESH_TOKEN_AGE, '/', $domain, false, true);
    }

    private static function RevokeTokens(){
        $domain = self::GetDomain();
        setcookie(self::ACCESS_TOKEN_NAME, '', time()-1, '/', $domain, false, true);
        setcookie(self::REFRESH_TOKEN_NAME, '', time()-1, '/', $domain, false, true);
    }

    private static function GetDomain(){
        $url = '';
        if(isset($_SERVER['HTTP_HOST'])){
            $url = $_SERVER['HTTP_HOST'];
        }else if(isset($_SERVER['SERVER_NAME'])){
            $url = $_SERVER['SERVER_NAME'];
        }else if(isset($_SERVER['SERVER_ADDR'])){
            $url = $_SERVER['SERVER_ADDR'];
        }

        $url = in_array($url, ['0.0.0.0', '::1'])? 'localhost': $url;

        $pieces = parse_url($url);
        $domain = isset($pieces['host'])? $pieces['host']: (isset($pieces['path'])? $pieces['path']: '');
        
        if(preg_match('/(?P<domain>[a-z0-9][a-z0-9\-]{1,63}\.[a-z\.]{2,6})$/i', $domain, $regs)){
            return '.'.$regs['domain'];
        }

        return $domain;
    }

    private function IsThrottled() {
        if(!empty($this->proxy) && $this->proxy->auth_throttle > 0){
            if(!isset($_COOKIE['sso_last_auth'])){
                $this->SetNextThrottlingTime();
            }

            $now = time();
            $last_auth = (int)$_COOKIE['sso_last_auth'];
            if(($now - $last_auth) <= $this->proxy->auth_throttle){
                return true;
            }
        }

        return false;
    }

    private function SetNextThrottlingTime(){
        if(!empty($this->proxy) && $this->proxy->auth_throttle > 0){
            setcookie('sso_last_auth', time(), time() + ($this->proxy->auth_throttle * 2), '/', $this->GetDomain(), false, true);
        }
    }
}