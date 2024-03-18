<?php

namespace Bbt\Sso;

require_once "Encrypter.php";
require_once "HttpClient.php";
require_once "JWT.php";
require_once "Proxy.php";

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
    private const SILENT_LOGOUT_REASONS = [
        'Missing access and refresh token',
        'Missing access_token',
        'Missing refresh_token',
        'Expired session'
    ];
    private const MSG_SESSION_EXPIRED = 'Your session is expired, please login again !';

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

    function LoginPage($params = null, $redirectLoginPage = true){
        $verifier = self::GenerateRandomString(64);
        setcookie('pkce_verifier', $verifier, time() + (60*60*24 * 3), '/', $this->GetDomain(), false, true);

        $challenge = base64_encode(hash('sha256', $verifier));
        
        if(empty($params)){
            $params = [];
        }
        $params['client_id'] = $this->client_id;
        $params['response_type'] = 'code';
        $params['challenge'] = $challenge;
        $params['challenge_method'] = 's256';
        
        $strs = [];
        foreach($params as $key => $value){
            $encoded_value = urlencode($value);
            $strs []= "$key=$encoded_value";
        }
        $login_url = "$this->sso_url/login?".(implode('&', $strs));

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
            setcookie('pkce_verifier', '', time() - 1, '/', self::GetDomain(), false, true);

            $resp = $this->http_client->post(
                $this->GetSsoUrl().'/token', 
                [
                    'grant_type' => 'authorization_code',
                    'code' => $_GET['code'],
                    'verifier' => $pkce_verifier
                ]
            );
            if($resp){
                $json = json_decode($resp);
                if($json->status != 'success'){
                    throw new \Exception($json->status, 500);
                }
                self::SaveTokens($json->token_data);

                return $json->user;
            }

            throw new \Exception('Empty response from Code-Exchange API', 500);
        }catch(\Exception $e){
            if($e->getCode() == 401 && $e->getMessage() == 'PKCE challenge failed'){
                $this->LoginPage(['alert' => 'Login failed, make sure not to open multiple SSO-Login Page at once']);
            }

            throw $e;
        }
    }

    /**
     * Call this to check the validity of the tokens and SSO's shared-session
     */
    function AuthCheck($autoRedirectLogin = true){
        if($this->IsThrottled()){
            return true;
        }

        try{
            $access_token = self::GetToken('access_token');
            $resp = $this->http_client->post(
                $this->GetSsoUrl().'/token', 
                ['grant_type' => 'verify'], 
                ["Authorization: Bearer $access_token"]
            );
            if($resp){
                $json = json_decode($resp);
                if($json->status != 'success'){
                    throw new \Exception("Auth check failed: $resp");
                }
                $this->SetNextThrottlingTime();

                return true;
            }

            throw new \Exception('Empty response from Authentication API', 500);
        }catch(\Exception $e){
            if($e->getCode() == 401){
                if($e->getMessage() == 'Expired token'){ //access token is expired
                    return $this->RefreshToken($autoRedirectLogin);
                }else{
                    $this->RevokeTokens();
                    $alert = '';
                    $result = null;
                    if(in_array($e->getMessage(), self::SILENT_LOGOUT_REASONS)){
                        $alert = self::MSG_SESSION_EXPIRED;
                        $result = false;
                    }else{
                        $alert = $e->getMessage();
                        $result = $e->getMessage();
                    }
                    if($autoRedirectLogin){
                        $loginParams = ['alert' => $alert];
                        if(!empty($_SERVER['HTTP_REFERER'])){
                            $loginParams['redirect'] = $_SERVER['HTTP_REFERER'];
                        }
                        $this->LoginPage($loginParams);
                    }

                    return $result;
                }
            }

            throw $e;
        }
    }
    
    private function RefreshToken($autoRedirectLogin){
        try{
            $refresh_token = self::GetToken('refresh_token');
            $resp = $this->http_client->post(
                $this->GetSsoUrl().'/token', 
                ['grant_type' => 'refresh'], 
                ["Authorization: Bearer $refresh_token"]
            );
            if($resp){
                $json = json_decode($resp);
                if($json->status == 'success'){
                    self::SaveTokens($json->data);
                    $this->SetNextThrottlingTime();

                    return true;
                }else{
                    throw new \Exception("Auth check failed: $resp");
                }
            }

            throw new \Exception('Empty response from Authentication API', 500);
        }catch(\Exception $e){
            if($e->getCode() == 401){
                $alert_msg = '';
                if(in_array($e->getMessage(), ['Expired token', 'Expired session'])){ //refresh token is expired
                    $alert_msg = self::MSG_SESSION_EXPIRED;
                }
                $this->RevokeTokens();
                if($autoRedirectLogin){
                    $loginParams = ['alert' => $alert_msg];
                    if(!empty($_SERVER['HTTP_REFERER'])){
                        $loginParams['redirect'] = $_SERVER['HTTP_REFERER'];
                    }
                    $this->LoginPage($loginParams);
                }

                return false;
            }
            
            throw $e;
        }
    }

    /**
     * Option for authenticating your api-app
     */
    function AuthGrantClientCredentials(){
        try{
            $credential = base64_encode($this->client_id.':'.$this->client_secret);
            $resp = $this->http_client->post(
                $this->GetSsoUrl().'/token', 
                ['grant_type' => 'client_credentials'], 
                ["Authorization: Basic $credential"]
            );
            if($resp){
                $json = json_decode($resp);
                if($json->status != 'success'){
                    throw new \Exception("Auth Type Client-Credentials failed: $resp");
                }

                return true;
            }

            throw new \Exception('Empty response from Authentication API', 500);
        }catch(\Exception $e){
            throw $e;
        }
    }

    function GetUserInfo(){
        $this->AuthCheck();

        try{
            $access_token = self::GetToken('access_token');
            $resp = $this->http_client->post(
                $this->GetSsoUrl().'/userinfo', 
                ['client_id' => $this->client_id], 
                ["Authorization: Bearer $access_token"]
            );
            if($resp){
                $json = json_decode($resp);
                if($json->status != 'success'){
                    throw new \Exception("Get User Info failed: $resp");
                }
                
                return $json->user;
            }

            throw new \Exception('Empty response from User-info API', 500);
        }catch(\Exception $e){
            throw $e;
        }
    }

    public function RevokeTokens(){
        $domain = self::GetDomain();
        setcookie(self::ACCESS_TOKEN_NAME, '', time()-1, '/', $domain, false, true);
        setcookie(self::REFRESH_TOKEN_NAME, '', time()-1, '/', $domain, false, true);
    }

    public function Logout($redirectLoginPage = true){
        try{
            $access_token = self::GetToken('access_token');
            $this->RevokeTokens();
            $resp = $this->http_client->post(
                $this->GetSsoUrl().'/logout', 
                [], 
                ["Authorization: Bearer $access_token"]
            );
            if($resp){
                $json = json_decode($resp);
                if($json->status != 'success'){
                    throw new \Exception("SLO failed: $resp");
                }
            }else{
                throw new \Exception('Empty response from Logout API', 500);
            }
        }catch(\Exception $e){
            if($e->getCode() != 401){
                throw $e;
            }
        }

        return $this->LoginPage(['alert' => 'You have been logged-out'], $redirectLoginPage);
    }

    private function GetSsoUrl(){
        return !empty($this->sso_url_local)? $this->sso_url_local: $this->sso_url;
    }

    private static function GetToken($name){
        $token_keymap = [
            'access_token' => self::ACCESS_TOKEN_NAME,
            'refresh_token' => self::REFRESH_TOKEN_NAME
        ];
        
        if(empty($_COOKIE[self::ACCESS_TOKEN_NAME]) && empty($_COOKIE[self::REFRESH_TOKEN_NAME])) {
            throw new \Exception('Missing access and refresh token', 401);
        }

        $tag = $token_keymap[$name];
        if(empty($_COOKIE[$tag])) {
            if($name == 'access_token' && !empty($_COOKIE[self::REFRESH_TOKEN_NAME])){
                throw new \Exception('Expired token', 401);
            }
            throw new \Exception("Missing $name", 401);
        }

        return $_COOKIE[$tag];
    }

    private static function SaveTokens($data){
        $domain = self::GetDomain();

        $access_token_age = (int)(1.5 * (float)$data->access_token_expires_in);
        setcookie(self::ACCESS_TOKEN_NAME, $data->access_token, time() + $access_token_age, '/', $domain, false, true);

        $refresh_token_age = (int)(1.5 * (float)$data->refresh_token_expires_in);
        setcookie(self::REFRESH_TOKEN_NAME, $data->refresh_token, time() + $refresh_token_age, '/', $domain, false, true);
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

        $url = in_array($url, ['127.0.0.1', '0.0.0.0', '::1'])? 'localhost': $url;

        $pieces = parse_url($url);
        $domain = isset($pieces['host'])? $pieces['host']: (isset($pieces['path'])? $pieces['path']: '');
        
        if(preg_match('/(?P<domain>[a-z0-9][a-z0-9\-]{1,63}\.[a-z\.]{2,6})$/i', $domain, $regs)){
            return '.'.$regs['domain'];
        }

        return $domain;
    }
    
	private static function GenerateRandomString($length){
		return bin2hex(random_bytes(($length-($length%2))/2));
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
            setcookie('sso_last_auth', time(), time() + ($this->proxy->auth_throttle * 2), '/', self::GetDomain(), false, true);
        }
    }
}