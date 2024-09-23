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
    private $failover_url;
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
        $sso_url, 
        $client_id, $client_secret,
        $failover_url = null,
        $proxy = null
    ){
        $this->sso_url = $sso_url;
        $this->client_id = $client_id;
        $this->client_secret = $client_secret;
        $this->failover_url = $failover_url;
        $this->proxy = $proxy;
        $this->http_client = new HttpClient($proxy);
    }

    function LoginPage($params = null, $redirectLoginPage = true){
        $verifier = null;
        if(!empty($_COOKIE['pkce_verifier'])){
            $verifier = $_COOKIE['pkce_verifier'];
        }else{
            $verifier = self::GenerateRandomString(64);
            self::_SetCookie('pkce_verifier', $verifier, time() + (60*60*24 * 3), '/', $this->GetDomain(), false, false);
        }

        $challenge = base64_encode(hash('sha256', $verifier));
        
        if(empty($params)){
            $params = [];
        }
        $params['client_id'] = $this->client_id;
        $params['response_type'] = 'code';
        $params['challenge'] = $challenge;
        $params['challenge_method'] = 's256';

        $login_url = "$this->sso_url/login?".self::AssocToUrlParams($params);

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
        if(!empty($_GET['code'])){
            $params = [];
            if(!empty($_GET['redirect'])){
                $params['redirect'] = $_GET['redirect'];
            }

            if(!isset($_COOKIE['pkce_verifier'])){
                $params['alert'] = 'You left your login-page open for a long period of time. Please try logging in again !';
                $this->LoginPage($params);
            }

            $pkce_verifier = $_COOKIE['pkce_verifier'];
            self::_SetCookie('pkce_verifier', '', -1);

            $params['grant_type'] = 'authorization_code';
            $params['code'] = $_GET['code'];
            $params['verifier'] = $pkce_verifier;
    
            header("Location: $this->sso_url/token2?".self::AssocToUrlParams($params));
            exit;
        }else if(!empty($_GET['login_status'])){
            $user = null;
            if($_GET['login_status'] == 'success'){
                $user = json_decode(urldecode($_GET['user']));
            }

            return $user;
        }else{
            throw new \Exception('Invalid call, neither parameter "code", or "login_status" is to be found !');
        }
    }

    /**
     * Call this to check the validity of the tokens and SSO's shared-session
     */
    function AuthCheck($autoRedirectLogin = true){
        if($this->IsThrottled()){
            return true;
        }

        //for redirection methods
        // $current_url = (empty($_SERVER['HTTPS']) ? 'http' : 'https')."://".$_SERVER['HTTP_HOST'].$_SERVER['REQUEST_URI'];

        try{
            $access_token = self::GetToken('access_token');
            $resp = $this->http_client->get(
                $this->GetSsoEndpoint().'/token2', 
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
                }else{}
            }
        }
    }
    
    private function RefreshToken($autoRedirectLogin){
        try{
            $refresh_token = self::GetToken('refresh_token');
            $resp = $this->http_client->get(
                $this->GetSsoEndpoint().'/token2', 
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
    // function AuthGrantClientCredentials(){
    //     try{
    //         $credential = base64_encode($this->client_id.':'.$this->client_secret);
    //         $resp = $this->http_client->post(
    //             $this->GetSsoEndpoint().'/token', 
    //             ['grant_type' => 'client_credentials'], 
    //             ["Authorization: Basic $credential"]
    //         );
    //         if($resp){
    //             $json = json_decode($resp);
    //             if($json->status != 'success'){
    //                 throw new \Exception("Auth Type Client-Credentials failed: $resp");
    //             }

    //             return true;
    //         }

    //         throw new \Exception('Empty response from Authentication API', 500);
    //     }catch(\Exception $e){
    //         throw $e;
    //     }
    // }

    function GetUserInfo(){
        $this->AuthCheck();

        try{
            $access_token = self::GetToken('access_token');
            $resp = $this->http_client->post( 
                $this->GetSsoEndpoint().'/userinfo', 
                ['client_id' => $this->client_id], 
                ["Authorization: Bearer $access_token"]
            );
            if($resp){
                $json = json_decode($resp);
                if(empty($json) || $json->status != 'success'){
                    throw new \Exception("Get User Info failed: $resp");
                }
                
                return $json->user;
            }

            throw new \Exception('Empty response from User-info API', 500);
        }catch(\Exception $e){
            if($e->getCode() == 401){
                header("Refresh:0"); //refresh pages to get the refreshed token value (which fetched upon AuthCheck() above)
            }

            throw $e;
        }
    }

    public function RevokeTokens(){
        $domain = self::GetDomain();
        setcookie(self::ACCESS_TOKEN_NAME, '', time()-1, '/', $domain, false, false);
        setcookie(self::REFRESH_TOKEN_NAME, '', time()-1, '/', $domain, false, false);
    }

    public function Logout($redirectLoginPage = true){
        $token = null;

        try{
            $token = self::GetToken('access_token');
        }catch(\Exception $e){}
        
        if(empty($token)){
            try{
                $token = self::GetToken('refresh_token');
            }catch(\Exception $e){}
        }
        $this->RevokeTokens();

        if(!empty($token)){
            $resp = $this->http_client->post(
                $this->GetSsoEndpoint().'/logout', 
                [], 
                ["Authorization: Bearer $token"]
            );
            if($resp){
                $json = json_decode($resp);
                if($json->status != 'success'){
                    throw new \Exception("SLO failed: $resp");
                }
            }else{
                throw new \Exception('Empty response from Logout API', 500);
            }
        }

        return $this->LoginPage(['alert' => 'You have been logged-out'], $redirectLoginPage);
    }

    private function GetSsoEndpoint(){
        return !empty($this->failover_url)? $this->failover_url: $this->sso_url;
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
        // $cookie_opts = [
        //     'expires' => time() + 60 * 60 * 12,
        //     'samesite' => 'lax',
        //     'secure' => false,
        //     'httponly' => true
        // ];
        $cookie_opts = [
            'expires' => time() + 60 * 60 * 12,
            'samesite' => 'strict',
            'secure' => false,
            'httponly' => false
        ];
        self::_SetCookie(self::ACCESS_TOKEN_NAME, $data->access_token, $cookie_opts);
        self::_SetCookie(self::REFRESH_TOKEN_NAME, $data->refresh_token, $cookie_opts);
    }

    private static function _SetCookie($name, $value, $expires_or_options , $path = '/', $domain = '', $secure = false, $httponly = false){
        $cookie_arr = [
            $name => $value
        ];

        $expires_time = -1;
        if(is_array($expires_or_options)){
            foreach($expires_or_options as $row_name => $row_value){
                if($row_name == 'expires'){
                    $expires_time = $row_value;
                }else{
                    $cookie_arr[$row_name]= $row_value;
                }
            }
        }else{
            $expires_time = $expires_or_options;
            $cookie_arr['path']= $path;
            $cookie_arr['domain']= $domain;
            $cookie_arr['secure']= $secure;
            $cookie_arr['httponly']= $httponly;
        }

        if(!array_key_exists('path', $cookie_arr)){
            $cookie_arr['path']= '/';
        }
        if(!array_key_exists('domain', $cookie_arr)){
            $cookie_arr['domain']= self::GetDomain();
        }
        if(!array_key_exists('samesite', $cookie_arr)){
            $cookie_arr['samesite']= 'lax';
        }
        if($expires_time > 0){
            $expires = time() + 60 * 60 * 12;
        }else{
            $expires = time() * -1;
        }

        $dateTime = new \DateTime();
        $dateTime->setTimestamp($expires);
        $dateTime->setTimezone(new \DateTimeZone(date_default_timezone_get()));
        $expiresText = $dateTime->format('D, d M Y H:i:s e');
        $cookie_arr['expires']= $expiresText;

        $cookie_sets = [];
        foreach($cookie_arr as $row_key => $row_value){
            if($row_key == 'secure'){
                if($row_value == true){
                    $cookie_sets []= 'secure';
                }
            }else if($row_key == 'httponly'){
                if($row_value == true){
                    $cookie_sets []= 'httponly';
                }
            }else{
                $cookie_sets []= "$row_key=$row_value";
            }
        }
        $cookie_str = implode('; ', $cookie_sets);
        
        header("Set-Cookie: $cookie_str", false);
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

    private static function AssocToUrlParams($params){
        $strs = [];
        foreach($params as $key => $value){
            $encoded_value = urlencode($value);
            $strs []= "$key=$encoded_value";
        }

        return implode('&', $strs);
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