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
    private $proxy_url;
    private $proxy_username;
    private $proxy_password;
    private $auth_throttle;
    private $token_keymap = [
        'access_token' => 'mwsat',
        'refresh_token' => 'mwsrt',
    ];
    private $token_ages = [
        'access_token' => (60*3),
        'refresh_token' => (60*60*12)
    ];

    function __construct(
        $sso_url, $client_id, $client_secret,
        $sso_url_local = '',
        $proxy_url = '',
        $proxy_username = '', $proxy_password = '',
        $auth_throttle = 0
    ){
        $this->sso_url = $sso_url;
        $this->client_id = $client_id;
        $this->client_secret = $client_secret;
        $this->sso_url_local = $sso_url_local;
        $this->proxy_url = $proxy_url;
        $this->proxy_username = $proxy_username;
        $this->proxy_password = $proxy_password;
        $this->auth_throttle = $auth_throttle;
    }

    function LoginPage($params = []){
        $code_length = 64;
		$verifier = bin2hex(random_bytes(($code_length-($code_length%2))/2));
        setcookie('pkce_verifier', $verifier, time() + (60*60*24 * 3), "/", $this->GetSsoDomain(), false, true);

        $challenge = base64_encode(hash('sha256', $verifier));
        
        $params['client_id'] = $this->client_id;
        $params['challenge'] = $challenge;
        $params['challenge_method'] = 's256';

        $login_url = $this->sso_url;
        if(count($params) > 0){
            $strs = [];
            foreach($params as $key => $value){
                $encoded_value = urlencode($value);
                $strs []= "$key=$encoded_value";
            }
            $login_url .= '?'.(implode('&', $strs));
        }
        header("Location: $login_url");
        exit();
    }

    function SsoCallbackHandler(){
        if(!isset($_GET['code'])){
            throw new \Exception('Invalid call, missing "code"');
        }

        if(!isset($_COOKIE['pkce_verifier'])){
            $this->LoginPage(['alert' => 'You left your login-page open for a long period of time. Please try logging in again !']);
        }

        try{
            $pkce_verifier = $_COOKIE['pkce_verifier'];
            setcookie('pkce_verifier', '', time() - 1, "/", $this->GetSsoDomain(), false, true);

            $resp = $this->HttpPost($this->GetBaseUrl().'/get_token', [
                'code' => $_GET['code'],
                'verifier' => $pkce_verifier
            ]);
            if($resp){
                $json_resp = json_decode($resp);
                
                $this->SaveToken('access_token', $json_resp->access_token);
                $this->SaveToken('refresh_token', $json_resp->refresh_token);

                return $json_resp->user;
            }
        }catch(\Exception $e){
            throw $e;
        }

        return null;
    }

    /**
     * 
     */
    function Auth(){
        if($this->IsThrottled()){
            return;
        }

        try{
            $access_token = $this->GetToken('access_token');
            $resp = $this->HttpPost($this->GetBaseUrl().'/authorize', [
                'client_id' => $this->client_id,
                'access_token' => $access_token
            ]);
            if($resp){
                $json_resp = json_decode($resp);
                if($json_resp->status != 'ok'){
                    throw new \Exception("Authorization Failed: $resp");
                }
                $this->SetNextThrottlingTime();
            }
        }catch(\Exception $e){
            if($e->getCode() == 401){
                if($e->getMessage() == 'expired'){ //access token is expired
                    $this->RefreshToken();
                }else{ //401 error, the cause is being logged in SSO server
                    $this->Logout(['alert' => 'Your session is expired(401-access), please login again ! ('.$e->getMessage().')']);
                }
            }else{
                throw $e;
            }
        }
    }

    function GetUserInfo(){
        $this->Auth();

        try{
            $resp = $this->HttpPost($this->GetBaseUrl().'/userinfo', [
                'client_id' => $this->client_id,
                'access_token' => $this->GetToken('access_token')
            ]);
            if($resp){
                $json_resp = json_decode($resp);
                if($json_resp->status != 'success'){
                    throw new \Exception("Get User Info failed: $resp");
                }
                
                return $json_resp->employee;
            }
        }catch(\Exception $e){
            // if($e->getCode() == 401){
            //     if($e->getMessage() == 'expired'){ //access token is expired
            //         $this->RefreshToken();
            //     }else{ //401 error, the cause is being logged in SSO server
            //         $this->Logout(['alert' => 'Your session is expired(401-access), please login again ! ('.$e->getMessage().')']);
            //     }
            // }else{
            //     throw $e;
            // }
            throw $e;
        }

        throw new \Exception('userinfo endpoint return no data');
    }

    function CheckSharedSession(){

    }

    private function RefreshToken(){
        try{
            $refresh_token = $this->GetToken('refresh_token');
            $resp = $this->HttpPost($this->GetBaseUrl().'/authorize', [
                'client_id' => $this->client_id,
                'refresh_token' => $refresh_token
            ]);
            if($resp){
                $json_resp = json_decode($resp);
                if($json_resp->status == 'ok'){
                    $this->SaveToken('access_token', $json_resp->access_token);
                    $this->SetNextThrottlingTime();
                }else{
                    throw new \Exception("Refresh Authorization Failed: $resp");
                }
            }
        }catch(\Exception $e){
            if($e->getCode() == 401){
                $alert_msg = '';
                if($e->getMessage() == 'expired'){ //refresh token is expired
                    $alert_msg = 'Your session is expired, please login again !';
                }else{ //401 error, the cause is being logged in SSO server
                    $alert_msg = 'Your session is expired(401-refresh), please login again ! ('.$e->getMessage().')';
                }
                $this->Logout(['alert' => $alert_msg]);
            }else{
                throw $e;
            }
        }
    }

    public function RevokeTokens(){
        setcookie($this->token_keymap['access_token'], '', time()-1, "/", $this->GetSsoDomain(), false, true);
        setcookie($this->token_keymap['refresh_token'], '', time()-1, "/", $this->GetSsoDomain(), false, true);
    }

    public function Logout($loginPageParams = []){
        // session_destroy();
        $this->RevokeTokens();
                
        $this->LoginPage($loginPageParams);
    }

    private function GetBaseUrl(){
        return !empty($this->sso_url_local)? $this->sso_url_local: $this->sso_url;
    }

    private function GetToken($name){
        // if(session_status() === PHP_SESSION_NONE || empty($_SESSION['sso']) || empty($_SESSION['sso'][$name])){
        //     $this->LoginPage();
        // }
        
        // return $_SESSION['sso'][$name];
        
        if(empty($_COOKIE[$this->token_keymap['access_token']]) && empty($_COOKIE[$this->token_keymap['refresh_token']])) {
            $this->LoginPage();
        }

        $tag = $this->token_keymap[$name];

        if(empty($_COOKIE[$tag])) {
            throw new \Exception('expired', 401);
        }

        return $_COOKIE[$tag];
    }

    private function SaveToken($name, $token){
        setcookie($this->token_keymap[$name], $token, time() + $this->token_ages[$name], "/", $this->GetSsoDomain(), false, true);
    }

	private function GetSsoDomain(){
		$parse = parse_url($this->sso_url);

		return $parse['host'];
	}

    private function HttpPost($url, $params){
        $curl = curl_init($url);
        curl_setopt($curl, CURLOPT_POSTFIELDS, $params);
        curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($curl, CURLOPT_FAILONERROR, false);
        curl_setopt($curl, CURLOPT_CONNECTTIMEOUT, 30);
        curl_setopt($curl, CURLOPT_TIMEOUT, 60);

        if(!empty($this->proxy_url)){
            curl_setopt($curl, CURLOPT_PROXY, $this->proxy_url);
            if(!empty($this->proxy_username)){
                curl_setopt($curl, CURLOPT_PROXYUSERPWD, "$this->proxy_username:$this->proxy_password");
            }
        }
        
        $curlResponse = curl_exec($curl);
        $http_resp_code = curl_getinfo($curl, CURLINFO_RESPONSE_CODE);
        
        $error_no = '';
        $error_msg = '';
        if(($error_no = curl_errno($curl))) {
            $error_msg = curl_error($curl);
        }
        curl_close($curl);

        if($http_resp_code >= 400){
            $msg = !empty($curlResponse)? $curlResponse: $error_msg;
            throw new \Exception($msg, $http_resp_code);
        }else if($error_no != 0){
            throw new \Exception($error_msg, $error_no);
        }

        return $curlResponse;
    }

    private function IsThrottled() {
        if($this->auth_throttle > 0){
            if(!isset($_COOKIE['sso_last_auth'])){
                $this->SetNextThrottlingTime();
            }

            $now = time();
            $last_auth = (int)$_COOKIE['sso_last_auth'];
            if(($now - $last_auth) <= $this->auth_throttle){
                return true;
            }
        }

        return false;
    }

    private function SetNextThrottlingTime(){
        setcookie('sso_last_auth', time(), time() + ($this->auth_throttle * 2), "/", $this->GetSsoDomain(), false, true);
    }
}