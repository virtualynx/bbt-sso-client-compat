<?php
/**
 * For PHP >= 5.4.0
 */
class BbtSsoClient {
    private $sso_url;
    private $client_id;
    private $sso_url_local;
    private $proxy_url;
    private $proxy_username;
    private $proxy_password;
    private $auth_throttle;

    function __construct(
        $sso_url, $client_id, 
        $sso_url_local = '',
        $proxy_url = '',
        $proxy_username = '', $proxy_password = '',
        $auth_throttle = 0
    ){
        $this->sso_url = $sso_url;
        $this->client_id = $client_id;
        $this->sso_url_local = $sso_url_local;
        $this->proxy_url = $proxy_url;
        $this->proxy_username = $proxy_username;
        $this->proxy_password = $proxy_password;
        $this->auth_throttle = $auth_throttle;
    }

    function LoginPage($params = []){
        if(session_status() === PHP_SESSION_NONE) {
            session_start();
        }else{
            session_regenerate_id();
        }

		$code_length = 64;
		$verifier = bin2hex(random_bytes(($code_length-($code_length%2))/2));
        $_SESSION['pkce_verifier'] = $verifier;

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
            throw new Exception('Invalid call, missing "code"');
        }

        if(empty($_SESSION['pkce_verifier'])){ //might be caused by session timeout/by clearing browser's cache
            // header("HTTP/1.1 401 PKCE Verifier is missing");exit;
            $this->LoginPage(['error' => 'You left your login-page open for a long period of time. Please try logging in again !']);
        }

        try{
            $resp = $this->HttpPost($this->GetBaseUrl().'/get_token', [
                'code' => $_GET['code'],
                'verifier' => $_SESSION['pkce_verifier']
            ]);
            if($resp){
                $json_resp = json_decode($resp);
                
                session_regenerate_id();

                if(!isset($_SESSION['sso'])){
                    $_SESSION['sso'] = [];
                }
                $_SESSION['sso']['access_token'] = $json_resp->access_token;
                $_SESSION['sso']['refresh_token'] = $json_resp->refresh_token;

                return $json_resp->employee;
            }
        }catch(Exception $e){
            throw $e;
        }

        return null;
    }

    /**
     * 
     */
    function Auth(){
        if(session_status() === PHP_SESSION_NONE) {
            $this->LoginPage();
        }

        if($this->auth_throttle > 0){
            if(!isset($_SESSION['sso']['last_auth'])){
                $_SESSION['sso']['last_auth'] = time();
            }

            $now = time();
            $last_auth = (int)$_SESSION['sso']['last_auth'];
            if(($now - $last_auth) <= $this->auth_throttle){
                return;
            }
        }

        try{
            $resp = $this->HttpPost($this->GetBaseUrl().'/authorize', [
                'client_id' => $this->client_id,
                'access_token' => $this->GetToken('access_token')
            ]);
            if($resp){
                $json_resp = json_decode($resp);
                if($json_resp->status != 'ok'){
                    throw new Exception("Authorization Failed: $resp");
                }
                if($this->auth_throttle > 0){
                    $_SESSION['sso']['last_auth'] = time();
                }
            }
        }catch(Exception $e){
            if($e->getCode() == 401){
                if($this->endsWith($e->getMessage(), ': 401 Expired')){ //access token is expired
                    $this->RefreshToken();
                }else{ //401 error, the cause is being logged in SSO server
                    $this->Logout(['alert' => 'Your session is expired(401), please login again !']);
                }
            }else{
                throw $e;
            }
        }
    }

    private function RefreshToken(){
        try{
            $resp = $this->HttpPost($this->GetBaseUrl().'/authorize', [
                'client_id' => $this->client_id,
                'refresh_token' => $this->GetToken('refresh_token')
            ]);
            if($resp){
                $json_resp = json_decode($resp);
                if($json_resp->status == 'ok'){
                    // session_regenerate_id();
                    $_SESSION['sso']['access_token'] = $json_resp->access_token;
                    if($this->auth_throttle > 0){
                        $_SESSION['sso']['last_auth'] = time();
                    }
                }else{
                    throw new Exception("Refresh Authorization Failed: $resp");
                }
            }
        }catch(Exception $e){
            if($e->getCode() == 401){
                $alert_msg = 'Your session is expired, please login again !';
                if($this->endsWith($e->getMessage(), ': 401 Expired')){ //refresh token is expired
                    $alert_msg = 'Your session is expired, please login again !';
                }else{ //401 error, the cause is being logged in SSO server
                    $alert_msg = 'Your session is expired(401), please login again !';
                }
                $this->Logout(['alert' => $alert_msg]);
            }else{
                throw $e;
            }
        }
    }

    private function Logout($loginPageParams = []){
        session_destroy();
        $this->LoginPage($loginPageParams);
    }

    private function GetBaseUrl(){
        return !empty($this->sso_url_local)? $this->sso_url_local: $this->sso_url;
    }

    private function GetToken($name){
        if(session_status() === PHP_SESSION_NONE || empty($_SESSION['sso']) || empty($_SESSION['sso'][$name])){
            $this->LoginPage();
        }
        
        return $_SESSION['sso'][$name];
    }

    private function HttpPost($url, $params){
        $curl = curl_init($url);
        curl_setopt($curl, CURLOPT_POSTFIELDS, $params);
        curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($curl, CURLOPT_FAILONERROR, true);
        curl_setopt($curl, CURLOPT_CONNECTTIMEOUT, 30); 
        curl_setopt($curl, CURLOPT_TIMEOUT, 120);

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
            throw new Exception($error_msg, $http_resp_code);
        }else if($error_no != 0){
            throw new Exception($error_msg, $error_no);
        }

        return $curlResponse;
    }

    private function endsWith($haystack, $needle) {
        return substr_compare($haystack, $needle, -strlen($needle)) === 0;
    }
}