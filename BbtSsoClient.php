<?php
/**
 * For PHP >= 5.4.0
 */
class BbtSsoClient {
    private $sso_url;
    private $client_id;

    function __construct($sso_url, $client_id){
        $this->sso_url = $sso_url;
        $this->client_id = $client_id;
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

        if(empty($_SESSION['pkce_verifier'])){
			header("HTTP/1.1 401 PKCE Verifier is missing");exit;
        }

        try{
            $resp = $this->HttpPost($this->sso_url.'/get_token', [
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

        try{
            $resp = $this->HttpPost($this->sso_url.'/authorize', [
                'client_id' => $this->client_id,
                'access_token' => $this->GetToken('access_token')
            ]);
            if($resp){
                $json_resp = json_decode($resp);
                if($json_resp->status != 'ok'){
                    throw new Exception("Authorization Failed: $resp");
                }
            }
        }catch(Exception $e){
            if($e->getMessage() == '401 Expired'){ //access token is expired
                $this->RefreshToken();
            }else{
                throw $e;
            }
        }
    }

    private function RefreshToken(){
        try{
            $resp = $this->HttpPost($this->sso_url.'/authorize', [
                'client_id' => $this->client_id,
                'refresh_token' => $this->GetToken('refresh_token')
            ]);
            if($resp){
                $json_resp = json_decode($resp);
                if($json_resp->status == 'ok'){
                    // session_regenerate_id();
                    $_SESSION['sso']['access_token'] = $json_resp->access_token;
                }else{
                    throw new Exception("Refresh Authorization Failed: $resp");
                }
            }
        }catch(Exception $e){
            if($e->getMessage() == '401 Expired'){ //refresh token is expired
                session_destroy();
                $this->LoginPage([
                    'alert' => 'Your session is expired, please login again !'
                ]);
            }
        }
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
        
        $curlResponse = curl_exec($curl);
        $error_no = '';
        $error_msg = '';
        if(($error_no = curl_errno($curl))) {
            $error_msg = curl_error($curl);
        }
        curl_close($curl);

        if(!empty($error_no)){
            $split1 = explode(':', $error_msg);
            $error_msg2 = trim($split1[1]);
            throw new Exception($error_msg2);
        }

        return $curlResponse;
    }
}