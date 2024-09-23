<?php

namespace Bbt\Sso;

class HttpClient {
    private $proxy;

    function __construct(Proxy $proxy = null){
        $this->proxy = $proxy;
    }

    public function post($url, $params, $headers = []){
        $curl = curl_init($url);
        
        curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($curl, CURLOPT_FAILONERROR, false);
        curl_setopt($curl, CURLOPT_CONNECTTIMEOUT, 30);
        curl_setopt($curl, CURLOPT_TIMEOUT, 60);

        if(!empty($params)){
            curl_setopt($curl, CURLOPT_POSTFIELDS, $params);
        }

        if(!empty($headers)){
            curl_setopt($curl, CURLOPT_HTTPHEADER, $headers);
        }

        if(!empty($this->proxy)){
            curl_setopt($curl, CURLOPT_PROXY, $this->proxy->proxy_url);
            if(!empty($this->proxy->proxy_username)){
                $proxyUsername = $this->proxy->proxy_username;
                $proxyPassword = $this->proxy->proxy_password;
                curl_setopt($curl, CURLOPT_PROXYUSERPWD, "$proxyUsername:$proxyPassword");
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

    public function get($url, $params, $headers = [], $body = ''){
        $strs = [];
        foreach($params as $key => $value){
            $encoded_value = urlencode($value);
            $strs []= "$key=$encoded_value";
        }
        $strs = implode('&', $strs);

        $curl = curl_init($url.(!empty($strs)? "?$strs": ''));

        curl_setopt($curl, CURLOPT_CUSTOMREQUEST, 'GET');
        if(!empty($body)){
            curl_setopt($curl, CURLOPT_POSTFIELDS, $body);
        }
        
        curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($curl, CURLOPT_FAILONERROR, false);
        curl_setopt($curl, CURLOPT_CONNECTTIMEOUT, 30);
        curl_setopt($curl, CURLOPT_TIMEOUT, 60);

        if(!empty($headers)){
            curl_setopt($curl, CURLOPT_HTTPHEADER, $headers);
        }

        if(!empty($this->proxy)){
            curl_setopt($curl, CURLOPT_PROXY, $this->proxy->proxy_url);
            if(!empty($this->proxy->proxy_username)){
                $proxyUsername = $this->proxy->proxy_username;
                $proxyPassword = $this->proxy->proxy_password;
                curl_setopt($curl, CURLOPT_PROXYUSERPWD, "$proxyUsername:$proxyPassword");
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
}