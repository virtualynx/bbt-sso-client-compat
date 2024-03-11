<?php

namespace Bbt\Sso;

class Proxy {
    public $proxy_url;
    public $proxy_username;
    public $proxy_password;
    public $auth_throttle;

    function __construct(
        $proxy_url,
        $proxy_username = '', $proxy_password = '',
        $auth_throttle = 0
    ){
        $this->proxy_url = $proxy_url;
        $this->proxy_username = $proxy_username;
        $this->proxy_password = $proxy_password;
        $this->auth_throttle = $auth_throttle;
    }
}