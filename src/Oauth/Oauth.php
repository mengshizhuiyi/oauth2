<?php
namespace Oauth;


class Oauth{
    
	//加解密使用的key
	const ENCRYPT_KEY = 'oauth';
	const STR = '123457890qwertyuiopasdfghjklzxcvbnm123457890qwertyuiopasdfghjklzxcvbnm123457890qwertyuiopasdfghjklzxcvbnm';
	private $redis_oauth_access_token_key 	= 'oauth_expires_access_token_';    //oauth2.0 各个账号使用的key
	
	//appid
	public $appid = '';
	public $secret = '';
	
	public function __construct($appid = '', $secret = '')
	{
	    $this->appid = $appid;
	    $this->secret = $secret;
	}
	
	/**
	 * 根据appid加密特定的数据
	 */
	public function encryptData($str)
	{
	    $en_str = $str . '_' . $this->appid;
	    return $this->o_encrypt($en_str);
	}
	
	/**
	 * 解密数据
	 */
	public function decryptData($str)
	{
	    $de_str = $this->o_decrypt($str);
	    $de_arr = explode('_', $de_str);
	    $key_num = count($de_arr);
	    unset($de_arr[$key_num - 1]);
	    return implode('_', $de_arr);
	}
	
	/**
	 * 创建access_token（根据appid获取access_token）并存储
	 */
	public function createAccessToken($second = 7200)
	{
	    $str = str_shuffle(self::STR);
	    $str = substr($str, 0, 32);
	    $str .= time();
	    $str = md5($str);
	    $key = $this->redis_oauth_access_token_key . $str;
		$this->setCache($key, $this->appid, $second);		//存取2个小时
		return $str;
	}
	
	/**
	 * 验证access_token
	 */
	public function checkAccessToken($access_token)
	{
		$key = $this->redis_oauth_access_token_key . $access_token;
	    $res = $this->getCache($key);
		if($res)
		{
		    return $res;
		}	
		return false;
	}
	
	
	/**
	 * 获取缓存数据
	 */
	public function getCache($key)
	{
	    return ;
	}
	
	/**
	 * 存储缓存数据
	 */
	public function setCache($key, $value, $second)
	{
	    return ;
	}
	
	
	/**
	 * 加密函数
	 */
	public function o_encrypt($str)
	{
		$crypt = base64_encode(mcrypt_encrypt(MCRYPT_RIJNDAEL_256, md5(self::ENCRYPT_KEY), $str, MCRYPT_MODE_CBC, md5(md5(self::ENCRYPT_KEY))));
		$crypt = base64_encode($crypt);
		$crypt = str_replace(array('+', '/', '='), array('-', '_', ''), $crypt);
		return trim($crypt);
	}
	
	/**
	 * 解密函数
	 */
	public function o_decrypt($str)
	{
		$data = str_replace(array('-', '_'), array('+', '/'), $str);
		$mod4 = strlen($data) % 4;
		if ($mod4)
		{
			$data .= substr('====', $mod4);
		}
		$data = base64_decode($data);
		return rtrim(mcrypt_decrypt(MCRYPT_RIJNDAEL_256, md5(self::ENCRYPT_KEY), base64_decode($data), MCRYPT_MODE_CBC, md5(md5(self::ENCRYPT_KEY))));
	}
}