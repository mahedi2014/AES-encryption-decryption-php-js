<?php error_reporting(E_ALL); ?>
<!DOCTYPE html>
<html>
<head>
    <meta http-equiv="Content-Type" content="text/html; charset=utf-8">
    <title>CryptoJS AES and PHP</title>
    <script type="text/javascript" src="aes.js"></script>
    <script type="text/javascript">
        var CryptoJSAesJson = {
            stringify: function (cipherParams) {
                var j = {ct: cipherParams.ciphertext.toString(CryptoJS.enc.Base64)};
                if (cipherParams.iv) j.iv = cipherParams.iv.toString();
                if (cipherParams.salt) j.s = cipherParams.salt.toString();
                return JSON.stringify(j).replace(/\s/g, '');
            },
            parse: function (jsonStr) {
                var j = JSON.parse(jsonStr);
                var cipherParams = CryptoJS.lib.CipherParams.create({ciphertext: CryptoJS.enc.Base64.parse(j.ct)});
                if (j.iv) cipherParams.iv = CryptoJS.enc.Hex.parse(j.iv);
                if (j.s) cipherParams.salt = CryptoJS.enc.Hex.parse(j.s);
                return cipherParams;
            }
        };

        var passphrase = "your password same in php-js";
        var plaintext = "{'name':'mahedi azad'}";

        var encdata = CryptoJS.AES.encrypt(JSON.stringify(plaintext), passphrase, {format: CryptoJSAesJson}).toString();
        console.log('encdata', encdata);

        var decdata = JSON.parse(CryptoJS.AES.decrypt(encdata, passphrase, {format: CryptoJSAesJson}).toString(CryptoJS.enc.Utf8));
        console.log('decdata', decdata);
    </script>
</head>
<body>
<h1>CryptoJS AES and PHP</h1>
<?php
/**
 * Helper library for CryptoJS AES encryption/decryption
 * Allow you to use AES encryption on client side and server side vice versa
 *
 * @author BrainFooLong (bfldev.com)
 * @link https://github.com/brainfoolong/cryptojs-aes-php
 */

/**
 * Decrypt data from a CryptoJS json encoding string
 *
 * @param mixed $passphrase
 * @param mixed $jsonString
 * @return mixed
 */
function cryptoJsAesDecrypt($passphrase, $jsonString)
{
    $jsondata = json_decode($jsonString, true);
    try {
        $salt = hex2bin($jsondata["s"]);
        $iv = hex2bin($jsondata["iv"]);
    } catch (Exception $e) {
        return null;
    }
    $ct = base64_decode($jsondata["ct"]);
    $concatedPassphrase = $passphrase . $salt;
    $md5 = array();
    $md5[0] = md5($concatedPassphrase, true);
    $result = $md5[0];
    for ($i = 1; $i < 3; $i++) {
        $md5[$i] = md5($md5[$i - 1] . $concatedPassphrase, true);
        $result .= $md5[$i];
    }
    $key = substr($result, 0, 32);
    $data = openssl_decrypt($ct, 'aes-256-cbc', $key, true, $iv);
    return json_decode($data, true);
}

/**
 * Encrypt value to a cryptojs compatiable json encoding string
 *
 * @param mixed $passphrase
 * @param mixed $value
 * @return string
 */
function cryptoJsAesEncrypt($passphrase, $value)
{
    $salt = openssl_random_pseudo_bytes(8);
    $salted = '';
    $dx = '';
    while (strlen($salted) < 48) {
        $dx = md5($dx . $passphrase . $salt, true);
        $salted .= $dx;
    }
    $key = substr($salted, 0, 32);
    $iv = substr($salted, 32, 16);
    $encrypted_data = openssl_encrypt(json_encode($value), 'aes-256-cbc', $key, true, $iv);
    $data = array("ct" => base64_encode($encrypted_data), "iv" => bin2hex($iv), "s" => bin2hex($salt));
    return json_encode($data);
}

echo '<h1>JS encryption and decryption (see console)</h1>';
$passphrase = 'your password same in php-js';
$plaintext = "{'name':'mahedi azad'}";

$encrypted_json = '{"ct":"9Dx1ikbKNvMhk34tmFXD8/2D0o+VWQyPAq+4Hw9R9Pc=","iv":"ca828a98c0670630df7b70f49fcd0615","s":"b22dc67509a307ee"}';
$decdata = cryptoJsAesDecrypt('your password same in php-js', $encrypted_json);
echo '<pre>';
echo 'Path: ' . __FILE__ . " at line " . __LINE__ . "\n";
print_r($decdata);
echo '</pre>';


echo '<h1>PHP encryption and decryption</h1>';
$passphrase = 'your password same in php-js';
$plaintext = "{'name':'mahedi azad'}";

$encdataphp_json = cryptoJsAesEncrypt($passphrase, $plaintext);
echo '<pre>';
echo 'Path: ' . __FILE__ . " at line " . __LINE__ . "\n";
print_r($encdataphp_json);
echo '</pre>';

$decdata = cryptoJsAesDecrypt($passphrase, $encdataphp_json);
echo '<pre>';
echo 'Path: ' . __FILE__ . " at line " . __LINE__ . "\n";
print_r($decdata);
echo '</pre>';


?>


</body>
</html>
