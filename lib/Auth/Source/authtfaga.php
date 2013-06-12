<?php

/**
 * @author Tamas Frank, NIIFI
 *
 * GoogleAuthenticator 2 factor authentication module.
 * 
 * Configure it by adding an entry to config/authsources.php such as this:
 *
 *      'authtfaga' => array(
 *       	'authtfaga:authtfaga',
 *
 *        	'db.dsn' => 'mysql:host=db.example.com;port=3306;dbname=idpauthtfaga',
 *       	'db.username' => 'simplesaml',
 *       	'db.password' => 'bigsecret',
 *			'mainAuthSource' => 'ldap',
 *			'uidField' => 'uid'
 *        ),
 *
 * @package simpleSAMLphp
 * @version $Id$
 */

class sspmod_authtfaga_Auth_Source_authtfaga extends SimpleSAML_Auth_Source {

	/**
	 * The string used to identify our states.
	 */
	const STAGEID = 'authtfaga.stage';

	/**
	 * The number of characters of the OTP that is the secure token.
	 * The rest is the user id.
	 */
	const TOKENSIZE = 32;

	/**
	 * The key of the AuthId field in the state.
	 */
	const AUTHID = 'sspmod_authtfaga_Auth_Source_authtfaga.AuthId';

    /**
     *   sstc-saml-loa-authncontext-profile-draft.odt
    */

    const TFAAUTHNCONTEXTCLASSREF = 'urn:oasis:names:tc:SAML:2.0:post:ac:classes:nist-800-63:3';

    private $db_dsn;
    private $db_username;
    private $db_password;
    private $dbh;


    public $tfa_authencontextclassref;

	//Google Authenticator code length
	protected $_codeLength = 6;

	/**
	 * Constructor for this authentication source.
	 *
	 * @param array $info  Information about this authentication source.
	 * @param array $config  Configuration.
	 */
	public function __construct($info, $config) {
		assert('is_array($info)');
		assert('is_array($config)');

		/* Call the parent constructor first, as required by the interface. */
		parent::__construct($info, $config);

		if (array_key_exists('db.dsn', $config)) {
			$this->db_dsn = $config['db.dsn'];
		}
		if (array_key_exists('db.username', $config)) {
			$this->db_username = $config['db.username'];
		}
		if (array_key_exists('db.password', $config)) {
			$this->db_password = $config['db.password'];
		}

        $this->tfa_authencontextclassref = self::TFAAUTHNCONTEXTCLASSREF;
        try {
          $this->dbh = new PDO($this->db_dsn, $this->db_username, $this->db_password);
        } catch (PDOException $e) {
          	var_dump($this->db_dsn, $this->db_username, $this->db_password);
            echo 'Connection failed: ' . $e->getMessage();
        }
        $this->createTables();
               
	}
	
	public function authenticate(&$state) {
		assert('is_array($state)');

		/* We are going to need the authId in order to retrieve this authentication source later. */
		$state[self::AUTHID] = $this->authId;

		$id = SimpleSAML_Auth_State::saveState($state, self::STAGEID);

		$url = SimpleSAML_Module::getModuleURL('authtfaga/login.php');
		SimpleSAML_Utilities::redirect($url, array('AuthState' => $id));
	}

	private function createTables()
	{
		$q = "CREATE TABLE IF NOT EXISTS sspga_gakeys (
		          gakey VARCHAR (20),
		          PRIMARY KEY(gakey),
		          uid VARCHAR(60)
		         );";
		$result = $this->dbh->query($q);
		$q = "CREATE TABLE IF NOT EXISTS sspga_status (
		          uid VARCHAR(60),
		          PRIMARY KEY(uid),
		          enable BOOL
		         );";
		$result = $this->dbh->query($q);
	   
	}

	public function enable2fa($uid)
	{
	  $q = "REPLACE INTO sspga_status SET enable=1, uid='$uid'";
	  $result = $this->dbh->query($q);
	  SimpleSAML_Logger::info('authtfaga: ' . $uid . ' turns ON the two-factor authentication.');
	  return TRUE;
	}
	
	public function disable2fa($uid)
	{
	  $q = "REPLACE INTO sspga_status SET enable=0,uid='$uid'";
	  $result = $this->dbh->query($q);
	  SimpleSAML_Logger::info('authtfaga: ' . $uid . ' turns OFF the two-factor authentication.');
	  return TRUE;
	}
	
	public function isEnabled2fa($uid)
	{
	  $q = "SELECT * FROM sspga_status WHERE uid='$uid'";
	  $result = $this->dbh->query($q);
	  $row = $result->fetch();
	  $enabled =  $row["enable"];
	
	  return $enabled;
	}


    public function registerGAkey($uid,$ga_id)
    {
      if (!$ga_id)
         return FALSE;

      $q = "REPLACE INTO sspga_gakeys (uid,gakey) VALUES (\"".$uid."\",\"".$ga_id."\");";
      $result = $this->dbh->query($q);
      SimpleSAML_Logger::info('authtfaga: ' . $uid . ' register his gakey: '. $ga_id);
      return true;
    }

    public function deletegakey($uid,$ga_id)
    {
      $q = "DELETE FROM sspga_gakeys WHERE uid=\"".$uid."\" AND gakey=\"".$ga_id."\";";
      $result = $this->dbh->query($q);
      SimpleSAML_Logger::info('authtfaga: ' . $uid . ' delete his gakey: '. $ga_id);
      return TRUE;
    }

    public function getGAkeyFromUID($uid)
    {
      $q = "SELECT gakey FROM sspga_gakeys WHERE uid='$uid'";
      $result = $this->dbh->query($q);
      $row = $result->fetch();
      return $row['gakey'];
    }


	/**
	 * Below this line there is PHP Class for handling Google Authenticator 2-factor authentication
	 *
	 * @author Michael Kliewe
	 * @copyright 2012 Michael Kliewe
	 * @license http://www.opensource.org/licenses/bsd-license.php BSD License
	 * @link http://www.phpgangsta.de/
	 */

	/**
     * Create new secret.
     * 16 characters, randomly chosen from the allowed base32 characters.
     *
     * @param int $secretLength
     * @return string
     */
    public function createSecret($secretLength = 16)
    {
        $validChars = $this->_getBase32LookupTable();
        unset($validChars[32]);

        $secret = '';
        for ($i = 0; $i < $secretLength; $i++) {
            $secret .= $validChars[array_rand($validChars)];
        }
        return $secret;
    }

    /**
     * Calculate the code, with given secret and point in time
     *
     * @param string $secret
     * @param int|null $timeSlice
     * @return string
     */
    public function getCode($secret, $timeSlice = null)
    {
        if ($timeSlice === null) {
            $timeSlice = floor(time() / 30);
        }

        $secretkey = $this->_base32Decode($secret);

        // Pack time into binary string
        $time = chr(0).chr(0).chr(0).chr(0).pack('N*', $timeSlice);
        // Hash it with users secret key
        $hm = hash_hmac('SHA1', $time, $secretkey, true);
        // Use last nipple of result as index/offset
        $offset = ord(substr($hm, -1)) & 0x0F;
        // grab 4 bytes of the result
        $hashpart = substr($hm, $offset, 4);

        // Unpak binary value
        $value = unpack('N', $hashpart);
        $value = $value[1];
        // Only 32 bits
        $value = $value & 0x7FFFFFFF;

        $modulo = pow(10, $this->_codeLength);
        return str_pad($value % $modulo, $this->_codeLength, '0', STR_PAD_LEFT);
    }

    /**
     * Get QR-Code URL for image, from google charts
     *
     * @param string $name
     * @param string $secret
     * @return string
     */
    public function getQRCodeGoogleUrl($name, $secret) {
        $urlencoded = urlencode('otpauth://totp/'.$name.'?secret='.$secret.'');
        return 'https://chart.googleapis.com/chart?chs=200x200&chld=M|0&cht=qr&chl='.$urlencoded.'';
    }

    /**
     * Check if the code is correct. This will accept codes starting from $discrepancy*30sec ago to $discrepancy*30sec from now
     *
     * @param string $secret
     * @param string $code
     * @param int $discrepancy This is the allowed time drift in 30 second units (8 means 4 minutes before or after)
     * @return bool
     */
    public function verifyCode($secret, $code, $discrepancy = 1)
    {
        $currentTimeSlice = floor(time() / 30);

        for ($i = -$discrepancy; $i <= $discrepancy; $i++) {
            $calculatedCode = $this->getCode($secret, $currentTimeSlice + $i);
            if ($calculatedCode == $code ) {
                return true;
            }
        }

        return false;
    }

    /**
     * Set the code length, should be >=6
     *
     * @param int $length
     * @return PHPGangsta_GoogleAuthenticator
     */
    public function setCodeLength($length)
    {
        $this->_codeLength = $length;
        return $this;
    }

    /**
     * Helper class to decode base32
     *
     * @param $secret
     * @return bool|string
     */
    protected function _base32Decode($secret)
    {
        if (empty($secret)) return '';

        $base32chars = $this->_getBase32LookupTable();
        $base32charsFlipped = array_flip($base32chars);

        $paddingCharCount = substr_count($secret, $base32chars[32]);
        $allowedValues = array(6, 4, 3, 1, 0);
        if (!in_array($paddingCharCount, $allowedValues)) return false;
        for ($i = 0; $i < 4; $i++){
            if ($paddingCharCount == $allowedValues[$i] &&
                substr($secret, -($allowedValues[$i])) != str_repeat($base32chars[32], $allowedValues[$i])) return false;
        }
        $secret = str_replace('=','', $secret);
        $secret = str_split($secret);
        $binaryString = "";
        for ($i = 0; $i < count($secret); $i = $i+8) {
            $x = "";
            if (!in_array($secret[$i], $base32chars)) return false;
            for ($j = 0; $j < 8; $j++) {
                $x .= str_pad(base_convert(@$base32charsFlipped[@$secret[$i + $j]], 10, 2), 5, '0', STR_PAD_LEFT);
            }
            $eightBits = str_split($x, 8);
            for ($z = 0; $z < count($eightBits); $z++) {
                $binaryString .= ( ($y = chr(base_convert($eightBits[$z], 2, 10))) || ord($y) == 48 ) ? $y:"";
            }
        }
        return $binaryString;
    }

    /**
     * Helper class to encode base32
     *
     * @param string $secret
     * @param bool $padding
     * @return string
     */
    protected function _base32Encode($secret, $padding = true)
    {
        if (empty($secret)) return '';

        $base32chars = $this->_getBase32LookupTable();

        $secret = str_split($secret);
        $binaryString = "";
        for ($i = 0; $i < count($secret); $i++) {
            $binaryString .= str_pad(base_convert(ord($secret[$i]), 10, 2), 8, '0', STR_PAD_LEFT);
        }
        $fiveBitBinaryArray = str_split($binaryString, 5);
        $base32 = "";
        $i = 0;
        while ($i < count($fiveBitBinaryArray)) {
            $base32 .= $base32chars[base_convert(str_pad($fiveBitBinaryArray[$i], 5, '0'), 2, 10)];
            $i++;
        }
        if ($padding && ($x = strlen($binaryString) % 40) != 0) {
            if ($x == 8) $base32 .= str_repeat($base32chars[32], 6);
            elseif ($x == 16) $base32 .= str_repeat($base32chars[32], 4);
            elseif ($x == 24) $base32 .= str_repeat($base32chars[32], 3);
            elseif ($x == 32) $base32 .= $base32chars[32];
        }
        return $base32;
    }

    /**
     * Get array with all 32 characters for decoding from/encoding to base32
     *
     * @return array
     */
    protected function _getBase32LookupTable()
    {
        return array(
            'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', //  7
            'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', // 15
            'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', // 23
            'Y', 'Z', '2', '3', '4', '5', '6', '7', // 31
            '='  // padding char
        );
    }    
    

}

?>
