<?php

/**
 * @author Tamas Frank, NIIFI
 *
 */

// Get session object
$session = SimpleSAML_Session::getSession();

// Get the authetication state
$authStateId = $_REQUEST['AuthState'];
$state = SimpleSAML_Auth_State::loadState($authStateId, 'authtfaga.stage');
assert('array_key_exists("SimpleSAML_Auth_Source.id", $state)');

$authId = $state['SimpleSAML_Auth_Source.id'];
$as = SimpleSAML_Configuration::getConfig('authsources.php')->getValue($authId);

// Use 2 factor authentication class
$gaLogin = SimpleSAML_Auth_Source::getById($authId, 'sspmod_authtfaga_Auth_Source_authtfaga');
if ($gaLogin === null) {
    throw new Exception('Invalid authentication source: ' . $authId);
}

// Init template
$template = 'authtfaga:login.php';
$globalConfig = SimpleSAML_Configuration::getInstance();
$t = new SimpleSAML_XHTML_Template($globalConfig, $template);

$errorCode = null;

//If user doesn't have session, force to use the main authentication method
if (!$session->isValid($as['mainAuthSource'])) {
    SimpleSAML_Auth_Default::initLogin($as['mainAuthSource'], SimpleSAML_Utilities::selfURL());
}

$attributes = $session->getAuthData($as['mainAuthSource'], 'Attributes');
$state['Attributes'] = $attributes;

$uid = $attributes[ $as['uidField'] ][0];
$state['UserID'] = $uid;
$isEnabled = $gaLogin->isEnabled2fa($uid);

if (is_null($isEnabled) || isset($_GET['postSetEnable2fa'])) {
    //If the user has not set his preference of 2 factor authentication, redirect to settings page
    if (isset($_POST['setEnable2f'])) {
        if ($_POST['setEnable2f'] == 1) {
            $gaKey = $gaLogin->createSecret();
            $gaLogin->registerGAkey($uid, $gaKey);

            $gaLogin->enable2fa($uid);
            $t->data['todo'] = 'generateGA';
            $t->data['autofocus'] = 'otp';
            $totpIssuer = empty($as['totpIssuer']) ? 'dev_aai_teszt_IdP' : $as['totpIssuer'];
            $t->data['qrcode'] = $gaLogin->getQRCodeGoogleUrl($totpIssuer.':'.$uid, $totpIssuer, $gaKey);
        } elseif ($_POST['setEnable2f'] == 0) {
            $gaLogin->disable2fa($uid);
            SimpleSAML_Auth_Source::completeAuth($state);
        }
    } else {
        $t->data['todo'] = 'choose2enable';
    }
} elseif ($isEnabled == 1) {
    //Show the second factor form
    if (isset($_POST['otp'])) {
        $secret = $gaLogin->getGAkeyFromUID($uid);
        $loggedIn = $gaLogin->verifyCode($secret, $_POST['otp']);

        if ($loggedIn) {
            $state['saml:AuthnContextClassRef'] = $gaLogin->tfa_authencontextclassref;
            SimpleSAML_Auth_Source::completeAuth($state);
        } else {
            $errorCode = 'WRONGOTP';
            $t->data['todo'] = 'loginOTP';
        }
    } else {
        $t->data['autofocus'] = 'otp';
        $t->data['todo'] = 'loginOTP';
    }
} else {
    // User has set up not to use 2 factor, so he is logged in
    SimpleSAML_Auth_Source::completeAuth($state);
}

$t->data['stateparams'] = array('AuthState' => $authStateId);
$t->data['errorcode'] = $errorCode;
$t->show();
exit();
