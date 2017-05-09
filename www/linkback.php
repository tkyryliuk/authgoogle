<?php


/**
 * Handle linkback() response from Google API .
 *
 * @author Sylvain MEDARD
 * 07/2014
 * @package simpleSAMLphp
 * @version $Id$
 */

$stateId = $_REQUEST['state'];
$state = SimpleSAML_Auth_State::loadState($stateId, sspmod_authgoogle_Auth_Source_Google::STAGE_INIT);

// https://developers.google.com/accounts/docs/OAuth2Login
if (array_key_exists('code', $_REQUEST)) {

	SimpleSAML_Logger::debug('Google authorization code => ' . $_REQUEST['code']);

	// Good
	$state['authgoogle:code'] = $_REQUEST['code'];

	if (array_key_exists('exp', $_REQUEST))
		$state['authgoogle:exp'] = $_REQUEST['exp'];

} else {
	// error = 'access_denied' means user chose not to login with GoogleOIDC
	// redirect them to their original page so they can choose another auth mechanism
	if ($_REQUEST['error'] === 'access_denied') {
		$e = new SimpleSAML_Error_UserAborted();
		SimpleSAML_Auth_State::throwException($state, $e);
	}

	// Error
	throw new Exception('Authentication failed: [' . $_REQUEST['error_code'] . '] ' . $_REQUEST['error']);
}


if (isset($state))
{
/* Find authentication source. */
assert('array_key_exists(sspmod_authgoogle_Auth_Source_Google::AUTHID, $state)');
$sourceId = $state[sspmod_authgoogle_Auth_Source_Google::AUTHID];

$source = SimpleSAML_Auth_Source::getById($sourceId);
if ($source === NULL) {
	throw new Exception('Could not find authentication source with id ' . $sourceId);
}


$source->finalStep($state);			
SimpleSAML_Auth_Source::completeAuth($state);

}

